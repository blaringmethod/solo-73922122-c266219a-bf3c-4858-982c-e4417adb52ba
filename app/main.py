"""FastAPI web entry point for the offline mTLS chain doctor.

Upload routes (/diagnose and /api/diagnose) never rely on framework form
parsing: they stream the multipart body through :mod:`app.ingest`, charging
each chunk against a per-request 2 MiB cap and a cross-process 4 MiB shared
in-flight budget coordinated in SQLite (see :mod:`app.budget`).
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .budget import DEFAULT_TOTAL_BUDGET, BudgetStore, SharedBudgetExhausted
from .diagnostics import (
    ALLOWED_SIGNATURE_LABEL,
    DiagnosticInputError,
    diagnose,
    parse_pem_bundle,
)
from .ingest import (
    DEFAULT_PER_REQUEST_LIMIT,
    MultipartMalformed,
    RequestTooLarge,
    read_multipart,
)

BASE_DIR = Path(__file__).resolve().parent
EXAMPLES_DIR = BASE_DIR / "examples"

DATA_DIR = Path(os.environ.get("APP_DATA_DIR", "/data"))
BUDGET_DB = Path(os.environ.get("BUDGET_DB", str(DATA_DIR / "budget" / "budget.db")))
STAGING_DIR = Path(os.environ.get("STAGING_DIR", str(DATA_DIR / "staging")))
WORKER_NAME = os.environ.get("WORKER_NAME")
TOTAL_BUDGET = int(os.environ.get("TOTAL_BUDGET", DEFAULT_TOTAL_BUDGET))
PER_REQUEST_LIMIT = int(
    os.environ.get("PER_REQUEST_LIMIT", DEFAULT_PER_REQUEST_LIMIT)
)
STALE_AFTER = float(os.environ.get("STALE_AFTER_SECONDS", 30.0))

_store: BudgetStore | None = None


def get_store() -> BudgetStore:
    """Lazily build the shared store so local tests run without /data."""
    global _store
    if _store is None:
        _store = BudgetStore(
            db_path=BUDGET_DB,
            staging_root=STAGING_DIR,
            worker_name=WORKER_NAME,
            total_budget=TOTAL_BUDGET,
            stale_after=STALE_AFTER,
        )
        _store.start()
    return _store


@asynccontextmanager
async def lifespan(_app: FastAPI):
    store = get_store()
    task = asyncio.create_task(store.run_background())
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(Exception):
            await task
        store.stop()


app = FastAPI(
    title="mTLS 证书链离线诊断",
    description="内网 mTLS 客户端证书链排障：区分中间证书缺失与交叉签发选链错误",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


def _example_names() -> list[str]:
    return sorted(
        p.name
        for p in EXAMPLES_DIR.iterdir()
        if p.is_dir() and (p / "manifest.json").exists()
    )


def _index_context(**extra) -> dict:
    context = {
        "examples": _example_names(),
        "default_time": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "sig_policy": ALLOWED_SIGNATURE_LABEL,
        "per_request_limit": PER_REQUEST_LIMIT,
        "total_budget": TOTAL_BUDGET,
    }
    context.update(extra)
    return context


def _parse_when(raw: str) -> dt.datetime:
    text = raw.strip()
    if not text:
        return dt.datetime.now(dt.timezone.utc)
    when = dt.datetime.fromisoformat(text)
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.timezone.utc)
    return when.astimezone(dt.timezone.utc)


def _run_diagnosis(
    leaf_bytes: bytes,
    intermediates_bytes: bytes,
    root_bytes: bytes,
    when: dt.datetime,
):
    leaf_certs = parse_pem_bundle(leaf_bytes)
    root_certs = parse_pem_bundle(root_bytes)
    intermediates = (
        parse_pem_bundle(intermediates_bytes)
        if intermediates_bytes.strip()
        else []
    )
    return diagnose(leaf_certs, intermediates, root_certs, when)


_NO_STORE = {"Cache-Control": "no-store"}


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    response = templates.TemplateResponse(
        request, "index.html", _index_context()
    )
    response.headers["Cache-Control"] = "no-store"
    return response


async def _handle_upload(request: Request, want_json: bool):
    """Shared streaming pipeline for the HTML and JSON upload routes."""
    store = get_store()
    try:
        payload = await read_multipart(request, store, PER_REQUEST_LIMIT)
    except RequestTooLarge as exc:
        if want_json:
            return JSONResponse(
                {"error": str(exc), "code": "payload_too_large"},
                status_code=413,
                headers=_NO_STORE,
            )
        response = templates.TemplateResponse(
            request,
            "index.html",
            _index_context(error=str(exc), error_code="413"),
            status_code=413,
        )
        response.headers["Cache-Control"] = "no-store"
        return response
    except SharedBudgetExhausted as exc:
        if want_json:
            return JSONResponse(
                {"error": str(exc), "code": "budget_exhausted"},
                status_code=503,
                headers={**_NO_STORE, "Retry-After": "5"},
            )
        response = templates.TemplateResponse(
            request,
            "index.html",
            _index_context(error=str(exc), error_code="503"),
            status_code=503,
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Retry-After"] = "5"
        return response
    except MultipartMalformed as exc:
        if want_json:
            return JSONResponse(
                {"error": str(exc), "code": "malformed_multipart"},
                status_code=400,
                headers=_NO_STORE,
            )
        response = templates.TemplateResponse(
            request,
            "index.html",
            _index_context(error=str(exc), error_code="400"),
            status_code=400,
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    # Budget is held from here until diagnosis finishes and every upload temp
    # file has been closed/removed -- success, bad PEM or parse failure alike.
    try:
        try:
            leaf_part = payload.files.get("leaf")
            root_part = payload.files.get("root")
            inter_part = payload.files.get("intermediates")
            leaf_bytes = leaf_part.read_bytes() if leaf_part else b""
            root_bytes = root_part.read_bytes() if root_part else b""
            inter_bytes = inter_part.read_bytes() if inter_part else b""
            when = _parse_when(payload.form.get("validation_time", ""))
            result = _run_diagnosis(
                leaf_bytes, inter_bytes, root_bytes, when
            )
        except (DiagnosticInputError, ValueError) as exc:
            if want_json:
                return JSONResponse(
                    {"error": str(exc)}, status_code=400, headers=_NO_STORE
                )
            response = templates.TemplateResponse(
                request,
                "index.html",
                _index_context(
                    error=str(exc),
                    error_code="400",
                    default_time=payload.form.get("validation_time", ""),
                ),
                status_code=400,
            )
            response.headers["Cache-Control"] = "no-store"
            return response

        if want_json:
            return JSONResponse(result.to_dict(), headers=_NO_STORE)
        response = templates.TemplateResponse(
            request,
            "result.html",
            {"r": result, "r_dict": result.to_dict()},
        )
        response.headers["Cache-Control"] = "no-store"
        return response
    finally:
        # All read handles were opened per read_bytes() and closed on exit of
        # the with-block; now remove the temp files, then return the bytes.
        payload.close_all()


@app.post("/diagnose", response_class=HTMLResponse)
async def diagnose_html(request: Request):
    return await _handle_upload(request, want_json=False)


@app.post("/api/diagnose")
async def diagnose_api(request: Request):
    return await _handle_upload(request, want_json=True)


@app.get("/examples/{name}")
def load_example(name: str):
    """Redirect the browser to a prefilled upload form for a built-in demo."""
    safe = Path(name).name  # strip any path components
    manifest = EXAMPLES_DIR / safe / "manifest.json"
    if not manifest.exists():
        return JSONResponse({"error": f"示例 {name} 不存在"}, status_code=404)
    return RedirectResponse(url=f"/?example={safe}", status_code=303)


@app.get("/api/examples/{name}")
def example_payload(name: str):
    safe = Path(name).name
    directory = EXAMPLES_DIR / safe
    manifest = directory / "manifest.json"
    if not manifest.exists():
        return JSONResponse({"error": f"示例 {name} 不存在"}, status_code=404)
    payload = {"manifest": manifest.read_text(encoding="utf-8"), "files": {}}
    for pem in sorted(directory.glob("*.pem")):
        payload["files"][pem.name] = pem.read_text(encoding="utf-8")
    return payload
