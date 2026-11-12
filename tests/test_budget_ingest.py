"""Tests for streaming ingestion, byte budgets and crash recovery.

Covers:
  * per-request 2 MiB cap counting multipart overhead and unknown fields (413)
  * shared cross-process 4 MiB budget exhaustion (503, no queueing)
  * Content-Length cannot be trusted (enforced on actual streamed bytes)
  * whole-body buffering is avoided (staging grows chunk-by-chunk)
  * reservations/temp files released on success, bad PEM, parse failure,
    over-limit and client disconnect
  * a dead worker's staging is reaped and its bytes returned, while another
    live worker's request is never touched
  * HTML rejection pages show the reason and never an old conclusion
"""

from __future__ import annotations

import asyncio
import json
import shutil
import sqlite3
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.budget import BudgetStore
from app.ingest import DEFAULT_PER_REQUEST_LIMIT

EXAMPLES = Path(__file__).resolve().parent.parent / "app" / "examples"


def _example_payload(name: str):
    directory = EXAMPLES / name
    manifest = json.loads((directory / "manifest.json").read_text())
    files = {p.name: p.read_text() for p in directory.glob("*.pem")}
    return manifest, files


def _multipart_body(fields: list[tuple[str, str, bytes | str]]) -> tuple[bytes, str]:
    boundary = "----budgettestboundary42"
    chunks: list[bytes] = []
    for field_name, filename, content in fields:
        if isinstance(content, str):
            content = content.encode()
        chunks.append(f"--{boundary}\r\n".encode())
        if filename:
            chunks.append(
                f'Content-Disposition: form-data; name="{field_name}"; '
                f'filename="{filename}"\r\n'.encode()
            )
            chunks.append(b"Content-Type: application/x-pem\r\n\r\n")
        else:
            chunks.append(
                f'Content-Disposition: form-data; name="{field_name}"\r\n\r\n'.encode()
            )
        chunks.append(content)
        chunks.append(b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), boundary


@pytest.fixture()
def isolated_app(tmp_path, monkeypatch):
    """Fresh app + budget store on an isolated directory for each test."""
    data_dir = tmp_path / "data"
    db_path = data_dir / "budget" / "budget.db"
    staging = data_dir / "staging"
    monkeypatch.setattr(main, "BUDGET_DB", db_path)
    monkeypatch.setattr(main, "STAGING_DIR", staging)
    monkeypatch.setattr(main, "WORKER_NAME", "test-worker-a")
    monkeypatch.setattr(main, "TOTAL_BUDGET", 4 * 1024 * 1024)
    monkeypatch.setattr(main, "PER_REQUEST_LIMIT", DEFAULT_PER_REQUEST_LIMIT)
    main._store = None
    with TestClient(main.app) as client:
        yield client, main.get_store(), db_path, staging
    main._store = None


def _good_fields(manifest, files) -> list[tuple[str, str, bytes]]:
    return [
        ("leaf", manifest["leaf"], files[manifest["leaf"]]),
        ("root", manifest["root"], files[manifest["root"]]),
        ("intermediates", manifest["intermediates"], files[manifest["intermediates"]]),
        ("validation_time", "", manifest["validation_time"]),
    ]


# --------------------------------------------------------------------- happy
def test_happy_path_releases_everything(isolated_app):
    client, store, db_path, staging = isolated_app
    manifest, files = _example_payload("cross-sign")
    body, boundary = _multipart_body(_good_fields(manifest, files))
    resp = client.post(
        "/api/diagnose",
        content=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    assert resp.status_code == 200
    assert resp.json()["passing_chain"] is not None
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM allocations").fetchone()[0] == 0
    # Only the empty worker namespace remains; no .part temp files anywhere.
    assert list(staging.rglob("*.part")) == []


# ------------------------------------------------------------- per-request
def test_request_over_2mib_returns_413_and_cleans_up(isolated_app):
    client, store, db_path, staging = isolated_app
    manifest, files = _example_payload("cross-sign")
    big_leaf = b"-----BEGIN CERTIFICATE-----\n" + b"A" * (
        DEFAULT_PER_REQUEST_LIMIT
    ) + b"\n-----END CERTIFICATE-----\n"
    fields = [
        ("leaf", "big.pem", big_leaf),
        ("root", manifest["root"], files[manifest["root"]]),
        ("intermediates", manifest["intermediates"], files[manifest["intermediates"]]),
        ("validation_time", "", manifest["validation_time"]),
    ]
    body, boundary = _multipart_body(fields)
    assert len(body) > DEFAULT_PER_REQUEST_LIMIT
    resp = client.post(
        "/api/diagnose",
        content=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    assert resp.status_code == 413
    assert resp.json()["code"] == "payload_too_large"
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM allocations").fetchone()[0] == 0
    assert list(staging.rglob("*.part")) == []


def test_unknown_fields_and_overhead_count_toward_limit(isolated_app, monkeypatch):
    client, store, _db, _staging = isolated_app
    # Lower the per-request cap via the env-driven constant to prove overhead
    # is counted: payloads smaller than the cap in pure file bytes still fail.
    tiny_cap = 800
    monkeypatch.setattr(main, "PER_REQUEST_LIMIT", tiny_cap)
    manifest, files = _example_payload("cross-sign")
    junk = "x" * 600
    fields = _good_fields(manifest, files) + [("mystery_field", "", junk)]
    body, boundary = _multipart_body(fields)
    # The unknown field alone plus boundaries pushes us past 800 bytes.
    resp = client.post(
        "/api/diagnose",
        content=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    assert resp.status_code == 413


def test_content_length_cannot_be_trusted(isolated_app):
    """A lying, small Content-Length must not bypass the streamed 2 MiB cap."""
    client, _store, _db, _staging = isolated_app
    manifest, files = _example_payload("cross-sign")
    big_leaf = b"X" * (DEFAULT_PER_REQUEST_LIMIT + 1024)
    fields = [
        ("leaf", "big.pem", big_leaf),
        ("root", manifest["root"], files[manifest["root"]]),
        ("intermediates", manifest["intermediates"], files[manifest["intermediates"]]),
        ("validation_time", "", manifest["validation_time"]),
    ]
    body, boundary = _multipart_body(fields)

    async def post_lying_content_length() -> int:
        transport = httpx.ASGITransport(app=main.app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as http:
            req = http.build_request(
                "POST",
                "/api/diagnose",
                content=body,
                headers={
                    "Content-Type": (
                        f"multipart/form-data; boundary={boundary}"
                    ),
                    # Deliberately inconsistent with the real body.
                    "Content-Length": "10",
                },
            )
            resp = await http.send(req)
            return resp.status_code

    assert asyncio.run(post_lying_content_length()) == 413


# ------------------------------------------------------------- shared 503
def test_shared_budget_exhaustion_returns_503_no_queue(isolated_app, monkeypatch):
    client, store, db_path, _staging = isolated_app
    # Simulate another in-flight request holding most of the shared 4 MiB.
    store.charge("foreign-req", 4 * 1024 * 1024 - 512)
    try:
        manifest, files = _example_payload("cross-sign")
        body, boundary = _multipart_body(_good_fields(manifest, files))
        assert len(body) > 512
        resp = client.post(
            "/api/diagnose",
            content=body,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
        )
        assert resp.status_code == 503
        payload = resp.json()
        assert payload["code"] == "budget_exhausted"
        assert resp.headers.get("retry-after")
        # The foreign reservation must be untouched; the rejected request
        # must not have left a partial reservation behind.
        with sqlite3.connect(db_path) as conn:
            rows = conn.execute(
                "SELECT req_id, bytes FROM allocations"
            ).fetchall()
        assert rows == [("foreign-req", 4 * 1024 * 1024 - 512)]
    finally:
        store.release("foreign-req")


def test_413_takes_precedence_over_503(isolated_app):
    client, store, _db, _staging = isolated_app
    store.charge("foreign-req", 4 * 1024 * 1024 - 1024)
    try:
        manifest, files = _example_payload("cross-sign")
        big_leaf = b"X" * (DEFAULT_PER_REQUEST_LIMIT + 1024)
        fields = [
            ("leaf", "big.pem", big_leaf),
            ("root", manifest["root"], files[manifest["root"]]),
            ("intermediates", manifest["intermediates"],
             files[manifest["intermediates"]]),
            ("validation_time", "", manifest["validation_time"]),
        ]
        body, boundary = _multipart_body(fields)
        resp = client.post(
            "/api/diagnose",
            content=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        assert resp.status_code == 413
    finally:
        store.release("foreign-req")


def test_budget_recovers_after_503_for_later_legit_upload(isolated_app):
    client, store, _db, _staging = isolated_app
    store.charge("foreign-req", 4 * 1024 * 1024 - 64)
    manifest, files = _example_payload("cross-sign")
    body, boundary = _multipart_body(_good_fields(manifest, files))
    blocked = client.post(
        "/api/diagnose",
        content=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    assert blocked.status_code == 503
    store.release("foreign-req")
    ok = client.post(
        "/api/diagnose",
        content=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    assert ok.status_code == 200


# ------------------------------------------------------------- malformed
def test_malformed_multipart_returns_400_and_cleans_up(isolated_app):
    client, _store, db_path, staging = isolated_app
    resp = client.post(
        "/api/diagnose",
        content=b"this is not multipart at all",
        headers={"Content-Type": "multipart/form-data; boundary=zzz"},
    )
    assert resp.status_code == 400
    assert resp.json()["code"] == "malformed_multipart"
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM allocations").fetchone()[0] == 0
    assert list(staging.rglob("*.part")) == []


def test_bad_pem_releases_budget_and_tempfiles(isolated_app):
    client, _store, db_path, staging = isolated_app
    manifest, files = _example_payload("cross-sign")
    fields = [
        ("leaf", "bad.pem", b"not a pem at all"),
        ("root", manifest["root"], files[manifest["root"]]),
        ("intermediates", "i.pem", b""),
        ("validation_time", "", manifest["validation_time"]),
    ]
    body, boundary = _multipart_body(fields)
    resp = client.post(
        "/api/diagnose",
        content=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    assert resp.status_code == 400
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM allocations").fetchone()[0] == 0
    assert list(staging.rglob("*.part")) == []


# ------------------------------------------------------------- disconnect
def test_client_disconnect_releases_budget(isolated_app):
    """An http.disconnect mid-body must still return the budget."""
    _client, store, db_path, _staging = isolated_app
    leaf_part = (
        b"-----BEGIN CERTIFICATE-----\n"
        + b"A" * 100_000
        + b"\n-----END CERTIFICATE-----\n"
    )
    boundary = "discboundary"
    first_chunk = (
        f"--{boundary}\r\n".encode()
        + b'Content-Disposition: form-data; name="leaf"; '
        b'filename="leaf.pem"\r\n\r\n'
        + leaf_part
    )
    queue: asyncio.Queue = asyncio.Queue()
    queue.put_nowait({"type": "http.request", "body": first_chunk,
                      "more_body": True})
    queue.put_nowait({"type": "http.disconnect"})

    async def receive():
        return await queue.get()

    sent: list[dict] = []

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/diagnose",
        "raw_path": b"/api/diagnose",
        "query_string": b"",
        "headers": [
            (b"content-type",
             f"multipart/form-data; boundary={boundary}".encode())
        ],
        "client": ("127.0.0.1", 1234),
        "server": ("testserver", 80),
        "root_path": "",
        "app": main.app,
    }

    # Starlette turns a disconnect into ClientDisconnect; either way the
    # finally-block in the ingestion layer must free the reservation.
    with pytest.raises(Exception):
        asyncio.run(main.app(scope, receive, send))

    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM allocations").fetchone()[0] == 0
    assert list(store.staging_root.rglob("*.part")) == []


# ------------------------------------------------------------- streaming
def test_body_is_not_buffered_whole(isolated_app, monkeypatch):
    """While chunks flow in, only chunk-sized temp files exist on disk."""
    client, store, _db, staging = isolated_app
    manifest, files = _example_payload("cross-sign")
    # A big *unknown file* field keeps the payload well over one chunk while
    # the real PEM inputs stay valid, so the request ends in a 200 diagnosis.
    big = b"P" * 500_000
    fields = _good_fields(manifest, files) + [("bulk_extra", "extra.bin", big)]
    body, boundary = _multipart_body(fields)

    observed_max = 0

    real_charge = store.charge

    def spy_charge(req_id, num_bytes):
        nonlocal observed_max
        result = real_charge(req_id, num_bytes)
        largest = 0
        for part in staging.rglob("*.part"):
            largest = max(largest, part.stat().st_size)
        observed_max = max(observed_max, largest)
        return result

    monkeypatch.setattr(store, "charge", spy_charge)
    resp = client.post(
        "/api/diagnose",
        content=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    assert resp.status_code == 200
    # The 500 KB field must never have been held whole in memory; disk writes
    # trailed the 64 KiB chunk size.
    assert observed_max <= 70_000


# ------------------------------------------------------------- crash reap
def test_dead_worker_is_reaped_live_worker_untouched(tmp_path):
    db_path = tmp_path / "budget.db"
    staging = tmp_path / "staging"
    liveness = tmp_path / "liveness"

    dead = BudgetStore(db_path, staging, worker_name="dead-worker",
                       stale_after=0.05)
    dead.start()
    live = BudgetStore(db_path, staging, worker_name="live-worker",
                       stale_after=0.05)
    live.start()

    dead.charge("dead-req-1", 3000)
    dead.charge("dead-req-2", 1000)
    live.charge("live-req", 2000)
    # Touch files so staging really exists.
    for w, req in (("dead-worker", "dead-req-1"), ("dead-worker", "dead-req-2"),
                   ("live-worker", "live-req")):
        d = staging / w / req
        d.mkdir(parents=True, exist_ok=True)
        (d / "upload.part").write_bytes(b"x" * 100)

    assert dead.current_usage() == 6000

    # Simulate a hard crash: no stop(), just remove the heartbeat file and
    # let it go stale.
    shutil.rmtree(liveness, ignore_errors=True)
    liveness.mkdir()
    live.heartbeat()  # live worker re-creates and refreshes its own file
    time.sleep(0.08)

    freed = live.reap_once()
    assert freed == 4000
    assert live.current_usage() == 2000
    # Dead worker's staging gone, live request intact.
    assert not (staging / "dead-worker").exists()
    assert (staging / "live-worker" / "live-req" / "upload.part").exists()
    with sqlite3.connect(db_path) as conn:
        workers = {r[0] for r in conn.execute("SELECT worker_id FROM workers")}
        assert workers == {"live-worker"}
        reqs = {r[0] for r in conn.execute("SELECT req_id FROM allocations")}
        assert reqs == {"live-req"}


def test_reap_restores_budget_for_followup_request(tmp_path, monkeypatch):
    db_path = tmp_path / "budget.db"
    staging = tmp_path / "staging"
    dead = BudgetStore(db_path, staging, worker_name="crashed", stale_after=0.05)
    dead.start()
    dead.charge("stuck", 4 * 1024 * 1024)  # whole budget held by crashed proc
    # Hard crash: the process vanishes without stop(); its heartbeat file is
    # left behind but goes stale, and the DB row's heartbeat stops updating.
    time.sleep(0.08)

    monkeypatch.setattr(main, "BUDGET_DB", db_path)
    monkeypatch.setattr(main, "STAGING_DIR", staging)
    monkeypatch.setattr(main, "WORKER_NAME", "survivor")
    monkeypatch.setattr(main, "TOTAL_BUDGET", 4 * 1024 * 1024)
    monkeypatch.setattr(main, "PER_REQUEST_LIMIT", DEFAULT_PER_REQUEST_LIMIT)
    monkeypatch.setattr(main, "STALE_AFTER", 0.05)
    main._store = None
    with TestClient(main.app) as client:
        # Startup reclaims the crashed worker's bytes.
        assert client.get("/").status_code == 200
        assert main.get_store().current_usage() == 0
        manifest, files = _example_payload("cross-sign")
        body, boundary = _multipart_body(_good_fields(manifest, files))
        resp = client.post(
            "/api/diagnose",
            content=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        assert resp.status_code == 200
    main._store = None


# ------------------------------------------------------------- HTML route
def test_html_rejection_shows_reason_without_old_result(isolated_app):
    client, _store, _db, _staging = isolated_app
    manifest, files = _example_payload("cross-sign")
    big_leaf = b"X" * (DEFAULT_PER_REQUEST_LIMIT + 1024)
    fields = [
        ("leaf", "big.pem", big_leaf),
        ("root", manifest["root"], files[manifest["root"]]),
        ("intermediates", manifest["intermediates"],
         files[manifest["intermediates"]]),
        ("validation_time", "", manifest["validation_time"]),
    ]
    body, boundary = _multipart_body(fields)
    resp = client.post(
        "/diagnose",
        content=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    assert resp.status_code == 413
    assert "413" in resp.text
    assert "字节上限" in resp.text
    # Result-page content must not leak into the rejection page.
    assert "通过的链" not in resp.text
    assert "候选链" not in resp.text
    assert resp.headers.get("cache-control") == "no-store"


def test_html_503_shows_reason(isolated_app):
    client, store, _db, _staging = isolated_app
    store.charge("foreign-req", 4 * 1024 * 1024 - 64)
    try:
        manifest, files = _example_payload("cross-sign")
        body, boundary = _multipart_body(_good_fields(manifest, files))
        resp = client.post(
            "/diagnose",
            content=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        assert resp.status_code == 503
        assert "503" in resp.text
        assert "预算" in resp.text
        assert "通过的链" not in resp.text
    finally:
        store.release("foreign-req")


def test_twelve_cert_rule_still_enforced(isolated_app):
    """The original 12-certificate diagnostic rule is unchanged."""
    client, _store, _db, _staging = isolated_app
    from tests.cert_factory import VAL, gen_key, make_ca, make_leaf, pem

    root_k = gen_key()
    root = make_ca("Root", "Root", root_k, root_k, self_signed=True)
    certs, keys = [], [root_k]
    for i in range(1, 13):  # 12 intermediates + leaf => well over 12 unique
        k = gen_key()
        certs.append(
            make_ca(f"CA{i}", f"CA{i - 1}" if i > 1 else "Root", k, keys[-1])
        )
        keys.append(k)
    leaf = make_leaf("leaf", "CA12", gen_key(), keys[-1])
    fields = [
        ("leaf", "leaf.pem", pem(leaf)),
        ("root", "root.pem", pem(root)),
        ("intermediates", "inter.pem", b"".join(pem(c) for c in certs)),
        ("validation_time", "", VAL.isoformat()),
    ]
    body, boundary = _multipart_body(fields)
    resp = client.post(
        "/api/diagnose",
        content=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    assert resp.status_code == 400
    assert "12" in resp.json()["error"]
