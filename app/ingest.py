"""Streaming multipart ingestion with per-request and shared byte budgets.

The framework's usual ``UploadFile`` machinery buffers whole parts before the
endpoint runs.  That is exactly what we must avoid here: instead we drive
python-multipart's push parser ourselves, chunk by chunk, straight from the
ASGI receive stream.

For every chunk pulled off the socket we, in order:

1. enforce the per-request cap (default 2 MiB, counting *all* multipart
   overhead and unknown fields too — Content-Length is never trusted),
2. charge the bytes against the cross-process SQLite budget (413 vs 503),
3. only then hand the chunk to the parser.

Part payloads are written to per-request temporary files under the shared
staging volume; nothing holds the whole body in memory.  On any exit path
(success, bad PEM, parse failure, over-limit, client disconnect) the staging
directory is removed and the reservation released.
"""

from __future__ import annotations

import contextlib
import dataclasses
import shutil
import uuid
from pathlib import Path

from python_multipart.exceptions import MultipartParseError
from python_multipart.multipart import MultipartParser, parse_options_header
from starlette.datastructures import Headers

from .budget import BudgetStore, SharedBudgetExhausted

DEFAULT_PER_REQUEST_LIMIT = 2 * 1024 * 1024  # 2 MiB full multipart body
_FORM_FIELD_LIMIT = 64 * 1024  # validation_time etc. are tiny; cap abuse
_KNOWN_FILE_FIELDS = ("leaf", "intermediates", "root")
_KNOWN_FORM_FIELDS = ("validation_time",)


class RequestTooLarge(Exception):
    """The single request's full multipart body exceeded 2 MiB."""


class MultipartMalformed(Exception):
    """The body could not be parsed as multipart/form-data."""


@dataclasses.dataclass
class UploadedPart:
    field_name: str
    filename: str
    path: Path
    size: int

    def read_bytes(self) -> bytes:
        with self.path.open("rb") as handle:
            return handle.read()

    def close(self) -> None:
        # The file lives in the per-request staging dir, which is removed in
        # one shot; close() exists so callers can release handles explicitly.
        pass


@dataclasses.dataclass
class MultipartPayload:
    files: dict[str, UploadedPart]
    form: dict[str, str]
    req_id: str
    stage_dir: Path
    store: BudgetStore

    def close_all(self) -> None:
        """Close/remove every upload temp file and release the reservation."""
        with contextlib.suppress(Exception):
            shutil.rmtree(self.stage_dir, ignore_errors=True)
        self.store.release(self.req_id)


class _PartSink:
    """One in-progress part, streamed straight to its own temp file."""

    def __init__(self, stage_dir: Path, field_name: str, filename: str | None):
        self.field_name = field_name
        self.filename = filename or ""
        self.is_file = filename is not None
        name = f"{field_name}-{uuid.uuid4().hex}.part"
        self.path = stage_dir / name
        self.handle = self.path.open("wb")
        self.size = 0

    def write(self, data: bytes) -> None:
        self.handle.write(data)
        self.size += len(data)

    def close(self) -> None:
        if not self.handle.closed:
            self.handle.flush()
            self.handle.close()


class _StreamingMultipart:
    def __init__(
        self,
        request,
        store: BudgetStore,
        per_request_limit: int = DEFAULT_PER_REQUEST_LIMIT,
    ) -> None:
        self.request = request
        self.store = store
        self.per_request_limit = per_request_limit

        content_type = request.headers.get("content-type", "")
        ctype, options = parse_options_header(content_type)
        if ctype != b"multipart/form-data" or not options.get(b"boundary"):
            raise MultipartMalformed(
                "请求必须是 multipart/form-data 且带 boundary，无法流式解析。"
            )
        boundary = options[b"boundary"]

        self.req_id = uuid.uuid4().hex
        self.stage_dir = store.stage_dir_for(self.req_id)
        self.request_bytes = 0
        self.finished = False

        self._sinks: list[_PartSink] = []
        self._current: _PartSink | None = None
        self._header_name = bytearray()
        self._header_value = bytearray()
        self._part_headers: list[tuple[bytes, bytes]] = []

        callbacks = {
            "on_part_begin": self._on_part_begin,
            "on_part_end": self._on_part_end,
            "on_header_field": self._on_header_field,
            "on_header_value": self._on_header_value,
            "on_header_end": self._on_header_end,
            "on_headers_finished": self._on_headers_finished,
            "on_part_data": self._on_part_data,
            "on_end": self._on_end,
        }
        self.parser = MultipartParser(boundary, callbacks)

    # ------------------------------------------------------- parser events
    def _on_part_begin(self) -> None:
        self._part_headers = []

    def _on_header_field(self, data: bytes, start: int, end: int) -> None:
        self._header_name += data[start:end]

    def _on_header_value(self, data: bytes, start: int, end: int) -> None:
        self._header_value += data[start:end]

    def _on_header_end(self) -> None:
        self._part_headers.append(
            (bytes(self._header_name).strip().lower(), bytes(self._header_value).strip())
        )
        self._header_name = bytearray()
        self._header_value = bytearray()

    def _on_headers_finished(self) -> None:
        headers = Headers(raw=[(k, v) for k, v in self._part_headers])
        disposition = headers.get("content-disposition", "")
        _, disp_options = parse_options_header(disposition)
        field_name = disp_options.get(b"name", b"").decode("latin-1")
        raw_filename = disp_options.get(b"filename")
        filename = raw_filename.decode("latin-1") if raw_filename is not None else None
        self._current = _PartSink(self.stage_dir, field_name, filename)
        self._sinks.append(self._current)

    def _on_part_data(self, data: bytes, start: int, end: int) -> None:
        chunk = data[start:end]
        current = self._current
        assert current is not None
        if not current.is_file and current.size + len(chunk) > _FORM_FIELD_LIMIT:
            raise MultipartMalformed(
                f"表单字段 {current.field_name!r} 超过 {_FORM_FIELD_LIMIT} 字节上限。"
            )
        current.write(chunk)

    def _on_part_end(self) -> None:
        if self._current is not None:
            self._current.close()
        self._current = None

    def _on_end(self) -> None:
        self.finished = True

    # ------------------------------------------------------------- driving
    async def read(self) -> MultipartPayload:
        """Pull the body off the socket without buffering it wholesale."""
        try:
            async for chunk in self.request.stream():
                if not chunk:
                    continue
                # 1) per-request cap: raw wire bytes, overhead included.
                self.request_bytes += len(chunk)
                if self.request_bytes > self.per_request_limit:
                    raise RequestTooLarge(
                        f"单个请求 multipart 正文超过 "
                        f"{self.per_request_limit} 字节上限"
                        f"（已实际接收 {self.request_bytes} 字节，"
                        "multipart 边界与表单开销同样计入）。"
                    )
                # 2) shared cross-process budget, before the parser sees it.
                try:
                    self.store.charge(self.req_id, len(chunk))
                except SharedBudgetExhausted:
                    raise
                # 3) only now may the chunk enter the parser.
                try:
                    self.parser.write(chunk)
                except MultipartParseError as exc:
                    raise MultipartMalformed(f"multipart 解析失败：{exc}") from exc

            try:
                self.parser.finalize()
            except MultipartParseError as exc:
                raise MultipartMalformed(f"multipart 结尾不完整：{exc}") from exc
            if not self.finished:
                raise MultipartMalformed(
                    "multipart 正文在结束边界之前中断（客户端断连或请求被截断）。"
                )
            return self._build_payload()
        except Exception:
            # Universal cleanup: over-limit, 503, parse error, disconnect...
            self._abort()
            raise

    def _abort(self) -> None:
        for sink in self._sinks:
            with contextlib.suppress(Exception):
                sink.close()
        with contextlib.suppress(Exception):
            shutil.rmtree(self.stage_dir, ignore_errors=True)
        self.store.release(self.req_id)

    def _build_payload(self) -> MultipartPayload:
        files: dict[str, UploadedPart] = {}
        form: dict[str, str] = {}
        for sink in self._sinks:
            sink.close()
            if sink.is_file:
                # Keep the first part per field name; extra ones still
                # consumed budget and were streamed, never buffered.
                if sink.field_name in _KNOWN_FILE_FIELDS and sink.field_name not in files:
                    files[sink.field_name] = UploadedPart(
                        field_name=sink.field_name,
                        filename=sink.filename,
                        path=sink.path,
                        size=sink.size,
                    )
            else:
                if sink.field_name in _KNOWN_FORM_FIELDS and sink.field_name not in form:
                    form[sink.field_name] = sink.path.read_text(
                        encoding="utf-8", errors="replace"
                    )
        return MultipartPayload(
            files=files,
            form=form,
            req_id=self.req_id,
            stage_dir=self.stage_dir,
            store=self.store,
        )


async def read_multipart(
    request,
    store: BudgetStore,
    per_request_limit: int = DEFAULT_PER_REQUEST_LIMIT,
) -> MultipartPayload:
    """Public entry point used by both HTML and JSON routes."""
    reader = _StreamingMultipart(request, store, per_request_limit)
    return await reader.read()
