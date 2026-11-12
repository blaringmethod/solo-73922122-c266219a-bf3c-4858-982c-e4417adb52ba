"""Cross-process in-flight body budget coordinated through SQLite.

Two (or more) web processes share one SQLite database on a shared volume and
together enforce a global in-flight body budget (default 4 MiB).  Every byte
that enters a multipart parser is *charged* before it is handed over, in small
chunks, so neither process ever buffers a whole request body and neither can
overcommit the shared staging resources.

Design notes
------------
* Every charge is a short ``BEGIN IMMEDIATE`` transaction that commits at once.
  No database write transaction is kept open while a request body is still
  arriving or while diagnosis runs.
* Each process registers itself as a *worker* and keeps a heartbeat file fresh
  on the shared volume.  A surviving process reaps allocations owned by dead
  workers (missing/stale heartbeat), deletes their staging directories and
  returns their bytes to the pool.  Staging directories are namespaced per
  worker, so a reaper can never remove another live request's files.
* SQLite runs in WAL mode with a busy timeout; contention only ever makes a
  writer wait briefly, never hold a long-lived lock.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import sqlite3
import threading
import time
import uuid
from pathlib import Path

DEFAULT_TOTAL_BUDGET = 4 * 1024 * 1024  # 4 MiB shared in-flight body budget
_HEARTBEAT_INTERVAL = 5.0
_REAP_INTERVAL = 10.0
_STALE_SECONDS = 30.0  # heartbeat older than this => worker presumed dead


class SharedBudgetExhausted(Exception):
    """Raised when the cross-process in-flight budget cannot cover a chunk."""


def _connect(db_path: str | os.PathLike[str]) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), timeout=5.0, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


class BudgetStore:
    """SQLite-backed shared byte budget with dead-worker reaping."""

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        staging_root: str | os.PathLike[str],
        worker_name: str | None = None,
        total_budget: int = DEFAULT_TOTAL_BUDGET,
        stale_after: float = _STALE_SECONDS,
    ) -> None:
        self.db_path = Path(db_path)
        self.staging_root = Path(staging_root)
        self.worker_name = worker_name or f"worker-{os.getpid()}"
        # Unique per process incarnation: a recreated container may reuse the
        # same worker name but never this token.
        self.instance_token = uuid.uuid4().hex
        self.total_budget = int(total_budget)
        self.stale_after = float(stale_after)

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.staging_root.mkdir(parents=True, exist_ok=True)
        self._liveness_dir = self.db_path.parent / "liveness"
        self._liveness_dir.mkdir(parents=True, exist_ok=True)

        self._heartbeat_file = (
            self._liveness_dir / f"{self.worker_name}.{self.instance_token}"
        )
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None
        # Serializes the reaper's own transactions; request connections are
        # independent and rely on SQLite's busy timeout instead.
        self._reap_lock = threading.Lock()

    # ------------------------------------------------------------------ paths
    def stage_dir_for(self, req_id: str) -> Path:
        """Per-request staging path, namespaced by worker for safe reaping."""
        path = self.staging_root / self.worker_name / req_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def liveness_path(self) -> Path:
        return self._heartbeat_file

    # ------------------------------------------------------------- lifecycle
    def start(self) -> None:
        """Register this worker and immediately reclaim any dead predecessor."""
        self._heartbeat_file.touch()
        with _connect(self.db_path) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS allocations (
                    req_id     TEXT PRIMARY KEY,
                    worker_id  TEXT NOT NULL,
                    bytes      INTEGER NOT NULL,
                    stage_dir  TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS workers (
                    worker_id      TEXT PRIMARY KEY,
                    instance_token TEXT NOT NULL,
                    pid            INTEGER NOT NULL,
                    heartbeat_at   REAL NOT NULL
                );
                """
            )
            # A previous container/process using the same worker name is
            # necessarily gone: reclaim it before advertising ourselves.
            row = conn.execute(
                "SELECT instance_token FROM workers WHERE worker_id = ?",
                (self.worker_name,),
            ).fetchone()
            if row is not None:
                self._reap_worker(conn, self.worker_name, row[0])
            conn.execute(
                """
                INSERT INTO workers(worker_id, instance_token, pid, heartbeat_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(worker_id) DO UPDATE SET
                    instance_token = excluded.instance_token,
                    pid = excluded.pid,
                    heartbeat_at = excluded.heartbeat_at
                """,
                (self.worker_name, self.instance_token, os.getpid(), time.time()),
            )
        # Sweep anything else left behind by an earlier crash.
        self.reap_once()

    def stop(self) -> None:
        """Best-effort local cleanup; survivors reap us if this is skipped."""
        self._stop.set()
        with contextlib.suppress(Exception):
            with _connect(self.db_path) as conn:
                conn.execute(
                    "DELETE FROM allocations WHERE worker_id = ?",
                    (self.worker_name,),
                )
                conn.execute(
                    "DELETE FROM workers WHERE worker_id = ?",
                    (self.worker_name,),
                )
        with contextlib.suppress(Exception):
            shutil.rmtree(self.staging_root / self.worker_name, ignore_errors=True)
            self._heartbeat_file.unlink(missing_ok=True)

    async def run_background(self) -> None:
        """Heartbeat + reaper loop, run as an asyncio background task."""
        last_heartbeat = 0.0
        last_reap = 0.0
        try:
            while not self._stop.is_set():
                now = time.time()
                if now - last_heartbeat >= _HEARTBEAT_INTERVAL:
                    await asyncio.to_thread(self.heartbeat)
                    last_heartbeat = time.time()
                if now - last_reap >= _REAP_INTERVAL:
                    await asyncio.to_thread(self.reap_once)
                    last_reap = time.time()
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:  # pragma: no cover - shutdown path
            pass

    # ------------------------------------------------------------ heartbeats
    def heartbeat(self) -> None:
        now = time.time()
        with contextlib.suppress(OSError):
            self._heartbeat_file.touch()
        with contextlib.suppress(sqlite3.Error), _connect(self.db_path) as conn:
            conn.execute(
                "UPDATE workers SET heartbeat_at = ? WHERE worker_id = ?",
                (now, self.worker_name),
            )

    def _is_alive(self, worker_id: str, token: str, now: float) -> bool:
        """Liveness proof is a *fresh* heartbeat file on the shared volume.

        A crashed container leaves its file behind, so mere existence is not
        enough: its mtime must be recent (the running counterpart touches it
        every few seconds).  All containers share the host kernel clock.
        """
        path = self._liveness_dir / f"{worker_id}.{token}"
        try:
            mtime = path.stat().st_mtime
        except FileNotFoundError:
            return False
        return (now - mtime) <= self.stale_after

    # ---------------------------------------------------------------- reaper
    def reap_once(self) -> int:
        """Reclaim allocations/staging of dead workers. Returns bytes freed."""
        freed = 0
        with self._reap_lock:
            with _connect(self.db_path) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    now = time.time()
                    workers = conn.execute(
                        "SELECT worker_id, instance_token FROM workers"
                    ).fetchall()
                    dead = [
                        (w, token)
                        for w, token in workers
                        if w != self.worker_name and not self._is_alive(w, token, now)
                    ]
                    orphan_dirs: list[str] = []
                    for worker_id, _token in dead:
                        freed += self._reap_worker(conn, worker_id, _token)
                        orphan_dirs.append(worker_id)

                    # Defensive: allocations whose worker row vanished.
                    orphans = conn.execute(
                        """
                        SELECT DISTINCT a.worker_id
                        FROM allocations a
                        LEFT JOIN workers w ON w.worker_id = a.worker_id
                        WHERE w.worker_id IS NULL
                        """
                    ).fetchall()
                    for (worker_id,) in orphans:
                        rows = conn.execute(
                            "SELECT stage_dir, bytes FROM allocations "
                            "WHERE worker_id = ?",
                            (worker_id,),
                        ).fetchall()
                        for stage_dir, num_bytes in rows:
                            orphan_dirs.append(worker_id)
                            freed += int(num_bytes)
                            with contextlib.suppress(OSError):
                                shutil.rmtree(stage_dir, ignore_errors=True)
                        conn.execute(
                            "DELETE FROM allocations WHERE worker_id = ?",
                            (worker_id,),
                        )
                    conn.execute("COMMIT")
                except Exception:
                    conn.execute("ROLLBACK")
                    raise

            # Whole-worker namespace removal outside the DB transaction.
            for worker_id in set(orphan_dirs):
                with contextlib.suppress(OSError):
                    shutil.rmtree(
                        self.staging_root / worker_id, ignore_errors=True
                    )
                for stale in self._liveness_dir.glob(f"{worker_id}.*"):
                    with contextlib.suppress(OSError):
                        stale.unlink()
        return freed

    def _reap_worker(
        self, conn: sqlite3.Connection, worker_id: str, token: str
    ) -> int:
        """Delete one dead worker's rows. Caller owns the transaction."""
        rows = conn.execute(
            "SELECT stage_dir, bytes FROM allocations WHERE worker_id = ?",
            (worker_id,),
        ).fetchall()
        freed = 0
        for stage_dir, num_bytes in rows:
            freed += int(num_bytes)
            with contextlib.suppress(OSError):
                shutil.rmtree(stage_dir, ignore_errors=True)
        conn.execute("DELETE FROM allocations WHERE worker_id = ?", (worker_id,))
        conn.execute("DELETE FROM workers WHERE worker_id = ?", (worker_id,))
        with contextlib.suppress(OSError):
            self._liveness_dir.joinpath(f"{worker_id}.{token}").unlink(
                missing_ok=True
            )
        return freed

    # ------------------------------------------------------------- per-query
    def charge(self, req_id: str, num_bytes: int) -> None:
        """Reserve ``num_bytes`` for one request or fail immediately.

        Raises :class:`SharedBudgetExhausted` without queuing when the shared
        4 MiB pool cannot cover the chunk.  The transaction commits before
        this method returns, so no write lock is held afterwards.
        """
        if num_bytes <= 0:
            return
        with _connect(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                used = conn.execute(
                    "SELECT COALESCE(SUM(bytes), 0) FROM allocations"
                ).fetchone()[0]
                if used + num_bytes > self.total_budget:
                    conn.execute("ROLLBACK")
                    raise SharedBudgetExhausted(
                        f"共享在途正文预算 {self.total_budget} 字节不足"
                        f"（当前已占用 {used} 字节，本次需要 {num_bytes} 字节）"
                    )
                conn.execute(
                    """
                    INSERT INTO allocations(req_id, worker_id, bytes, stage_dir,
                                            created_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(req_id) DO UPDATE SET
                        bytes = allocations.bytes + excluded.bytes
                    """,
                    (
                        req_id,
                        self.worker_name,
                        num_bytes,
                        str(self.staging_root / self.worker_name / req_id),
                        time.time(),
                    ),
                )
                conn.execute("COMMIT")
            except SharedBudgetExhausted:
                raise
            except Exception:
                with contextlib.suppress(sqlite3.Error):
                    conn.execute("ROLLBACK")
                raise

    def release(self, req_id: str) -> None:
        """Return the whole reservation for one request to the shared pool."""
        with contextlib.suppress(sqlite3.Error), _connect(self.db_path) as conn:
            conn.execute("DELETE FROM allocations WHERE req_id = ?", (req_id,))

    def current_usage(self) -> int:
        with _connect(self.db_path) as conn:
            return conn.execute(
                "SELECT COALESCE(SUM(bytes), 0) FROM allocations"
            ).fetchone()[0]
