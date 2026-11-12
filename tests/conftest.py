"""Shared pytest configuration: point data/staging at a throwaway directory."""

import os
import tempfile
from pathlib import Path

import pytest

_TEST_DATA = Path(tempfile.mkdtemp(prefix="mtls-test-data-"))
os.environ.setdefault("APP_DATA_DIR", str(_TEST_DATA))
os.environ.setdefault("BUDGET_DB", str(_TEST_DATA / "budget" / "budget.db"))
os.environ.setdefault("STAGING_DIR", str(_TEST_DATA / "staging"))
os.environ.setdefault("WORKER_NAME", "pytest-worker")
# Tight budgets make the 503 paths testable without huge payloads.
os.environ.setdefault("TOTAL_BUDGET", str(4 * 1024 * 1024))
os.environ.setdefault("PER_REQUEST_LIMIT", str(2 * 1024 * 1024))


@pytest.fixture()
def data_dir() -> Path:
    return _TEST_DATA
