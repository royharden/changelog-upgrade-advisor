"""Actual canonical offline boundary guard; no SDK, network or credential access."""

import importlib.util
from pathlib import Path

import pytest

path = Path(__file__).resolve().parents[2] / "vendor/s3/tests/conftest.py"
spec = importlib.util.spec_from_file_location("judges_actual_offline_guard", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@pytest.fixture(autouse=True)
def actual_offline_boundary(monkeypatch):
    module.consumer_boundary_guards.__wrapped__(monkeypatch)
