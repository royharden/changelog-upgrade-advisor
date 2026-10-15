"""Deny actual SDK, credential and network effects during local workflow checks."""

import importlib.util
from pathlib import Path

import pytest

path = Path(__file__).resolve().parents[2] / "vendor/s3/tests/conftest.py"
spec = importlib.util.spec_from_file_location("workflow_owned_boundary", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@pytest.fixture(autouse=True)
def offline_boundaries(monkeypatch):
    module.consumer_boundary_guards.__wrapped__(monkeypatch)
