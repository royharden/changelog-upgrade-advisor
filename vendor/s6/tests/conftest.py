"""Reuse the actual owned offline boundary fixture for moved S6 controls."""

import builtins
import importlib.util
from pathlib import Path

import pytest

guard = Path(__file__).resolve().parents[2] / "s3/tests/conftest.py"
spec = importlib.util.spec_from_file_location("s5_shared_offline_boundary_guard", guard)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@pytest.fixture(autouse=True)
def consumer_boundary_guards(monkeypatch):
    module.consumer_boundary_guards.__wrapped__(monkeypatch)
    original = builtins.__import__

    def importing(name, *args, **kwargs):
        if name == "issue_triage" or name.startswith("issue_triage."):
            raise AssertionError("owner import forbidden")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", importing)
