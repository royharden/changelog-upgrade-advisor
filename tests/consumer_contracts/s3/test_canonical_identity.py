"""what_bug_this_catches: consumer imports duplicate provider/ledger types or grants SDK effects."""

import builtins
import socket
from pathlib import Path

import pytest

from changelog_advisor.shared.callledger import Ledger
from changelog_advisor.shared.callledger import models as ledger_models
from changelog_advisor.shared.providers import controller, models


def test_same_actual_canonical_ledger_and_context_identity():
    assert controller.Ledger is Ledger
    assert controller.CallContext is ledger_models.CallContext
    assert models.TypedJudgmentRequest.__module__ == "changelog_advisor.shared.providers.models"
    assert not any(name.startswith("llm_router_eval") for name in __import__("sys").modules)


def test_moved_boundary_guards_are_positive_controls(monkeypatch, tmp_path):
    import importlib.util

    guard_path = Path(__file__).resolve().parents[3] / "vendor/s3/tests/conftest.py"
    spec = importlib.util.spec_from_file_location("consumer_guard", guard_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # The exact actual fixture implementation, not a parallel test guard.
    module.consumer_boundary_guards.__wrapped__(monkeypatch)
    with pytest.raises(AssertionError, match="network"):
        socket.create_connection(("example.test", 443))
    with pytest.raises(AssertionError, match="SDK"):
        builtins.__import__("openai")
    with pytest.raises(AssertionError, match="owner"):
        builtins.__import__("llm_router_eval")
    with pytest.raises(AssertionError, match="credential"):
        (tmp_path / ".creds" / "synthetic-never-created").open()
