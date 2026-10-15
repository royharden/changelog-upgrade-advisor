"""what_bug_this_catches: a screen copy replaces S3 types or collides in combined collection."""

import builtins
import importlib.util
import socket
from pathlib import Path

import pytest

from changelog_advisor.shared.callledger.models import canonical_digest
from changelog_advisor.shared.providers.controller import Provider
from changelog_advisor.shared.providers.models import TypedJudgmentRequest
from changelog_advisor.shared.screen import s3_adapter


def test_same_actual_canonical_native_objects():
    assert s3_adapter.Provider is Provider
    assert s3_adapter.TypedJudgmentRequest is TypedJudgmentRequest
    assert s3_adapter.canonical_digest is canonical_digest
    assert not any(
        n.startswith(("issue_triage", "llm_router_eval")) for n in __import__("sys").modules
    )


def test_actual_reused_offline_guard_blocks_owner_sdk_network_credentials(monkeypatch, tmp_path):
    path = Path(__file__).resolve().parents[3] / "vendor/s6/tests/conftest.py"
    spec = importlib.util.spec_from_file_location("s6_owned_guard", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.consumer_boundary_guards.__wrapped__(monkeypatch)
    with pytest.raises(AssertionError, match="SDK"):
        builtins.__import__("openai")
    with pytest.raises(AssertionError, match="owner"):
        builtins.__import__("llm_router_eval")
    with pytest.raises(AssertionError, match="owner"):
        builtins.__import__("issue_triage")
    with pytest.raises(AssertionError, match="network"):
        socket.create_connection(("example.test", 443))
    with pytest.raises(AssertionError, match="credential"):
        (tmp_path / ".creds" / "never-created").open()
