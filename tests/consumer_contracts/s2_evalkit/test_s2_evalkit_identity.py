"""what_bug_this_catches: consumer replaces canonical eval types or permits network effects."""

import importlib.util
import socket
import sys
from pathlib import Path

import pytest

from changelog_advisor.shared.evalkit import (
    corpus,
    identity,
    models,
    reporting,
    resampling,
    runner,
    statistics,
)


def test_s2_uses_same_actual_canonical_types_and_functions():
    assert runner.Outcome is models.Outcome
    assert runner.canonical_bytes is identity.canonical_bytes
    assert runner.validate_records is corpus.validate_records
    assert reporting.Statistic is statistics.Statistic
    assert resampling.Statistic is statistics.Statistic
    assert resampling.canonical_bytes is identity.canonical_bytes
    assert not any(name == "rfr" or name.startswith("rfr.") for name in sys.modules)


def test_s2_moved_suite_network_guard_actually_denies(monkeypatch):
    path = Path(__file__).resolve().parents[3] / "vendor/s2-evalkit/tests/evalkit/conftest.py"
    spec = importlib.util.spec_from_file_location("s2_owned_guard", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.forbid_network.__wrapped__(monkeypatch)
    with pytest.raises(AssertionError, match="network disabled"):
        socket.create_connection(("example.invalid", 443))
    with pytest.raises(AssertionError, match="network disabled"):
        socket.socket().connect(("example.invalid", 443))
