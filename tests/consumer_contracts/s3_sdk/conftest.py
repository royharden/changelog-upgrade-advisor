"""Exact producer public test fixtures, with documented consumer-only namespace mapping."""

import importlib.util
import socket
from pathlib import Path

import pytest

path = Path(__file__).resolve().parents[3] / "vendor/s3-sdk/tests/providers/conftest.py"
spec = importlib.util.spec_from_file_location("s5_actual_s3_sdk_fixture", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
Rig = module.Rig
rig = module.rig
factory = module.factory
spy = module.spy
reply = module.reply


@pytest.fixture(autouse=True)
def no_parent_network(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("S5 SDK mock consumer attempted parent network")

    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket, "getaddrinfo", denied)
