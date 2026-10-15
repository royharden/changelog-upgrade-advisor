"""Consumer-owned guards around actual moved public controls; no provider/network effects."""

import builtins
import socket
import urllib.request
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def consumer_boundary_guards(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("consumer conformance attempted actual network")

    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(urllib.request, "urlopen", denied)
    original_import = builtins.__import__

    def importing(name, *args, **kwargs):
        if name.split(".")[0] in ("llm_router_eval", "openai", "typesafe", "anthropic"):
            raise AssertionError("owner app or live SDK import forbidden")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", importing)
    original_open = builtins.open
    original_path_open = Path.open

    def check(path):
        if isinstance(path, (str, Path)) and ".creds" in Path(path).parts:
            raise AssertionError("credential file access forbidden")

    def opening(file, *args, **kwargs):
        check(file)
        return original_open(file, *args, **kwargs)

    def path_opening(self, *args, **kwargs):
        check(self)
        return original_path_open(self, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", opening)
    monkeypatch.setattr(Path, "open", path_opening)
