"""what_bug_this_catches: bootstrap reads keys, runs input, or invents analysis."""

import json
import os
import socket
import subprocess

import pytest

from changelog_advisor.__main__ import main


def test_status_does_not_access_external_state(monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        raise AssertionError("bootstrap attempted an external effect")

    monkeypatch.setattr(os, "getenv", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    assert main(["status"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["analysis_available"] is False
    assert output["provider_calls"] == 0
    assert "findings" not in output


def test_unknown_analysis_command_refuses_before_input_access(monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        raise AssertionError("unsupported command executed a process")

    monkeypatch.setattr(subprocess, "run", forbidden)
    with pytest.raises(SystemExit) as error:
        main(["check", "$(run-untrusted-command)"])
    assert error.value.code == 2
    assert capsys.readouterr().out == ""
