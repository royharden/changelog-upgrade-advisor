"""what_bug_this_catches: installed demo searches outside its package for fixtures."""

import json

import pytest

from changelog_advisor import cli


@pytest.mark.parametrize("refusal,expected", [(False, 0), (True, 3)])
def test_demo_resources_do_not_depend_on_cli_repository_path(
    refusal, expected, tmp_path, monkeypatch, capsys
):
    monkeypatch.setattr(cli, "__file__", str(tmp_path / "installed/changelog_advisor/cli.py"))
    out = tmp_path / "report"
    args = ["demo", "--out", str(out)] + (["--refusal"] if refusal else [])
    assert cli.run(args) == expected
    result = json.loads(capsys.readouterr().out)
    assert result["counts"]["packages"] == 5
    assert result["counts"]["advisory_records"] == 2
    assert result["provider_calls"] == 0
    assert {path.name for path in out.iterdir()} == {
        "checklist.json",
        "checklist.md",
        "checklist.html",
    }
