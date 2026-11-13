"""what_bug_this_catches: installed demo searches outside its package for fixtures."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from changelog_advisor import cli

ROOT = Path(__file__).resolve().parents[2]


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


def test_shipped_demo_checklist_survives_a_new_process(tmp_path):
    """what_bug_this_catches: the demo prints a checklist the next process cannot read back."""
    out = tmp_path / "durable"
    completed = subprocess.run(
        [sys.executable, "-m", "changelog_advisor", "demo", "--out", str(out)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    reported = json.loads(completed.stdout)
    assert reported["provider_calls"] == 0
    assert reported["status"]
    paths = reported["artifacts"]
    for name in ("checklist.json", "checklist.md", "checklist.html"):
        artifact = Path(paths[name])
        assert artifact.is_file() and artifact.stat().st_size > 0
    reread = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import json,sys; from pathlib import Path; "
                "data=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8')); "
                "print(json.dumps({'status': data['workflow_status'], "
                "'counts': data['counts'], 'provider_calls': data['provider_calls']}, "
                "sort_keys=True))"
            ),
            paths["checklist.json"],
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert reread.returncode == 0, reread.stderr
    restored = json.loads(reread.stdout)
    assert restored["status"] == reported["status"]
    assert restored["counts"] == reported["counts"]
    assert restored["provider_calls"] == 0
    checklist = json.loads(Path(paths["checklist.json"]).read_text(encoding="utf-8"))
    assert checklist["packages"]
    assert len(checklist["packages"]) == reported["counts"]["packages"]
    markdown = Path(paths["checklist.md"]).read_text(encoding="utf-8")
    assert f"Workflow: {reported['status'].replace('_', '\\_')}" in markdown
    assert "provider calls: 0" in markdown
