"""what_bug_this_catches: a green scanner missed blobs or exposed forbidden contents."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.check_secrets import MAX_BLOB_BYTES, content_rules, inspect_paths


@pytest.mark.parametrize(
    "path", [".env", ".ENV", ".creds/key.txt", ".thinking/plan.md", ".chatexports/chat.html"]
)
def test_forbidden_paths_fail_without_reading_contents(path):
    def forbidden_read(name):
        raise AssertionError("forbidden blob was read")

    scanned, failures = inspect_paths([path], forbidden_read)
    assert scanned == 0
    assert failures[0]["rule"] == "forbidden_product_path"


@pytest.mark.parametrize(
    "payload,expected",
    [
        (b"sk-" + b"x" * 48, "provider_key"),
        (b"-----BEGIN " + b"PRIVATE KEY-----", "private_key"),
        (b"TYPESAFE_API_KEY='" + b"x" * 32 + b"'", "literal_credential"),
    ],
)
def test_planted_controls_match_without_returning_secret_values(payload, expected):
    assert expected in content_rules(payload)
    scanned, failures = inspect_paths(["src/control.py"], lambda _: payload)
    assert scanned == 1
    assert failures == [{"path": "src/control.py", "rule": expected}]


def test_public_empty_environment_template_is_scanned_and_allowed():
    scanned, failures = inspect_paths(
        [".env.example"], lambda _: b"OPENAI_API_KEY=\nTYPESAFE_API_KEY=\n"
    )
    assert scanned == 1
    assert failures == []


def test_oversize_blob_cannot_be_a_green_scan():
    scanned, failures = inspect_paths(["large.dat"], lambda _: b"x" * (MAX_BLOB_BYTES + 1))
    assert scanned == 0
    assert failures[0]["rule"] == "blob_not_inspected_over_limit"


def test_staged_blob_is_checked_even_if_working_file_was_cleaned(tmp_path):
    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, check=True)
    control = tmp_path / "control.py"
    control.write_bytes(b"sk-" + b"x" * 48)
    subprocess.run(["git", "add", "--", "control.py"], cwd=tmp_path, check=True)
    control.write_text("clean working copy\n", encoding="utf-8")
    scanner = Path(__file__).resolve().parents[2] / "scripts" / "check_secrets.py"
    result = subprocess.run(
        [sys.executable, str(scanner), "--staged"],
        cwd=tmp_path,
        capture_output=True,
        check=False,
        # Above three 30s git queries so a slow Windows git returns its own status.
        timeout=120,
    )
    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert report["scanned"] == 1
    assert report["failures"] == [{"path": "control.py", "rule": "provider_key"}]
    assert b"x" * 48 not in result.stdout + result.stderr
