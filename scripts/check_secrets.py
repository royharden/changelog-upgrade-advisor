"""Bounded staged/index blob guard. Report rule names, never matching content."""

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Callable, Iterable
from pathlib import PurePosixPath

MAX_BLOB_BYTES = 2 * 1024 * 1024
FORBIDDEN_PARTS = {
    ".git",
    ".creds",
    ".agent-registry",
    ".agent-work",
    ".thinking",
    ".chatexports",
    "agentops",
}
RULES = {
    "private_key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "provider_key": re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b"),
    "literal_credential": re.compile(
        rb"(?i)\b(?:OPENAI_API_KEY|TYPESAFE_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN|"
        rb"api_key|access_token|password)\s*[:=]\s*['\"][^'\"\r\n]{16,}['\"]"
    ),
}


def forbidden_path(path: str) -> bool:
    parsed = PurePosixPath(path)
    return (
        parsed.is_absolute()
        or ".." in parsed.parts
        or any(part.lower() in FORBIDDEN_PARTS for part in parsed.parts)
        or (parsed.name.lower().startswith(".env") and parsed.name.lower() != ".env.example")
    )


def content_rules(content: bytes) -> list[str]:
    return [name for name, pattern in RULES.items() if pattern.search(content)]


def inspect_paths(
    paths: Iterable[str], read_blob: Callable[[str], bytes]
) -> tuple[int, list[dict[str, str]]]:
    scanned = 0
    failures: list[dict[str, str]] = []
    for path in paths:
        if forbidden_path(path):
            failures.append({"path": path, "rule": "forbidden_product_path"})
            continue  # Never inspect credential/agent-only blob contents.
        content = read_blob(path)
        if len(content) > MAX_BLOB_BYTES:
            failures.append({"path": path, "rule": "blob_not_inspected_over_limit"})
            continue
        scanned += 1
        failures.extend({"path": path, "rule": rule} for rule in content_rules(content))
    return scanned, failures


def _git(*arguments: str) -> bytes:
    result = subprocess.run(["git", *arguments], capture_output=True, check=False, timeout=15)
    if result.returncode:
        raise RuntimeError("git_index_query_failed")
    return result.stdout


def index_blob(path: str) -> bytes:
    size = int(_git("cat-file", "-s", f":{path}"))
    if size > MAX_BLOB_BYTES:
        raise RuntimeError("index_blob_over_limit")
    return _git("cat-file", "blob", f":{path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--staged", action="store_true")
    modes.add_argument("--tracked", action="store_true")
    args = parser.parse_args(argv)
    try:
        names = (
            _git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
            if args.staged
            else _git("ls-files", "-z")
        )
        paths = [name.decode("utf-8") for name in names.split(b"\0") if name]
        scanned, failures = inspect_paths(paths, index_blob)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        print(json.dumps({"status": "error", "reason": "index_not_fully_inspected"}))
        return 2
    print(json.dumps({"scanned": scanned, "failures": failures}, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
