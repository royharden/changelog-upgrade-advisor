"""Explicit local file intake and static artifacts; payloads cannot choose paths or actions."""

import argparse
import json
import sys
from pathlib import Path

from .pipeline import analyze_bundle, read_bundle
from .report import write_reports
from .shared.versions.runtime import VersionRuntimeError


def run(argv):
    parser = argparse.ArgumentParser(description="Build a local dependency upgrade checklist")
    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze", help="Analyze an explicit supplied JSON bundle")
    analyze.add_argument("--bundle", type=Path, required=True, help="JSON file, or - for stdin")
    demo = commands.add_parser("demo", help="Run five synthetic dependencies and two advisories")
    demo.add_argument(
        "--refusal", action="store_true", help="Show an unresolved-pin/missing-source case"
    )
    for command in (analyze, demo):
        command.add_argument(
            "--out", type=Path, required=True, help="New output directory; existing paths refused"
        )
        command.add_argument(
            "--method", choices=("keyword", "typed", "generative"), default="keyword"
        )
    args = parser.parse_args(argv)
    try:
        path = (
            args.bundle
            if args.command == "analyze"
            else (
                Path(__file__).resolve().parents[2]
                / "fixtures/demo-seeded"
                / ("refusal.json" if args.refusal else "normal.json")
            )
        )
        if args.command == "analyze" and path == Path("-"):
            raw = sys.stdin.buffer.read(64 * 1024 * 1024 + 1)
        else:
            with path.open("rb") as stream:
                raw = stream.read(64 * 1024 * 1024 + 1)
        report = analyze_bundle(read_bundle(raw), method=args.method)
        paths = write_reports(report, args.out)
    except (ValueError, TypeError, OSError, UnicodeError, RecursionError, VersionRuntimeError):
        print(
            json.dumps(
                {
                    "status": "refused",
                    "reason": "invalid_or_unavailable_local_input_runtime_or_output",
                    "provider_calls": 0,
                    "output_overwrite": False,
                },
                sort_keys=True,
            )
        )
        return 2
    print(
        json.dumps(
            {
                "status": report["workflow_status"],
                "counts": report["counts"],
                "artifacts": paths,
                "provider_calls": 0,
                "semantic_quality": "unmeasured",
            },
            sort_keys=True,
        )
    )
    return 3 if report["workflow_status"] == "partial" else 0
