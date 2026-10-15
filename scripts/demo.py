"""Run the original five-dependency/two-advisory local demo; no provider calls."""

import argparse
from pathlib import Path

from changelog_advisor.__main__ import main as advisor


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["offline"], default="offline")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--refusal", action="store_true")
    args = parser.parse_args()
    command = ["demo", "--out", str(args.out)]
    if args.refusal:
        command.append("--refusal")
    return advisor(command)


if __name__ == "__main__":
    raise SystemExit(main())
