"""Offline bootstrap demonstration; not the pending MVP analysis workflow."""

import argparse
import json

from changelog_advisor.__main__ import bootstrap_status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["offline"], default="offline")
    parser.parse_args()
    print(json.dumps(bootstrap_status(), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
