"""Inert W0 command surface. Analysis is a later implementation slice."""

import argparse
import json
from collections.abc import Sequence

from changelog_advisor import __version__


def bootstrap_status() -> dict[str, object]:
    """Describe implemented scope without reading files, keys, or the network."""
    return {
        "application": "changelog-upgrade-advisor",
        "version": __version__,
        "stage": "bootstrap",
        "mode": "offline",
        "implemented_commands": ["status"],
        "analysis_available": False,
        "provider_calls": 0,
        "pending": [
            "npm version and advisory analysis",
            "resolvable findings and checklist rendering",
            "five-dependency demonstration and evaluation",
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local dependency upgrade advisor")
    parser.add_argument("command", choices=["status"], help="Show the current offline capability")
    parser.parse_args(argv)
    print(json.dumps(bootstrap_status(), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
