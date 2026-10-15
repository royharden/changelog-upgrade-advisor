"""Inert status inventory plus explicitly requested local analysis commands."""

import argparse
import json
from collections.abc import Sequence

from changelog_advisor import __version__


def bootstrap_status() -> dict[str, object]:
    """Describe implemented scope without reading files, keys, or the network."""
    return {
        "application": "changelog-upgrade-advisor",
        "version": __version__,
        "stage": "offline-checklist",
        "mode": "offline",
        "implemented_commands": ["status", "analyze", "demo"],
        "analysis_available": True,
        "structural_models_available": True,
        "library_capabilities": [
            "supplied_memory_citations",
            "npm_exact_pins",
            "npm_release_windows",
            "offline_cited_checklist",
            "OSV_and_GHSA_membership",
        ],
        "version_runtime_required": "Node >=22 with semver@7.8.5",
        "installed_domain_resolvers": 0,
        "provider_calls": 0,
        "pending": [
            "installed live model adapters and conditional usage judge",
            "measured model evaluation and selection",
            "independent finished-app acceptance",
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    import sys

    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ("analyze", "demo"):
        from .cli import run

        return run(argv)
    parser = argparse.ArgumentParser(description="Local dependency upgrade advisor")
    parser.add_argument("command", choices=["status"], help="Show the current offline capability")
    parser.parse_args(argv)
    print(json.dumps(bootstrap_status(), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
