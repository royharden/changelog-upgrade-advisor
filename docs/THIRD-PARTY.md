# Dependencies and provenance

The npm registry metadata was inspected for semver 7.8.5 (ISC) before selecting the exact root dependency. The package-lock preserves its resolved URL and integrity, checked by `npm ci --ignore-scripts`. The library supplies npm semantics through the bounded Node adapter. Wheel builds include this exact installed package and its ISC license under `changelog_advisor/node_modules/semver`; no dependency install scripts run. [Upstream](https://github.com/npm/node-semver).

Python dependencies are resolved through uv.lock. The W0 setup installed Python 3.12.13, Pydantic 2.14.1, pytest 9.1.1, ruff 0.17.0 and pre-commit 4.7.0. Canonical shared modules retain their owning source and license in their VENDORED.md records. S3 provider/Ledger source is MIT at exact commit6edb2b6fae0870fb5242bc10b77e065b774a0a45. Optional openai3.31.0 is Apache-2.0; typesafe-sdk0.7.5 is MIT. The lock preserves the full SDK closure, with upstream notices retained in installed distributions. Product license is MIT. No prior-art or cookbook source is copied.

CI action versions are pinned to actual release commit references inspected through their upstream GitHub metadata: actions/checkout v7.0.1, actions/setup-node v7.1.0, astral-sh/setup-uv v10.3.0. A workflow file does not prove hosted CI execution.
