# Dependencies and provenance

The npm registry metadata was inspected for semver 7.8.5 (ISC) before selecting the exact root dependency. The generated package-lock must preserve the actual resolved integrity. The library supplies npm semantics; this bootstrap does not implement its business adapter yet. [Upstream](https://github.com/npm/node-semver).

Python dependencies are resolved through the generated uv.lock. The W0 setup installed Python 3.12.13, Pydantic 2.14.1, pytest 9.1.1, ruff 0.17.0 and pre-commit 4.7.0; lockfiles retain the complete resolved closure. Installed licence metadata is recorded in local verification receipts. Product licence is MIT. No prior-art source code or cookbook code is copied; no other app module is claimed vendored.

CI action versions are pinned to actual release commit references inspected through their upstream GitHub metadata: actions/checkout v7.0.1, actions/setup-node v7.1.0, astral-sh/setup-uv v10.3.0. A workflow file does not prove hosted CI execution.
