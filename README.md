# Changelog Upgrade Advisor

A local tool for dependency upgrade checklists with exact quoted evidence and explicit uncertainty. Current local libraries provide supplied-memory citation resolution and npm pin/window facts. The status CLI reports this stage; the complete dependency workflow remains pending.

## Quickstart

Install Python 3.12, uv and Node 22 or newer, then run from the repository root:

```sh
uv sync --frozen
npm ci --ignore-scripts
uv run advisor status
uv run python scripts/demo.py --mode offline
```

The status command reports local foundation scope, offline mode, zero app-installed resolvers and pending analysis. It requires no keys and does not inspect a manifest or generate findings. Explicit library callers can install memory sources and invoke the pinned npm runtime; the required five-dependency/two-advisory demonstration remains pending.

## Intended workflow

Supply package.json, an optional package-lock, targets and per-package release notes, with optional usage snippets. The planned output is JSON, Markdown and a self-contained HTML checklist containing deterministic version facts, potential breaking changes, resolvable quotes, advisories and visible unknown/error coverage. No dependencies are changed and no repository usage analysis is claimed.

## Architecture

Python owns the local CLI and reusable modules. `shared/cited` supplies structural models, strict tuple dispatch and explicit caller-memory sources; five schemas live in `schemas/cited`. [Cited](docs/CITED.md) documents trusted policy injection and its portable closure. `shared/versions` uses one pinned npm semver runtime for arithmetic, manifest/lock provenance and catalog-bound release windows; [versions](docs/versions.md) documents limits and unavailable-runtime failures. Default registry remains empty. Provider, ledger, evaluation and screening implementations await verified owner sources.

## Results and cost

Upgrade accuracy, resolver coverage, latency and model cost are not yet measured. No generated model result table exists. Bootstrap commands make no provider calls; this does not establish free runtime or storage.

## Limits

Status and foundation libraries are implemented. No wired manifest-to-checklist workflow, advisory fetcher, semantic model adapter, live test, independent evaluation corpus, viewer or deployment is claimed. See docs/LIMITATIONS.md and BOLT-HANDOFF.md. Tests and CI configuration cover current boundaries, not a finished app. Runtime timeout/malformed/oversize outcomes remain explicit incomplete errors rather than unaffected conclusions.

Coding agents write this product; candidate checks and later independent review determine verified scope. No public-release or provisioning action is implied.
