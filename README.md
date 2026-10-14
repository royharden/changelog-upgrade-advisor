# Changelog Upgrade Advisor

A local tool for dependency upgrade checklists with exact quoted evidence and explicit uncertainty. The current checkpoint contains an offline status scaffold and reusable structural citation models; dependency analysis and actual evidence resolution remain pending.

## Quickstart

Install Python 3.12, uv and Node 22 or newer, then run from the repository root:

```sh
uv sync --frozen
npm ci --ignore-scripts
uv run advisor status
uv run python scripts/demo.py --mode offline
```

The status command reports structural-model scope, offline mode, zero installed domain resolvers and pending analysis. It requires no keys and does not inspect a manifest or generate findings. The required five-dependency/two-advisory demonstration is pending.

## Intended workflow

Supply package.json, an optional package-lock, targets and per-package release notes, with optional usage snippets. The planned output is JSON, Markdown and a self-contained HTML checklist containing deterministic version facts, potential breaking changes, resolvable quotes, advisories and visible unknown/error coverage. No dependencies are changed and no repository usage analysis is claimed.

## Architecture

Python owns the local CLI and reusable modules. `shared/cited` now supplies Pydantic structural Source/Finding/Pointer models, strict full-triple registry and resolver protocols. Five generated schemas live in `schemas/cited`; see [the cited module](docs/CITED.md) for its bounds and portable copy closure. No concrete domain adapter is installed. One pinned npm semver runtime will supply npm ordering/range semantics. Provider, ledger, evaluation and screening implementations remain pending verified owner sources.

## Results and cost

Upgrade accuracy, resolver coverage, latency and model cost are not yet measured. No generated model result table exists. Bootstrap commands make no provider calls; this does not establish free runtime or storage.

## Limits

Only status and generic structural citation models/protocols are implemented. No manifest analysis, advisory fetcher, checklist renderer, concrete evidence resolver, model adapter, live test, evaluation corpus, installed viewer or deployment is claimed. See docs/LIMITATIONS.md and BOLT-HANDOFF.md. Tests and CI configuration cover this current boundary, not a finished app.

Coding agents write this product; candidate checks and later independent review determine verified scope. No public-release or provisioning action is implied.
