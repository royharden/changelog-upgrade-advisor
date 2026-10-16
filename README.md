# Changelog Upgrade Advisor

Build a local dependency upgrade checklist from a supplied npm manifest,
release notes and advisory snapshots. JSON, Markdown and standalone HTML retain
exact source quotes, visible uncertainty and entries dismissed by the keyword
baseline. Dependencies are never upgraded automatically.

## Quickstart

Use Python 3.12, uv, Node 22+ and npm from a source checkout:

```sh
uv sync --frozen
npm ci --ignore-scripts
uv run advisor status
uv run advisor demo --out out/normal
uv run advisor demo --refusal --out out/refusal
```

Each output directory must be new. Open `out/normal/checklist.html`, or inspect
`checklist.json` and `checklist.md`. The normal synthetic demo uses five
dependencies and two advisory records. It produces a review checklist with zero
provider calls. The refusal demo deliberately leaves pins and sources unresolved;
it preserves the advisory denominator and returns **exit 3** for partial analysis.
These are reproducible workflow examples, not a quality benchmark.

For your own saved inputs:

```sh
uv run advisor analyze --bundle fixtures/demo-seeded/normal.json --out out/custom
cat fixtures/demo-seeded/normal.json | uv run advisor analyze --bundle - --out out/stdin
```

The bundle edition is `s5-supplied-bundle/1`. It retains original manifest, lock
and registry JSON as strings, plus literal notes and optional usage snippets.
Inspect the example for its schema. Input files/stdin are capped at 64 MiB;
component limits also apply. No supplied URL, source command or package hook is
followed. Invalid input/runtime or an existing output directory returns exit 2.

## What the checklist shows

- Installed-pin provenance, the npm-validated version gap and releases crossed.
- Potential changes with literal quotes, source hashes and canonical line ranges.
- Missing, ambiguous, unclassified and capped source coverage.
- Separate OSV/GHSA membership, target membership and conditional usage states.
- Unknown advisories and unresolved evidence; failed quotes downgrade findings.
- Collapsed nonbreaking entries in HTML, plus complete evidence and coverage.

Membership in a vulnerable range does not establish vulnerable usage. In-range
usage requiring interpretation stays unknown. Semantic findings remain partial
even when their quotes resolve. There is no repository-wide reachability claim.

## Implementation and verification

`shared/versions` supplies pinned npm semver IPC, manifest/lock parsing, release
windows, note segmentation and separate advisory normalizers/client protocols.
`shared/cited` supplies structural evidence models and explicit resolver policies.
`judges` connects the plain keyword baseline and typed/generative request shapes.
`pipeline`, `cli` and `report` join these into the offline application.

The optional `shared/cited/fragments.py` export resolves explicit saved-text
anchor maps with caller-owned access/current-generation policies. It performs
no URL acquisition or HTML extraction. See [the cited contract](docs/CITED.md).

The app's retained advisory citation adapter is reusable as
`shared/versions/evidence.py`. It validates canonical raw/derived OSV and GHSA
records with explicit access/current-source policies. Citation fidelity remains
separate from membership and conditional usage; see [the advisory contract](docs/advisories.md).

`shared/cited/markdown.py` renders generic assessed Findings with all required
pointers, counts and reported resolution states. It shares the checklist's literal
escaping helper and refuses incomplete/misbound or oversized output; it does not
perform source verification or promote semantic claims.

The local source closure has a detached normal/refusal CLI control with its own
pinned npm dependency. It does not import the original checkout or live SDKs.
Published wheels and a hosted analysis service have not been qualified.

```sh
uv run --frozen --offline ruff check .
uv run --frozen --offline ruff format --check .
uv run --frozen --offline pytest tests vendor --junitxml=junit-local.xml
uv run --frozen --offline python scripts/check_secrets.py --tracked
```

The combined gate includes actual vendored consumer controls. Workflow checks
exercise malformed input, broken citations, unknown snapshots, bounded stdin,
HTML escaping, output-overwrite refusal and detached source portability. Earlier
Node timeout and pytest collection failures are historical failures; the later
corrected combined run supplies separate evidence. CI execution after a push is
unverified because this candidate has not been pushed.

Coding agents wrote this implementation. Synthetic controls establish local
behavior; independent finished-app review and product acceptance remain pending.

## Model results and cost

| Method | Current application behavior | Semantic quality |
|---|---|---|
| Keyword | Actual deterministic baseline; potential changes require review | Unmeasured |
| Typed/Jev | Unavailable offline; no substituted answers | Unmeasured |
| Generative | Unavailable offline; no substituted answers | Unmeasured |

Offline reports record zero model API calls. No live cost, model comparison,
calibration or heldout result is claimed. The baseline intentionally includes a
keyword false positive and misses a change without keywords.

## Remaining work

Live provider/SDK qualification, genuine bounded model tests, conditional usage
judging, controlled evaluation and method selection remain outstanding. Actual
bounded HTTP acquisition, remaining portable source-domain resolver exports and
licensed real examples also remain incomplete. A static report and passing local
controls do not close these requirements.

See [limitations](docs/LIMITATIONS.md), [judgment behavior](docs/judges.md),
[lessons](LESSONS.md) and [the Bolt handoff](BOLT-HANDOFF.md).
