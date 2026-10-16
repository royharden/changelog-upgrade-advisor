# Bolt infrastructure handoff

The implemented target is a local Python/Node CLI and standalone static report.
Database: **none**. Bolt action: **inspect and prepare only**. No publication or
infrastructure provisioning has occurred. The offline normal/refusal workflow
runs locally; live integrations and independent finished-app acceptance are pending.

| Component | Actual inventory |
|---|---|
| Source root | This repository root; `main`, current local candidate |
| Analysis | Python 3.12; `uv sync --frozen` |
| Version authority | Node 22+; `npm ci --ignore-scripts`; semver 7.8.5 |
| Commands | `advisor status`, `advisor analyze`, `advisor demo` |
| Static output | `checklist.html`, `checklist.json`, `checklist.md` |
| Input | Explicit bounded file/stdin bundle; saved snapshots only |
| Hosted frontend | No React/Vite viewer implemented |
| Database / migrations / auth / storage / functions / Realtime | Not required |
| SDKs / API keys | Optional pinned SDK mock/accounting join; funded live path unqualified; offline workflow needs no keys |
| Services / Docker / listeners | None required |
| Hosting / publication | Unprovisioned and unverified |

Reproduce from a source checkout:

```sh
uv sync --frozen
npm ci --ignore-scripts
uv run advisor demo --out out/normal
uv run advisor demo --refusal --out out/refusal
uv run --frozen --offline ruff check .
uv run --frozen --offline ruff format --check .
uv run --frozen --offline pytest tests vendor --junitxml=junit-local.xml
```

The normal CLI generates all three reports; the refusal CLI returns exit 3 and
retains unknown advisories and incomplete coverage. Output directories must be
new. Local controls cover malformed input, literal quote downgrade, escaping,
overwrite refusal and an actual detached normal/refusal source closure.
The wheel build requires `npm ci --ignore-scripts` followed by `uv build --wheel`;
it bundles the two synthetic demo resources and locked semver 7.8.5 with its ISC
license. An installed wheel still needs Python 3.12, Pydantic and native Node 22+.
Local Windows checks built and installed the wheel into a fresh Python environment,
then ran both the installed module and generated `advisor` executable away from
the checkout: normal exit 0, refusal exit 3, zero provider calls. Overwrite and
malformed-input checks refused with exit 2. The Linux CI wheel step is added;
its hosted execution has not been verified.
CI execution and live-model quality remain unverified.

The optional SDK extra adopts exact canonical S3 provider/Ledger source and adds a
programmatic simulation-only S5 judgment join. Windows SDK mock-wire controls use
real ledger reservations and owned worker closure; they do not provision a service,
read ambient keys or qualify a funded live call. Current unknown-usage completion
failure is closed with its conservative hold retained; the canonical producer
repair remains separate. The new SDK source was checked from the consumer source
namespace, not as an installed SDK-enabled wheel or a hosted Linux/Bolt runtime.

Importing this repo into Bolt does not execute or provision Python. A hosted
analysis endpoint or interactive viewer needs separate design and backend
verification. No duplicate TypeScript engine or browser secrets are present.
Remaining product gaps are listed in `docs/LIMITATIONS.md`.

Future inspection prompt:

> Read BOLT-HANDOFF.md and inspect the actual imported source. This is a local
> Python/Node CLI with generated standalone HTML, JSON and Markdown. If a completed
> checklist.html is supplied, prepare a static presentation with no external assets.
> Keep the documented source/runtime boundaries and report any unsupported runtime.
> No database, auth, migrations, functions or provider secrets are required for the
> static report. Record the actual hosting/build verification before publication.
