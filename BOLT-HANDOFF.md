# Changelog Upgrade Advisor — infrastructure inventory

Status: local foundation checkpoint; no hosted workflow ready to import. Current code includes status, cited models/schemas and explicit supplied-memory resolvers, plus npm pin/window functions. No manifest-to-checklist application exists yet. Python 3.12/uv and the pinned Node semver runtime require local execution; Bolt does not provision this local core.

| Resource | Current requirement / evidence |
|---|---|
| Database / migrations | Not required; none implemented |
| Edge functions / auth / storage / Realtime | Not required; none implemented |
| Browser secrets | None |
| Provider calls / server secrets | Not implemented in W0; later local controllers only |
| Hosted viewer | Not implemented; optional future static viewer deferred |
| Docker / listeners | Not required for bootstrap |
| Build/install | uv sync --frozen; npm ci --ignore-scripts |
| Local command | uv run advisor status |
| Offline scaffold | uv run python scripts/demo.py --mode offline |
| Structural models | shared/cited; Pydantic v2 dependency; zero installed concrete resolvers |
| Explicit library adapters | supplied-memory line/section only, trusted policies required; default/app registry still empty |
| Version core | shared/versions; one packaged npm helper and root forwarding entry; no Python comparator |
| Schema export | uv run python -m changelog_advisor.shared.cited.schema --out schemas/cited |
| Verification | ruff + pytest + staged secret guard; actual receipts kept outside the repo |
| Publication / GitHub import | Separate owner grant; no remote/provision/publication action taken |

Future inspection prompt: inspect the implemented inventory and local-runtime boundary before choosing a hosted component. Do not provision databases/functions/auth or claim Python analysis runs in Bolt merely from importing these files. No provisioning recipe is ready at this checkpoint.
