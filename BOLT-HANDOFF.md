# Changelog Upgrade Advisor — infrastructure inventory

Status: W0 implementation incomplete; no hosted component ready to import. Current code is a local Python status scaffold. Future dependency analysis requires Python 3.12/uv and a pinned Node semver runtime; Bolt does not provision this local core.

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
| Verification | ruff + pytest + staged secret guard; actual receipts kept outside the repo |
| Publication / GitHub import | Separate owner grant; no remote/provision/publication action taken |

Future inspection prompt: inspect the implemented inventory and local-runtime boundary before choosing a hosted component. Do not provision databases/functions/auth or claim Python analysis runs in Bolt merely from importing these files. No provisioning recipe is ready at this checkpoint.
