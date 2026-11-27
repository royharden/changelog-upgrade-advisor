# Changelog Upgrade Advisor

Build a local npm dependency upgrade checklist from a supplied manifest, release notes, and advisory snapshots. The advisor preserves source quotes and uncertainty in JSON, Markdown, and standalone HTML reports; it does not upgrade dependencies automatically.

## Try the offline demo

Use Python 3.12, uv, Node 22 or later, and npm from a source checkout:

```sh
npm ci --ignore-scripts
uv sync --frozen
uv run advisor status
uv run advisor demo --out out/normal
uv run advisor demo --refusal --out out/refusal
```

Each output directory must be new. Open `out/normal/checklist.html` or inspect the JSON and Markdown files. The synthetic normal example covers five dependencies and two advisory records without provider calls. The refusal example leaves inputs unresolved and exits 3 to signal partial analysis.

For supplied inputs, use `uv run advisor analyze --bundle path/to/bundle.json --out out/custom`. The included `src/changelog_advisor/demo_data/normal.json` demonstrates the `s5-supplied-bundle/1` format. The application does not follow supplied URLs or run package hooks.

## What it reports

The checklist describes version gaps, releases crossed, quoted source evidence, advisory range membership, and missing or ambiguous coverage. Range membership does not establish vulnerable usage, and semantic findings remain partial even when a quotation resolves. The keyword baseline needs human review; typed and generative judgments are unavailable in the offline workflow. Live advisory acquisition and model evaluation remain future work. See [limitations](docs/LIMITATIONS.md), [advisory behavior](docs/advisories.md), and [judges](docs/judges.md).

## Development

```sh
uv run ruff check .
uv run ruff format --check .
uv run pytest tests vendor
```

The project uses npm semver for version arithmetic and includes separately licensed vendored components; see [third-party notices](docs/THIRD-PARTY.md) and the relevant `vendor/` license files. The project is available under the [MIT license](LICENSE).
