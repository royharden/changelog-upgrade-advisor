# S3 native SDK source provenance

This consumer uses a composite source edition from llm-router-eval:

- Base: `dfab37dcf32ecc85aceaf828be1332ba711712a8`, tree
  `f3ea153d34f799e065e9a3f1d64c2ade38d989c0`.
- Response-cap supplement: only `providers/controller.py` and `providers/sdk.py`
  from `ff6eb72bc8c84209e40dc1987d4e34fb94f15bb4`, tree
  `98d843a10eec9bb33ec741bf2e7ec38e2bf3582f`.
- Lazy-export supplement: only `providers/__init__.py` from
  `b9d3e47f62749a57c1f850f7713db66d29cb684c`, tree
  `cceaafb0b4c815fac02d47aaddafc866cf8d9deb`.

All three supplemented runtime files are unchanged upstream Git bytes. The other
17 mapped assets remain pinned to the base edition. Relative imports and canonical
public object identity are preserved. The initializer defers loading controller,
accounting models and optional SDK transport modules until their exports are
requested; importing the SDK worker submodule can retain its standard-library-only
startup graph.

The three retained vendor test files replace the literal `llm_router_eval`
namespace with `changelog_advisor`; their assertions and fixture profiles are
unchanged. This is not a full 20-file adoption of either supplement commit, and
the producer's new regression edition is not substituted for the retained tests.

`vendor/s3-sdk/RESPONSE-CAP-PROVENANCE.json` records all 20 product-relative paths,
selected upstream commits, raw and consumer hashes, and namespace transformations.
S5 adds ten cap cases in `tests/consumer_contracts/s3_sdk/test_s5_response_cap.py`
and three fresh import/export controls in `test_s5_lazy_exports.py`. The latter
check the bare package and SDK-worker module graphs, and all 13 public exports'
canonical identity. Import-graph controls are distinct from actual mock-wire SDK
dispatch/accounting cases in `test_s5_native_join.py`.

The cap supplement rejects unsupported SDK response limits before funding or
dispatch. Only integer limits from 1 through 65536 are supported. Existing
reservation and unknown-usage settlement behavior remain intact. Missing an
unpriced counter alone need not make known cost unknown. The callledger, wire
models, SDK dependencies and lockfiles are unchanged. SDK pins remain openai
3.31.0 (Apache-2.0) and typesafe-sdk 0.7.5 (MIT). Preserve the upstream MIT notice at
`vendor/s3-sdk/LICENSE`. Original offline `vendor/s3` conformance assets remain.

These source and synthetic controls do not establish historical failure cause,
cold-start performance, stability, deadline adequacy, a live account, primary
prices, funding, paid calls, model quality, POSIX runtime, remote CI, an installed
release, Bolt execution or whole-application acceptance. SDK mock wire uses
synthetic simulation inputs and does not read ambient credentials. Any local
installed-candidate validation remains scoped to its exact recorded edition.
