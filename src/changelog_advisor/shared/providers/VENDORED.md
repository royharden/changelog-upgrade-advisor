# S3 native SDK source provenance

This consumer uses a composite source edition from llm-router-eval:

- Base: `dfab37dcf32ecc85aceaf828be1332ba711712a8`, tree
  `f3ea153d34f799e065e9a3f1d64c2ade38d989c0`.
- Response-cap supplement: only `providers/controller.py` and `providers/sdk.py`
  from `ff6eb72bc8c84209e40dc1987d4e34fb94f15bb4`, tree
  `98d843a10eec9bb33ec741bf2e7ec38e2bf3582f`.

The two supplemented runtime files are unchanged upstream Git bytes. The other
18 mapped assets remain pinned to the base edition. Runtime relative imports and
type identity are preserved. The three retained vendor test files replace the
literal `llm_router_eval` namespace with `changelog_advisor`; their assertions and
20-second fixture profile are unchanged. This is not a full 20-file adoption of
the supplement commit or its five new upstream cap tests.

`vendor/s3-sdk/RESPONSE-CAP-PROVENANCE.json` records all 20 product-relative paths,
selected upstream commits, raw and consumer hashes, and namespace transformations.
S5 adds ten consumer cap cases in
`tests/consumer_contracts/s3_sdk/test_s5_response_cap.py`. They cover both SDK
flavors, refusal at preparation/admission/run, and valid boundary caps. Their
test bodies and parameterization retain the diagnostic regression; import grouping
and layout follow the project's formatter.

The supplement rejects unsupported SDK response limits before funding or dispatch.
Only integer limits from 1 through 65536 are supported. Existing reservation and
unknown-usage settlement behavior remain intact. Missing an unpriced counter alone
need not make known cost unknown. The callledger, wire models, SDK dependencies
and lockfiles are unchanged. SDK pins remain openai 3.31.0 (Apache-2.0) and
typesafe-sdk 0.7.5 (MIT). Preserve the upstream MIT notice at
`vendor/s3-sdk/LICENSE`. Original offline `vendor/s3` conformance assets are retained.

These source and mock-wire controls do not establish a live account, primary
prices, funding, paid calls, model quality, POSIX runtime, remote CI, an installed
successor wheel, Bolt execution or whole-application acceptance. SDK mock wire
uses synthetic simulation inputs and does not read ambient credentials.
