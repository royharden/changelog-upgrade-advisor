# Offline untrusted-text screen integration

The seven runtime files under `shared/screen` are unchanged from S6 source
`8f8bb88ffc4148611dd6180b6f01d264c367cce3`. They use the existing sibling S3
provider and ledger classes. The separately adopted S3 purpose-consistency fix stays
in place; its other13 canonical source files match S6's original bundle.

Rules screen original and normalized text with explicit coverage and source generation.
The optional typed seam creates one original wrapper/native request before external
prepare/admit. Offline native use requires the same six caller objects and zero
outbound allocation. It validates the original source, model, question order, policy,
purpose and allocation before reuse. Cache miss and invalid inputs remain held.

The native source currently supports mock/strict replay. Synthetic captures remain
labelled mock; these controls establish no genuine Jev result or quality calibration.
No SDK, live transport or durable cache is installed by this integration. Before saving
a screened result, the caller must atomically verify the current source generation;
a previous pass does not authorize a later edit or external action.

`vendor/s6/SOURCE-MANIFEST.json` records exact original/adapted views and MIT notice.
Only test namespace, helper-root and detached-closure mappings changed. Run moved
controls explicitly with `pytest vendor/s6/tests/screen tests/consumer_contracts/s6`.
The synthetic S3 Rig comes from the already adopted public conformance source. The
owned boundary fixture blocks owner imports, SDKs, credential reads and network.
