# Structural cited module

`src/changelog_advisor/shared/cited` is a reusable Python 3.12/Pydantic v2 module. It exports structural models, an empty registry and an injected resolver protocol. It reads no sources, fetches no URLs, invokes no models and installs no concrete domain adapters. Constructing a valid Pointer does not prove that the source/artifact exists, a quote occurs there, an OCR box is measured or a human authorized anything.

`Finding` keeps the generic schema_version/id/text/verdict/probability/confidence/evidence/method shape. Its semantic verdict is only partial or unsupported; probability 1 and a syntactically matching literal quote cannot produce verified. Domain category, breakingness, usage and benchmark results belong in separate application wrappers. The caller must retain unresolved required evidence and downgrade it; this module contains no findings pipeline. Model IDs are supplied metadata, not generated stable-ID or approval proofs.

## Wire and dispatch

Pointer/1 is a closed full-triple union. It preserves source_id, original raw source_sha256/source_revision, separate evidence_artifact_sha256 and nullable logical provenance_ref. Hashes are canonical lowercase64 SHA256 strings, without normalization. IDs are bounded opaque strings preserved verbatim; absolute/traversal/backslash/drive paths, fetch URLs and control characters are rejected as logical references. These references never authorize an opener. SourceArtifact describes original byte length, optional explicit canonical-LF digest/newline policy and ordered line map; it does not acquire, hash or normalize raw files.

| Exact triple | Model scope at this checkpoint |
|---|---|
| file:line / supplied_text / line | bounded line and optional literal quote metadata |
| file:line / configured_log / line | redacted-result metadata, separate physical and artifact byte intervals |
| file:line / repository_file / line | immutable captured snapshot/direct-original-file binding |
| doc:section / supplied_text / section | named section and optional literal quote metadata |
| doc:section / code_existence_report / report_item | immutable current snapshot/item/query/coverage binding |
| doc:page:bbox / document_page / region | source-pixel/zero-index document metadata |
| doc:page:bbox / screenshot_collection / source_region | same region structure; collection access remains domain-owned |
| row:id / product_catalog / record_field | dataset+opaque record/raw field identity |
| row:id / event_table / row | declaration only: locator=null pending owner schema |
| row:id / metric_table / metric | declaration only: locator=null pending owner schema |
| url#fragment / saved_web / fragment | named retained fragment, no HTTP implementation |
| advisory:id / advisory_record / id | named retained advisory, no fetching/membership implementation |

Every route resolves unsupported in a new Registry. Register only an exact declared triple and an explicit Resolver.resolve(pointer,context) object; duplicate registration raises DuplicateResolverError without replacing the owner. No kind-only fallback or unregister/override exists. Pending null-locator declarations cannot resolve even if registered. Unknown input tags/version are unsupported at dispatch; malformed known wire is invalid before any resolver call. Direct model parsing rejects unknown wire fields/tags/version. Legacy spellings are not implicitly converted: a future named adapter must define and test an exact map.

ResolutionContext contains caller namespace and logical access/generation policy references plus optional requested text/spatial/text_and_spatial scope. A registered domain resolver is responsible for actual immutable source/artifact/access/lifetime/coverage checks; the generic registry checks returned bindings, scope and structural result. Exceptions produce a fixed sanitized error code, never raw domain/provider messages. Declared context alone grants no actual access.

## Evidence distinctions

Optional quote and literal UTF8 excerpt digest must be both present or both null; exact case, Unicode and line endings are preserved. Empty missing bodies do not become fabricated quotes. Hash consistency is structural fidelity only. Log input is redacted_result with neutral source IDs and source_revision=sha256:<original raw digest>; index epochs/redactor config cannot replace raw revision. Successful domain output must explicitly retain redacted_text owner scope and redacted_result provenance, mapped to generic text without claiming raw-source availability. Scanned coverage and output truncation remain independent metadata.

Product fields are the adopted id/name/brand/size/unit/price/category/description raw schema. Product source_revision=rg1:<raw-record digest>. The raw fingerprint's producer profile is product-raw-fields-v1 over every exact decoded raw string, including blanks; this module receives that fingerprint without acquiring/recomputing records. A substantive field Pointer requires a nonempty whole raw quote and exact UTF8 excerpt digest. Its declared artifact digest must match sorted compact UTF8 JSON (ensure_ascii=false, no BOM/newline) of {algorithm:product-record-field-evidence-v1,dataset_id,record_id,source_sha256,source_revision,field_id,raw_value}. This cross-field check proves declared serialization consistency only, not that the producer's record/quote exists or is permitted. Blank raw cells remain legitimate producer data but yield no substantive field Pointer; normalized/partial quotes require a future named profile. Origin row/file metadata cannot replace stable dataset+record identity or raw generation.

Source boxes are BoxPx{units:px,x0,y0,x1,y1}, finite with positive area and source bounds. Region page_index is zero-based; units/origin are px/top-left. Nonempty unique line IDs without boxes are accepted as text-capable metadata, not measured geometry. Box-only can have null excerpt. Original upload hash, retained rgba8-source-grid-v1 digest/profile and derived evidence hash are distinct. These models do not decode/EXIF-map pixels, invert transforms, verify membership/enclosure/reading order/excerpt occurrence, measure OCR or check deleted collections. Those require actual owner artifacts/resolvers.

Resolution spatial/text_and_spatial requires explicit native or measured_ocr provenance; model_claimed stays asserted_spatial. Null OCR confidence stays null. Bounds validation cannot promote asserted to measured, and a requested spatial scope cannot accept text/asserted output. Safe provenance contains typed IDs/enums/digests/counts/nulls, no arbitrary log dump. Serialized producer testimony is not itself proof that measurements occurred.

Repository profiles support explicitly captured SHA1 git_commit identities and labelled fixture_inventory raw64 identities. Fixture ID must equal raw inventory digest and cannot masquerade as an actual Git commit. Syntax alone cannot prove capture/reachability. Direct repository artifact digest equals the original file digest; raw revision excludes parser/config generation. Report input binds raw inventory/current snapshot, separate immutable report artifact and unique item/reference/query/coverage IDs. A report is not recursively embedded here; there is no report loader/parser. These structures cannot prove absence, uniqueness, lineage or external repository existence. Empty/binary retained files receive no invented line1. Actual raw/report serialization, query/coverage joins and current/historical semantics belong to the owner adapter.

## Portable model closure and limits

Copy the SAME `cited/{__init__.py,models.py,registry.py,schema.py}` under a consumer's package with its own namespace initializer, these docs, generated schemas and this repository's MIT license/notice. Imports are relative plus stdlib/Pydantic; the consumer must pin a compatible Pydantic dependency and preserve its notices/dependency closure. No owner app, workspace, Node, provider, ledger, OCR or image package is required. This is only the generic model/protocol export, not a complete resolver or full runtime export. Later vendoring must record actual source commit/file hashes/license and execute the consumer's compatibility checks. No source commit is invented in these docs.

Logical IDs<=256 characters, raw revision<=512, text<=32768, hashes64, IDs/line maps<=10000, findings<=128 pointers; integers<=2^53-1, finite probabilities[0,1]. Repository paths additionally<=4096UTF8 bytes. Quotes/IDs and frozen tuple arrays have no implicit normalization. Producers/callers must apply tighter domain payload/deadline/corpus bounds; these models are not transport envelope, raw-reader or operation-budget controls. Null pending locators and absent confidence are deliberate, not fabricated success.

Regenerate five model schemas from the repo root with:

```sh
uv run python -m changelog_advisor.shared.cited.schema --out schemas/cited
uv run pytest tests/cited
```

Generated schema byte parity is tested. JSON Schema expresses closed types/bounds, but cross-field digest/identity/scope validators additionally require Python model validation. A schema-shaped JSON object alone is not full conformance. Model tests use synthetic placeholders and protocol spies, never live/captured source truth or paid benchmark evidence. The detached test relocates the module, removes the owner's root/src import paths while retaining pinned installed dependencies, preloads Pydantic's own schema/plugin metadata, then blocks application Path source reads/network/process/key lookup and checks empty dispatch; Pydantic's own PYDANTIC_DISABLE_PLUGINS configuration lookup remains a declared dependency behavior. Interpreter code/dependency loading is not a claim of zero filesystem activity by Python itself.
