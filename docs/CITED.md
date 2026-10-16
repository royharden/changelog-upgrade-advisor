# Structural cited module

`src/changelog_advisor/shared/cited` is a reusable Python 3.12/Pydantic v2 module. Its base exports are structural models, an empty registry and an injected resolver protocol; they acquire no sources, fetch no URLs, invoke no models and install no domain adapters. The optional explicit memory-source extension below reads only retained caller buffers. Constructing a valid Pointer alone does not prove that the source/artifact exists, a quote occurs there, an OCR box is measured or a human authorized anything.

The optional memory-source extension resolves caller-supplied immutable text buffers for supplied_text/line and supplied_text/section; the offline app uses this for release notes. The optional saved-fragment extension below resolves supplied saved-text anchor maps. Importing the module or creating Registry still installs nothing. These routes do not install producer-owned filesystem, OCR or code resolvers. The base model closure remains unchanged; concrete source consumers copy the corresponding optional modules and their dependencies.

## Supplied saved-web fragments

`SavedWebSource.from_bytes` in `cited/fragments.py` accepts immutable UTF-8 raw
bytes, caller namespace/source/revision, explicit `identity` or `crlf-to-lf`
newline policy and an explicit tuple of `SectionSpan(fragment_id,start,end)`
anchor windows. It composes the existing MemorySource byte/line/section
validation; it does not parse HTML, discover anchors, fetch a URL, read files or
authenticate a capture. Anchors are exact logical IDs with no decoding or case
normalization. Raw HTML must be converted by its actual producer under a separately
documented projection; this adapter accepts only an explicit retained text view.

The saved-web-fragments/1 artifact preimage is sorted compact UTF-8 JSON, without
a trailing newline: `{algorithm:"saved-web-fragments/1",text_artifact_sha256:<memory artifact>}`.
The nested supplied-text-memory/1 artifact binds the original hash, revision,
namespace, canonical text, line map and every named window. Changing an anchor
map changes saved artifact identity even when the original bytes are equal.
`SavedWebSource.metadata` has source_type=saved_web; it cannot substitute the
underlying supplied_text artifact. Retained metadata is recomputed before use.

`SavedFragmentResolver(sources,access=...,generation=...)` uses the existing
AccessPolicy/GenerationPolicy protocols and MemoryBounds ceilings. It checks
policy references, literal allow, current source identity and retained bytes;
access/current generation and retained integrity are checked again before
disclosure. Only the named anchor window can resolve the literal quote. A quote
in another anchor, wrong case/Unicode/newline, missing snapshot/anchor, stale
generation, altered map, revoked/unknown policy or spatial/historical request
cannot become resolved evidence. No quote returns the actual complete window
within the existing result bound; oversized windows refuse instead of truncating.
Literal resolution remains distinct from source authenticity or semantic truth.

Install only with `install_saved_fragments(registry,resolver)`, which owns exactly
url#fragment/saved_web/fragment and preserves an existing owner on duplicate
registration. The optional detached closure is the base models/registry/
rowcanonical plus memory.py, assessment.py and fragments.py, with Pydantic and
the product MIT license. Tests relocate that exact closure and exercise actual
resolution plus required-evidence downgrade with network, subprocess/Node,
owner-app imports and key lookup denied. Consumers still need exact source
commit/hash/license publication and their own joined check; this capability is
not automatically wired into the CLI or an external consumer.

## Portable assessed-finding Markdown

`cited/markdown.py` exports `render_assessment(assessment,max_output_bytes=...)`
and the shared `escape_markdown` helper used by the application checklist. Obtain
the EvidenceAssessment with `assess_required_evidence(finding,registry,context)`
using the caller's actual source/policy resolver before rendering. The renderer
performs no source access, policy lookup, resolution, network, model or file I/O.
It cannot authenticate a supplied assessment's execution or certify semantic truth.

It validates Finding/Resolution wire shape, ordered one-result-per-required-pointer
cardinality and the available source/revision/artifact/literal-excerpt bindings.
It recomputes counts instead of trusting supplied summaries. Empty or unresolved
evidence displays unsupported; a previously unsupported finding is never promoted.
Every pointer remains visible with its source hashes/revision, locator, reported
resolution/reason/scope, optional provenance and literal resolved or explicitly
unresolved quoted claim. Optional method/policy/model/probability/confidence fields
are labelled reported metadata, not calibration or live-execution proof.
The declared pointer excerpt SHA256 is retained separately from the reported
result excerpt SHA256, including when resolution is unavailable and has no digest.

Output is escaped literal Markdown without generated links or active HTML. The
default and maximum complete-output bound is 1 MiB of UTF-8; callers may reduce
it. Invalid/misbound assessments or output beyond the bound raise ValueError;
the renderer never returns a truncated checklist that hides required evidence.
The renderer-only detached closure is `__init__.py,models.py,rowcanonical.py,
registry.py,assessment.py,markdown.py`, plus compatible Pydantic and MIT notices.
The actual detached source test additionally copies memory.py, obtains a real
supplied-memory assessment, then renders resolved and uninstalled-domain cases
under `-I -B` with source reads, Node/subprocess, network and key lookup denied.

## Explicit memory sources

Use `MemorySource.from_bytes` with namespace_id,source_id,source_revision, immutable raw bytes, explicit identity or crlf-to-lf policy, and optional trusted `SectionSpan(section_id,line_start,line_end)` tuples. Sections are declared before hashing, not parsed from source headings. Invalid UTF8, mutable input, overflow, duplicate section IDs and out-of-source spans refuse the complete source. No file/URL/archive loader exists. Defaults are256KiB/source,5000lines,500sections,128retained snapshots,8MiB raw total; callers may tighten within these ceilings. Resolver limits apply to each retained source as well as the collection. Bodies/corpus are never silently truncated.

Physical lines split only LF bytes, include their actual endings and never add a phantom line after final LF. Empty source has zero lines. Declared CRLF-to-LF converts only that byte pair; lone CR, Unicode separators, case and whitespace stay unchanged. The source stores actual raw/canonical hashes and exact physical-to-canonical byte intervals. An identity view cannot accept normalized quotes or another profile's artifact digest.

The nonrecursive supplied-text-memory/1 artifact preimage is sorted-key compact UTF8 JSON (ensure_ascii=false,no BOM/trailing LF) of {algorithm,namespace_id,source_id,source_revision,source_sha256,canonical_text_sha256,newline_policy,lines,sections}. Each line has source_line/canonical_line/source_byte_start/source_byte_end/canonical_byte_start/canonical_byte_end. Sections contain section_id/line_start/line_end and sort by exact ID UTF8 bytes. Raw source revision is a caller's trusted raw-generation token preserved verbatim; actual original byte hash is independently bound. Section/profile/view changes alter artifact identity even with equal raw bytes. Raw/current/artifact metadata is recomputed from retained bytes at resolution; changed buffers cannot retarget an old pointer.

`MemoryTextResolver(sources,access=...,generation=...)` requires explicit trusted AccessPolicy and GenerationPolicy objects with immutable logical ArtifactRef identities matching ResolutionContext. Access.decision(namespace_id,source_id) must return literal allow; deny, unknown, exceptions or wrong references refuse before the resolver inspects source text. Generation.current returns the trusted current SourceArtifact or null; unknown/stale/foreign identities refuse. Both checks repeat before disclosure, without caching an earlier allow. Application authentication, actual user identity and policy maintenance remain the caller's responsibilities; test policy labels are not human authentication evidence. Retained lookup is exact namespace+source+revision; same raw bytes in another namespace do not authorize access.

Call `install_supplied_text(registry,resolver)` during single-writer setup to install the two exact supplied routes. A conflict on either route preserves both existing owners and adds neither; no kind-only fallback or foreign-domain install occurs. Other producer adapters remain separately owned. A line pointer must fit actual physical lines, a section pointer its declared hashed window. A supplied quote must match literally within that window and its exact UTF8 digest; the returned text comes from actual retained bytes. Missing quote returns the actual complete selected window within the existing32768-character result bound, never a guessed snippet. Text-only sources refuse spatial-required scopes. Resolving even malicious-looking text executes no instructions and makes no semantic/approval claim.

`assess_required_evidence(finding,registry,context)` treats every Finding/1 evidence pointer as mandatory. Its frozen EvidenceAssessment preserves the original evidence/probability/confidence/method, ordered diagnoses, required/resolved/unresolved/status/reason counts. Any failed or absent evidence downgrades to unsupported; successful quotes cannot upgrade an unsupported semantic claim or turn partial into verified. This is evidence accounting, not a classifier, provider, semantic support validator, renderer or dependency pipeline.

The actual detached memory-source test copies all six cited files into a different consumer namespace, removes the owner root/src paths, uses caller-created raw UTF8/CRLF buffers and trusted policy doubles, then resolves real line/section evidence and preserves a partial Finding. Node, app/provider imports, external source readers, key lookup, network and process execution are guarded. Model-only detached checks remain distinct. No filesystem/HTTP/geometry/CSV/codeindex/advisory adapter or full application acceptance is supplied by these tests.

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
