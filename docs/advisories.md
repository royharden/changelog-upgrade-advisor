# Supplied advisory ranges

This library accepts bounded immutable UTF-8 JSON buffers (2 MiB per record), explicitly
labelled `synthetic` or `saved_response`. OSV 1.x and GitHub REST global advisories have
separate normalizers. Normalization starts no Node process and performs no I/O. Membership
uses the locked npm semver helper. It does not assess usage, reachability or severity.

OSV matches npm identity exactly, unions explicit versions and supported SEMVER/npm
ECOSYSTEM ranges, sorts event boundaries through npm and applies introduction, exclusive
fixed, inclusive last_affected and union-of-limit rules. `introduced: "0"` is unbounded;
`limit: "*"` is infinite. Unsupported GIT ranges, malformed/tied toggle boundaries or
missing applicable range data are unknown unless another supported alternative proves
membership. Explicit versions use literal version identity, including build suffixes.
An OSV prerelease is compared through SemVer without npm range prerelease filtering.

GHSA REST uses `vulnerable_version_range`; commas become npm AND while `||` remains OR.
The REST `first_patched_version` string/null is preserved as metadata and never overrides
the vulnerable range. Declared `vulnerable_functions` are source metadata, not proof of
use or repository reachability. OSV has no invented universal symbol field. A prerelease
excluded by npm's default range filter remains unknown rather than a safety conclusion.

Each record retains original bytes/hash, source, modification timestamp, origin, aliases
and withdrawal. Membership re-normalizes the buffer to verify the derived binding.
Exact ID/alias connected groups preserve all distinct source revisions; disagreements
or mixed withdrawal are conflict. Wrong identity is not_applicable, withdrawal is visible,
and missing/invalid/runtime-failed evidence is unknown. Pin and target must be evaluated
separately; membership does not imply the chosen upgrade fixes an advisory.

Primary specifications: [OSV schema 1.9.2](https://ossf.github.io/osv-schema/) and
[GitHub global advisory REST API](https://docs.github.com/en/rest/security-advisories/global-advisories),
read 2026-10-15 UTC. This source slice has no HTTP client, cache or actual fetched advisory.
Synthetic unit controls are implementation tests, not independent advisory Gold or a
measured usage classifier. Standalone application analysis remains incomplete.

## Reusable retained-record citation adapter

`versions/evidence.py` is the optional join between canonical advisory records
and `cited`. The application uses this same adapter; no parallel app-only resolver
is maintained. It does not fetch records, run npm, decide membership or judge usage.

Normalize supplied immutable bytes with `normalize_osv` or `normalize_ghsa`, then
call `AdvisorySource.from_record(record,namespace_id=...)`. It re-normalizes the
original raw bytes and compares every derived field; a forged summary, details,
identity, origin or raw hash cannot substitute for the canonical record. Each
source uses id `advisory-<source>-<raw SHA256>` and revision `sha256:<raw SHA256>`.
The unchanged advisory-summary-details/1 projection is sorted compact UTF-8 JSON,
ensure_ascii=false, without trailing newline, of `{profile,source,id,raw_sha256,text}`;
text is the literal normalized summary, one LF, then literal normalized details.
The evidence artifact SHA256 hashes that projection; the source SHA256 hashes
the original bytes. These hashes do not certify advisory authenticity/currentness.

Construct `AdvisoryRecordResolver((source,...),access=...,generation=...)` with the
existing explicit caller-owned AccessPolicy/GenerationPolicy protocols. Limits
are at most 1,000 retained records and 64 MiB total raw bytes, reducible by the
caller; the normalizers independently enforce the 2 MiB record limit. Duplicate
namespace/source/revision entries refuse. Namespace, policy references, literal
allow, current source metadata and retained raw/derived identity must agree.
Access/current generation and retained integrity are rechecked before disclosure.

`install_advisory_records(registry,resolver)` installs exactly
advisory:id/advisory_record/id and preserves an existing owner on duplicate
registration. A pointer must name the primary advisory ID and provide an exact
nonempty quote with its UTF-8 digest. Missing/nonliteral/wrong-record quotes remain
invalid; stale/current-unknown/revoked/foreign-namespace sources cannot resolve.
Only current text scope is supported. A resolving quote cannot establish usage,
severity, a safe upgrade target or semantic truth; required evidence still
downgrades a Finding to unsupported on failure.

The detached citation-only closure is two sibling packages: cited
`__init__.py, models.py, rowcanonical.py, registry.py, memory.py, assessment.py`;
versions `__init__.py, models.py, manifest.py, runtime.py, advisories.py, osv.py,
ghsa.py, evidence.py`. Preserve root MIT/license and dependency notices and a
compatible pinned Pydantic. Citation-only resolution requires neither Node nor
semver.mjs; version membership still requires the complete npm closure described
above. The detached test uses actual `-I -B` Python isolation and denies network,
Node/subprocess execution, source-file reads and key lookup after setup. Its
positive/negative OSV+GHSA evidence counts are synthetic implementation controls.
Consumers must bind exact reviewed source/license/profile and run their own joins.
