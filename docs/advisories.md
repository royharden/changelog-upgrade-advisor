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
