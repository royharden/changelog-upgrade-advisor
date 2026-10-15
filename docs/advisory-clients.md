# Cached advisory client contracts

Registry metadata, OSV query/get and GHSA global list/get are separate request paths.
URLs use fixed HTTPS hosts and validated identities; notes, lockfile URLs and model text
cannot provide an endpoint. OSV pages use next_page_token/page_token; GHSA next links are
validated against the exact package/version query and converted into a new fixed-host
cursor request. Raw server URLs are never followed. Five pages/source and1000 records
are local caps; cycles/missing pages/errors/caps keep the query incomplete and visible.

Offline mode never calls transport. Missing pages are not_fetched, errors stay errors;
a complete successful empty query can be empty. Cached records carry exact request keys,
HTTP-page SHA, retrieval timestamp and source origin. Parsed array records have a separate
canonical JSON hash; it is not mislabeled an exact HTTP-record byte slice. Unknown/stale/
future freshness is explicit and not a current database claim. New response bytes require
an explicit new cache snapshot, never silent last-write replacement. Supplied cache
archives are bounded64MiB, closed/digest-bound; serialization fails as a whole above cap.
This module does no implicit filesystem read/write or recency selection.

Injected mode implements the same client paths using a supplied transport. A guarded
resolver/dialer contract rejects any nonpublic DNS answer, requires a pinned public peer
and original URL, denies redirects, and passes a ten-second/per-run deadline plus byte cap.
Budget<=120 attempts including at most one HTTP retry,256MiB,120seconds, response32MiB
registry/2MiB advisory. Retry-After other than absent/0 is not slept through. Errors retain
closed identity and never retain arbitrary exception/server-error text as successful data.

The installed default transport DENIES network. No live DNS/socket/HTTP/TLS backend is
implemented or verified in this slice; injected peer metadata cannot prove real TLS or
SSRF safety. An actual separately granted backend must enforce deadline including DNS,
hostname-verified TLS to the pinned peer, streaming limits and no redirects before live
readiness. No SDK/key/service request or model cost ledger is involved in these tests.
This gap remains required work, not an MVP waiver. Application CLI/report integration,
independent Gold and usage/model quality are still pending.

Primary references: [OSV query](https://google.github.io/osv.dev/post-v1-query/),
[OSV get](https://google.github.io/osv.dev/get-v1-vulns/) and
[GHSA REST](https://docs.github.com/en/rest/security-advisories/global-advisories),
read2026-10-15UTC. All executable client fixtures in this slice are synthetic.
