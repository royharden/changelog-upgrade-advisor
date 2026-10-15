# Bounded local npm runtime

`NodeSemver` is an explicit context manager. Importing or constructing it starts
no process. Its first operation starts a fixed native Node executable and bundled
helper; subsequent operations reuse that owned stdio process. Close it after use:

```python
with NodeSemver() as versions:
    ordering = versions.compare_pairs([("1.9.0", "1.10.0")])
```

Every operation has one five-second deadline covering lock acquisition, validation,
lazy startup, partial writes, response reads and result validation. Requests and
responses retain protocol version1 and a2MiB limit; stderr has an8KiB lifetime cap.
The runtime checks the helper and actual pinned semver7.8.5 JavaScript files against
the context's first-operation fingerprint before each operation. Node's environment
contains only the fixed public process variables; caller data never supplies code,
module loaders, executable paths or environment overrides.

The helper accepts LF-framed requests and the original single object followed by
EOF. One lock serializes requests. Extra frames, malformed JSON, wrong request IDs,
unknown fields, oversized output and premature EOF fail the operation. There is no
retry or version-math fallback. Range semantics and the pinned npm authority stay
unchanged.

An owned process has a120-second lifetime timer and at most1000 requests. A later
explicit operation can create a fresh owned process after confirmed retirement.
Failures kill and wait only for the actual owned process, with bounded cleanup.
Uncertain startup or termination remains explicit and blocks reuse. `close()` is
idempotent after successful cleanup. All existing test callers now close their
contexts; embedded detached examples also close before exiting.

Focused lifecycle controls are implementation checks. They do not establish full
suite acceptance, advisory correctness, independent fixture quality or app readiness.
The prior full-suite timeout failure remains recorded until a separately allocated
broader test run completes against a pinned candidate.
