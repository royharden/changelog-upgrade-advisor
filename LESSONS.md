# Lessons learned

- Export cross-field constraints needed by JSON Schema consumers. A schema pass
  can otherwise disagree with an existing runtime validator. Keep runtime checks
  for ordered/unique line-map indices and actual source/content identity.
- Use absolute executable paths for Windows subprocesses. Relative executables
  can resolve against the launcher instead of the intended child cwd.
- Include startup, locking, complete framed IO and validation in deadlines.
  Persistent helpers need bounded frames/stderr, retirement, explicit close and
  actual owned-process cleanup. Keep npm as the version authority after failures.
- Collect original and moved tests together. Default pytest imports can collide
  on basenames even when suites pass separately. Renaming a consumer-owned file
  can fix collection without changing foreign test bodies.
- Preserve raw bytes, declared normalization/projection profiles and separate
  source/artifact hashes. Matching words cannot bypass namespace, access,
  generation or source-type boundaries, and cannot certify semantic claims.
- Retain expected counts for unavailable, held, malformed, capped and unresolved
  inputs. Missing snapshots and successful empty snapshots are distinct states.
- Preserve failed frozen intake. Authorized metadata derivatives need separate
  provenance and original/derived hashes; do not weaken ordinary input validation.
- Synthetic provider success is implementation evidence. Preserve its origin,
  nullable usage and capture cost/latency; zero new spend is no fresh latency or
  live-model observation.
- Separate working-tree checks from committed/full-candidate gates. A focused
  green suite or early demo cannot replace a later complete run.
- Test broken but structurally valid citations through the joined pipeline;
  quote/hash schema rejection alone does not exercise literal source resolution.
- Keep demo commands in CI synchronized with CLI output-directory requirements.
  Test a complete copied source closure, including the npm helper and assets.
- Verify each standalone report format against the same advisory evidence:
  installed/target membership, source identity, quote resolution and missing counts
  must remain visible without opening another artifact.
- Keep saved-text anchor maps in the evidence artifact identity. Equal raw bytes
  do not permit a changed fragment window, namespace or projection to reuse a
  citation. Reuse the canonical text/line machinery rather than parsing it twice.
- Export the same advisory adapter that the application consumes. Re-normalize
  retained raw records before trusting a derived quote, and keep citation fidelity,
  deterministic membership and conditional usage as separate results.
- Portable presentation must preserve unresolved evidence and recompute counts,
  without treating reported resolver results or model confidence as authentication.
  Refuse oversized complete output rather than dropping evidence to fit.
