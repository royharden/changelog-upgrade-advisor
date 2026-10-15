# Supplied changelog spans

The `changelog-spans/1` parser recognizes six documented heading styles: ATX bare,
bracket/date, Release/Version, exact package@version, setext bare and Markdown linked
version headings. It extracts candidate version strings and asks the locked npm helper
to validate/canonicalize them. Links are text and never fetched. Fences cannot introduce
headers; foreign package labels, malformed versions, duplicate canonical releases and
unknown peer headings never silently borrow another release association.

Inputs are strict UTF-8<=256KiB/5000 LF physical lines. Only CRLF-to-LF normalization is
allowed; literal Unicode/lone CR/case/whitespace remain. Oversized input has observed byte
counts and no prefix SourceArtifact. Bullets/paragraphs preserve exact source line windows,
nested/indented continuations and hierarchical heading context. Long entries split only
between physical lines<=8192UTF-8 bytes; unsplittable lines/context overflow are explicit
unknown entries with full bounds and counts. Every parsed span is retained; selection
uses the exact release window and caller's remaining<=500 run budget, without keyword
filtering. Caps/missing/empty/duplicate/unversioned coverage remain incomplete.

IDs hash profile,package,raw source hash,canonical release/section/line/chunk/content;
they remain stable across target selections of the same source. Release association is
parser output, not proof of publisher truth, semantic breakingness or human approval.

The optional `sources.py` bridge imports the existing S5 supplied-memory codec. It declares
selected section IDs/line bounds before hashing the full retained raw source, with explicit
CRLF view and sha256 raw revision. Different selected maps yield different artifact hashes,
not different raw revisions. Section pointers quote exact entry bytes. Explicit trusted
access/current-generation policy and registry installation remain required; no source or
heading grants permission. The same literal evidence stays partial/unsupported semantically.

The parser alone is stdlib+relative npm runtime and does not import the cited package;
the optional bridge adds the six-file cited closure/Pydantic. Importing either starts no
Node/network process. All fixtures currently synthetic implementation controls, separate
from independent Gold. Application judges/pipeline/demo/real samples/live backend/model
quality/final acceptance remain pending.
