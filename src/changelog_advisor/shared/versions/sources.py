"""Optional supplied-memory bridge. Source bytes/spans only, no acquisition/access inference."""

import hashlib

from ..cited.memory import MemorySource, SectionSpan
from ..cited.models import SectionLocator, SectionPointer
from .changelog import ParsedNotes, Span, span_identity


def make_span_source(
    notes: ParsedNotes, spans: tuple[Span, ...], *, namespace_id: str, source_id: str
) -> MemorySource:
    if type(spans) is not tuple or len(spans) > 500:
        raise ValueError("immutable selected span tuple within500 required")
    if (
        hashlib.sha256(notes.raw).hexdigest() != notes.sha256
        or notes.raw.decode("utf8").replace("\r\n", "\n").encode() != notes.canonical
    ):
        raise ValueError("parsed source binding mismatch")
    for span in spans:
        if span not in notes.spans:
            raise ValueError("span outside actual parsed source")
        text = "".join(notes.lines[span.line_start - 1 : span.line_end])
        if text != span.text or span.id != span_identity(
            notes.package,
            notes.sha256,
            span.release,
            span.section_start,
            span.line_start,
            span.line_end,
            span.chunk_index,
            text,
        ):
            raise ValueError("literal span identity mismatch")
    return MemorySource.from_bytes(
        namespace_id=namespace_id,
        source_id=source_id,
        source_revision="sha256:" + notes.sha256,
        raw=notes.raw,
        newline_policy="crlf-to-lf",
        sections=tuple(SectionSpan(s.id, s.line_start, s.line_end) for s in spans),
    )


def span_pointer(source: MemorySource, span: Span) -> SectionPointer:
    source.validate_retained()
    if span.state not in ("ready", "ambiguous_release") or not span.text or span.byte_count > 8192:
        raise ValueError("span unsupported for model/citation entry")
    if not any(
        s.section_id == span.id and (s.line_start, s.line_end) == (span.line_start, span.line_end)
        for s in source.sections
    ):
        raise ValueError("span not declared in retained source section map")
    text = source.canonical[
        source.lines[span.line_start - 1].canonical_byte_start : source.lines[
            span.line_end - 1
        ].canonical_byte_end
    ].decode("utf8")
    if text != span.text:
        raise ValueError("span literal text mismatch")
    m = source.metadata
    return SectionPointer(
        kind="doc:section",
        source_type="supplied_text",
        locator_subtype="section",
        source_id=m.source_id,
        source_sha256=m.source_sha256,
        source_revision=m.source_revision,
        evidence_artifact_sha256=m.evidence_artifact_sha256,
        locator=SectionLocator(
            section_id=span.id, quote=text, excerpt_sha256=hashlib.sha256(text.encode()).hexdigest()
        ),
    )
