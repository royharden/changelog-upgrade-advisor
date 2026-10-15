"""Synthetic implementation controls: source association/coverage, not independent Gold."""

import hashlib
import socket
from dataclasses import replace

import pytest

from changelog_advisor.shared.cited import ArtifactRef, Finding, Registry, ResolutionContext
from changelog_advisor.shared.cited.assessment import assess_required_evidence
from changelog_advisor.shared.cited.memory import MemoryTextResolver, install_supplied_text
from changelog_advisor.shared.versions.changelog import parse_changelog, select_spans
from changelog_advisor.shared.versions.models import WindowResult
from changelog_advisor.shared.versions.runtime import NodeSemver, VersionRuntimeError
from changelog_advisor.shared.versions.sources import make_span_source, span_pointer


@pytest.fixture(scope="module")
def npm():
    versions = [
        "1.0.0",
        "1.2.3",
        "v1.2.3",
        "1.2.3+build",
        "01.2.3",
        "2.0.0",
        "2.0.0-beta.1",
        "V1.2.3",
    ]
    with NodeSemver() as oracle:
        info = dict(zip(versions, oracle.validate_many(versions), strict=True))

    class Oracle:
        def validate_many(self, values):
            return [info[v] for v in values]

    return Oracle()


@pytest.fixture(autouse=True)
def deny_network(monkeypatch):
    def denied(*a, **kw):
        raise AssertionError("supplied source dispatched network")

    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)


def window(*releases, package="demo", complete=True):
    return WindowResult(
        package,
        "ready" if complete else "incomplete",
        "1.0.0",
        "2.0.0",
        releases,
        complete,
        len(releases),
        0,
        "a" * 64,
        "explicit",
        None,
        "synthetic_unit",
    )


@pytest.mark.parametrize(
    "heading,style",
    [
        ("## 1.2.3", "bare_atx"),
        ("## [1.2.3] - 2026-10-14", "bracket_atx"),
        ("## Release v1.2.3 (2026-10-14)", "named_release"),
        ("## demo@1.2.3", "package_release"),
        ("v1.2.3\n======", "setext"),
        ("## [v1.2.3](https://evil.test/never-followed) - 2026-10-14", "linked_version"),
    ],
)
def test_six_heading_styles_all_exact_entry_quotes(npm, heading, style):
    raw = (heading + "\n- Removed é\n  continuation CASE\n").encode()
    notes = parse_changelog(raw, "demo", npm)
    assert notes.headings[0].style == style and notes.headings[0].version == "1.2.3"
    selection = select_spans(notes, window("1.2.3"), npm)
    assert selection.status == "ready" and selection.selected_total == 1
    assert selection.spans[0].text == "- Removed é\n  continuation CASE\n"


def test_scoped_package_and_foreign_version_do_not_retarget(npm):
    notes = parse_changelog(
        b"## @scope/pkg@1.2.3\n- exact\n## @wrong/pkg@2.0.0\n- foreign\n", "@scope/pkg", npm
    )
    selection = select_spans(notes, window("1.2.3", "2.0.0", package="@scope/pkg"), npm)
    assert len(selection.spans) == 1 and selection.foreign_spans == 1
    assert selection.missing_releases == ("2.0.0",) and selection.status == "incomplete"
    foreign = parse_changelog(("## wrong@1.2.3\n" + "é" * 5000).encode(), "demo", npm)
    selected = select_spans(foreign, window("1.2.3"), npm)
    assert selected.spans == () and selected.foreign_spans == 1


def test_duplicate_canonical_release_is_ambiguous_not_last_write(npm):
    notes = parse_changelog(b"## v1.2.3\n- one\n## [1.2.3]\n- two\n", "demo", npm)
    selection = select_spans(notes, window("1.2.3"), npm)
    assert selection.ambiguous_releases == ("1.2.3",)
    assert len(selection.spans) == 2 and {s.state for s in selection.spans} == {"ambiguous_release"}
    assert selection.status == "incomplete" and len({s.id for s in selection.spans}) == 2


def test_context_subsections_nested_bullets_and_blank_continuations(npm):
    raw = (
        b"## 1.2.3\n### Changed\n- one\n  - nested\n\n  continuation\n- two\n"
        b"\nParagraph line\nwrapped\n"
    )
    notes = parse_changelog(raw, "demo", npm)
    assert len(notes.spans) == 3
    assert notes.spans[0].text == "- one\n  - nested\n\n  continuation\n"
    assert notes.spans[1].text == "- two\n" and notes.spans[2].text == "Paragraph line\nwrapped\n"
    assert notes.spans[0].context == ("## 1.2.3\n", "### Changed\n")


def test_fences_cannot_create_headers_or_bullets(npm):
    raw = b"## 1.2.3\n- real\n```python\n## 2.0.0\n- fake\n```js\n## [1.0.0]\n```\n- second\n"
    notes = parse_changelog(raw, "demo", npm)
    assert len(notes.headings) == 1 and len(notes.spans) == 2
    assert "## 2.0.0\n- fake" in notes.spans[0].text
    assert notes.spans[1].text == "- second\n"


def test_crlf_unicode_bare_cr_and_no_phantom_line(npm):
    raw = "## 1.2.3\r\n- =SUM(é)\r\n  e\u0301\u2028text\rlone".encode()
    notes = parse_changelog(raw, "demo", npm)
    assert len(notes.lines) == 3 and notes.spans[0].line_end == 3
    assert notes.spans[0].text == "- =SUM(é)\n  e\u0301\u2028text\rlone"
    assert notes.sha256 == hashlib.sha256(raw).hexdigest()
    assert notes.canonical != raw and notes.observed_bytes == len(raw)
    assert len(parse_changelog(raw + b"\n", "demo", npm).lines) == 3


@pytest.mark.parametrize(
    "raw,reason",
    [
        (b"x" * 262145, "notes_byte_limit"),
        (b"\n" * 5001, "notes_line_limit"),
        (b"\xff", "notes_invalid_utf8"),
    ],
    ids=("byte_limit", "line_limit", "invalid_utf8"),
)
def test_source_limits_not_prefix_source(npm, raw, reason):
    notes = parse_changelog(raw, "demo", npm)
    assert notes.reason == reason and not notes.spans and notes.observed_bytes == len(raw)
    assert notes.status in ("incomplete", "invalid")


def test_unknown_unreleased_missing_empty_and_outside_coverage(npm):
    raw = b"preamble\n## Unreleased\n- planned\n## 01.2.3\n- invalid\n## 1.0.0\n- old\n## 1.2.3\n"
    notes = parse_changelog(raw, "demo", npm)
    selected = select_spans(notes, window("1.2.3", "2.0.0"), npm)
    assert selected.missing_releases == ("2.0.0",) and selected.empty_releases == ("1.2.3",)
    assert selected.unknown_sections == 3 and selected.outside_spans == 4
    assert selected.status == "incomplete" and selected.spans == ()


def test_unknown_peer_header_closes_previous_release(npm):
    raw = b"## 1.2.3\n- valid\n## 1.2.3 / 2.0.0\n- ambiguous heading\n##2.0.0\n- malformed\n"
    notes = parse_changelog(raw, "demo", npm)
    selected = select_spans(notes, window("1.2.3"), npm)
    assert selected.spans[0].text == "- valid\n" and len(selected.spans) == 1
    assert selected.unknown_sections == 2 and selected.status == "incomplete"


def test_line_chunks_retain_all_literal_entries_and_unsplittable(npm):
    raw = ("## 1.2.3\n- " + "a" * 4000 + "\n  " + "b" * 5000 + "\n  " + "c" * 4000 + "\n").encode()
    notes = parse_changelog(raw, "demo", npm)
    assert "".join(s.text for s in notes.spans).encode() == raw.split(b"\n", 1)[1]
    assert len(notes.spans) == 3 and all(s.byte_count <= 8192 for s in notes.spans)
    huge = parse_changelog(("## 1.2.3\n- " + "é" * 5000 + "\n- next\n").encode(), "demo", npm)
    selected = select_spans(huge, window("1.2.3"), npm)
    assert selected.status == "incomplete" and selected.spans[0].state == "unsplittable_entry"
    assert selected.spans[0].byte_count > 8192 and selected.spans[1].text == "- next\n"


def test_every_selected_span_no_keyword_prefilter_and_cap(npm):
    notes = parse_changelog(b"## 1.2.3\n- one\n- two\n- three\n", "demo", npm)
    selection = select_spans(notes, window("1.2.3"), npm, max_spans=2)
    assert (
        selection.selected_total == 3 and selection.capped_count == 1 and len(selection.spans) == 2
    )
    assert selection.status == "incomplete"
    zero = select_spans(notes, window("1.2.3"), npm, max_spans=0)
    assert zero.capped_count == 3 and zero.status == "incomplete"
    assert select_spans(notes, window("1.2.3", complete=False), npm).status == "incomplete"
    with pytest.raises(ValueError):
        select_spans(notes, window("1.2.3"), npm, max_spans=True)
    with pytest.raises(ValueError):
        select_spans(notes, window("1.2.3", package="other"), npm)


def test_stable_ids_across_selection_and_build_metadata(npm):
    notes = parse_changelog(b"## 1.2.3\n- same\n- same\n## 1.2.3+build\n- different\n", "demo", npm)
    a = select_spans(notes, window("1.2.3"), npm)
    b = select_spans(notes, window("1.2.3", "1.2.3+build"), npm)
    assert a.spans == b.spans[:2] and len({s.id for s in notes.spans}) == 3
    assert b.spans[-1].release == "1.2.3+build"


def test_node_failure_does_not_claim_missing_or_unaffected():
    class Broken:
        def validate_many(self, values):
            raise VersionRuntimeError("version_runtime_unavailable")

    notes = parse_changelog(b"## 1.2.3\n- one\n", "demo", Broken())
    assert notes.status == "incomplete" and notes.reason == "notes_version_runtime_error"
    assert len(notes.spans) == 1 and notes.spans[0].state == "invalid_version_heading"
    assert select_spans(notes, window("1.2.3"), Broken()).status == "unknown"


class Access:
    reference = ArtifactRef(artifact_id="access", artifact_sha256="a" * 64, profile_id="access/1")

    def __init__(self, answer="allow"):
        self.answer = answer

    def decision(self, namespace_id, source_id):
        return self.answer


class Generation:
    reference = ArtifactRef(
        artifact_id="generation", artifact_sha256="b" * 64, profile_id="generation/1"
    )

    def __init__(self, metadata):
        self.metadata = metadata

    def current(self, namespace_id, source_id):
        return self.metadata


def test_actual_selected_section_source_resolves_and_counts_failures(npm):
    notes = parse_changelog("## 1.2.3\r\n- Removed é\r\n- unrelated\r\n".encode(), "demo", npm)
    spans = select_spans(notes, window("1.2.3"), npm).spans
    source = make_span_source(notes, spans, namespace_id="notes-space", source_id="notes-demo")
    p = span_pointer(source, spans[0])
    registry = Registry()
    access = Access()
    generation = Generation(source.metadata)
    install_supplied_text(
        registry, MemoryTextResolver((source,), access=access, generation=generation)
    )
    context = ResolutionContext(
        namespace_id="notes-space",
        access_policy_ref=access.reference,
        generation_policy_ref=generation.reference,
        required_scope="text",
    )
    finding = Finding(id="entry", text="Potential change", verdict="partial", evidence=(p,))
    assessed = assess_required_evidence(finding, registry, context)
    assert assessed.resolved_count == 1 and assessed.finding.verdict == "partial"
    assert assessed.resolutions[0].excerpt == spans[0].text
    access.answer = "deny"
    denied = assess_required_evidence(finding, registry, context)
    assert (
        denied.required_count == 1
        and denied.unresolved_count == 1
        and denied.finding.verdict == "unsupported"
    )
    other = make_span_source(notes, spans[:1], namespace_id="notes-space", source_id="notes-demo")
    assert other.metadata.source_revision == source.metadata.source_revision
    assert other.metadata.evidence_artifact_sha256 != source.metadata.evidence_artifact_sha256
    access.answer = "allow"
    generation.metadata = other.metadata
    assert assess_required_evidence(finding, registry, context).resolutions[0].status == "stale"


def test_source_bridge_rejects_foreign_and_tampered_spans(npm):
    notes = parse_changelog(b"## 1.2.3\n- one\n", "demo", npm)
    source = make_span_source(notes, notes.spans, namespace_id="notes", source_id="demo-notes")
    with pytest.raises(ValueError):
        make_span_source(
            notes,
            (replace(notes.spans[0], text="changed"),),
            namespace_id="notes",
            source_id="demo",
        )
    with pytest.raises(ValueError):
        span_pointer(source, replace(notes.spans[0], text="changed"))
    with pytest.raises(ValueError):
        make_span_source(notes, list(notes.spans), namespace_id="notes", source_id="demo")


def test_real_production_npm_heading_validation():
    with NodeSemver() as oracle:
        notes = parse_changelog(b"## v1.2.3\n- no prefilter\n", "demo", oracle)
    assert notes.status == "ready" and notes.headings[0].version == "1.2.3"
    assert notes.spans[0].text == "- no prefilter\n"


def test_five_hundred_map_has_full_raw_source_and_overflow_count(npm):
    raw = ("## 1.2.3\n" + "".join("- entry" + str(i) + "\n" for i in range(512))).encode()
    notes = parse_changelog(raw, "demo", npm)
    selected = select_spans(notes, window("1.2.3"), npm)
    assert (
        selected.selected_total == 512
        and selected.capped_count == 12
        and len(selected.spans) == 500
    )
    source = make_span_source(notes, selected.spans, namespace_id="notes", source_id="source")
    assert len(source.sections) == 500 and source.raw == raw
    assert span_pointer(source, selected.spans[-1]).locator.quote == "- entry499\n"


def test_context_overflow_is_not_silently_shortened(npm):
    raw = ("## 1.2.3\n### " + "é" * 5000 + "\n- entry\n").encode()
    notes = parse_changelog(raw, "demo", npm)
    selected = select_spans(notes, window("1.2.3"), npm)
    assert selected.status == "incomplete" and selected.spans[0].state == "context_overflow"
    assert len(selected.spans[0].context[-1].encode()) > 8192
    source = make_span_source(notes, selected.spans, namespace_id="notes", source_id="source")
    with pytest.raises(ValueError):
        span_pointer(source, selected.spans[0])
