"""Supplied changelog-spans/1. No acquisition, cited import or Python semver arithmetic."""

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass

from .models import WindowResult, package_name
from .runtime import VersionRuntimeError

VERSION = r"[vV]?[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?"
ATX = re.compile(r"^(#{1,6})[ \t]+(.+?)(?:[ \t]+#+)?[ \t]*$")
DATE = r"(?:[ \t]+(?:-[ \t]+\d{4}-\d{2}-\d{2}|\(\d{4}-\d{2}-\d{2}\)))?"
BULLET = re.compile(r"^([ \t]*)(?:[-*+]|[0-9]+[.)])[ \t]+")
FENCE = re.compile(r"^[ \t]{0,3}(`{3,}|~{3,})")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _lines(text: str):
    parts = text.split("\n")
    return tuple(p + "\n" for p in parts[:-1]) + ((parts[-1],) if parts[-1] else ())


@dataclass(frozen=True, slots=True)
class Heading:
    line: int
    body_start: int
    depth: int
    title: str
    style: str
    raw_version: str | None
    version: str | None
    state: str


@dataclass(frozen=True, slots=True)
class Span:
    id: str
    release: str | None
    section_start: int
    line_start: int
    line_end: int
    chunk_index: int
    text: str
    context: tuple[str, ...]
    byte_count: int
    state: str


@dataclass(frozen=True, slots=True)
class ParsedNotes:
    package: str
    raw: bytes
    sha256: str
    canonical: bytes
    lines: tuple[str, ...]
    headings: tuple[Heading, ...]
    spans: tuple[Span, ...]
    status: str
    reason: str
    observed_bytes: int


def span_identity(package, raw_hash, release, section_start, start, end, chunk, text):
    payload = {
        "algorithm": "changelog-spans/1",
        "package": package,
        "raw_source_sha256": raw_hash,
        "release": release,
        "section_start": section_start,
        "line_start": start,
        "line_end": end,
        "chunk_index": chunk,
        "literal_content_sha256": _sha(text.encode("utf8")),
    }
    return "span-" + _sha(
        json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf8")
    )


def _candidate(title: str, package: str):
    patterns = [
        ("bare_atx", rf"({VERSION}){DATE}"),
        ("bracket_atx", rf"\[({VERSION})\]{DATE}"),
        ("named_release", rf"(?:Release|Version)[ \t]+({VERSION}){DATE}"),
        ("linked_version", rf"\[({VERSION})\]\([^\r\n)]+\){DATE}"),
    ]
    for style, pattern in patterns:
        match = re.fullmatch(pattern, title, flags=re.IGNORECASE)
        if match:
            return style, match[1], "candidate"
    match = re.fullmatch(rf"(.+)@({VERSION}){DATE}", title)
    if match:
        return "package_release", match[2], "candidate" if match[1] == package else "foreign"
    return "unclassified", None, "unreleased" if "unreleased" in title.lower() else "unversioned"


def _headings(lines, package):
    headings = []
    fence = None
    current_depth = 0
    index = 0
    while index < len(lines):
        title = lines[index].removesuffix("\n")
        marker = FENCE.match(title)
        if marker:
            if fence is None:
                fence = marker[1]
            elif (
                marker[1][0] == fence[0]
                and len(marker[1]) >= len(fence)
                and re.fullmatch(
                    r"[ \t]{0,3}" + re.escape(fence[0]) + "{" + str(len(fence)) + r",}[ \t]*", title
                )
            ):
                fence = None
            index += 1
            continue
        if fence:
            index += 1
            continue
        atx = ATX.match(title)
        if atx:
            depth, body = len(atx[1]), atx[2]
            style, version, state = _candidate(body, package)
            if (
                version is not None
                or current_depth == 0
                or depth <= current_depth
                or state == "unreleased"
            ):
                headings.append(
                    Heading(index + 1, index + 2, depth, title, style, version, None, state)
                )
                current_depth = depth
            index += 1
            continue
        if (
            re.fullmatch(VERSION, title)
            and index + 1 < len(lines)
            and re.fullmatch(r"[ \t]*(?:={3,}|-{3,})[ \t]*", lines[index + 1].removesuffix("\n"))
        ):
            headings.append(
                Heading(index + 1, index + 3, 1, title, "setext", title, None, "candidate")
            )
            current_depth = 1
            index += 2
            continue
        if title.startswith("#") and re.search(r"[0-9]+\.[0-9]+", title):
            headings.append(
                Heading(
                    index + 1, index + 2, 1, title, "unclassified", None, None, "malformed_heading"
                )
            )
            current_depth = 1
        index += 1
    return headings


def _groups(lines, heading, end):
    current = []
    context = [(heading.depth, "".join(lines[heading.line - 1 : heading.body_start - 1]))]
    if not heading.title:
        context = []
    bullet_indent = None
    fence = None
    groups = []

    def flush():
        nonlocal current, bullet_indent
        if current:
            groups.append((tuple(current), tuple(title for _, title in context)))
        current, bullet_indent = [], None

    for line_number in range(heading.body_start, end + 1):
        line = lines[line_number - 1]
        body = line.removesuffix("\n")
        marker = FENCE.match(body)
        if marker:
            if fence is None:
                fence = marker[1]
            elif (
                marker[1][0] == fence[0]
                and len(marker[1]) >= len(fence)
                and re.fullmatch(
                    r"[ \t]{0,3}" + re.escape(fence[0]) + "{" + str(len(fence)) + r",}[ \t]*", body
                )
            ):
                fence = None
            current.append(line_number)
            continue
        if fence:
            current.append(line_number)
            continue
        subheading = ATX.match(body)
        if subheading:
            flush()
            depth = len(subheading[1])
            context = [(d, t) for d, t in context if d < depth]
            context.append((depth, line))
            continue
        if not body.strip(" \t\r"):
            # Blank lines inside an indented bullet continuation are retained literally.
            next_line = lines[line_number] if line_number < end else ""
            indent = len(next_line) - len(next_line.lstrip(" \t"))
            if current and bullet_indent is not None and indent > bullet_indent:
                current.append(line_number)
            else:
                flush()
            continue
        bullet = BULLET.match(body)
        indent = len(bullet[1]) if bullet else None
        if bullet and current and (bullet_indent is None or indent <= bullet_indent):
            flush()
        if bullet and not current:
            bullet_indent = indent
        current.append(line_number)
    flush()
    return groups


def _spans(lines, heading, end, package, raw_hash):
    result = []
    for group, context in _groups(lines, heading, end):
        chunks = []
        current = []
        size = 0
        for number in group:
            count = len(lines[number - 1].encode("utf8"))
            if current and size + count > 8192:
                chunks.append(current)
                current, size = [], 0
            if count > 8192:
                chunks.append([number])
            else:
                current.append(number)
                size += count
        if current:
            chunks.append(current)
        for chunk_index, chunk in enumerate(chunks):
            start, stop = chunk[0], chunk[-1]
            text = "".join(lines[start - 1 : stop])
            count = len(text.encode("utf8"))
            state = heading.state
            if count > 8192:
                state = "unsplittable_entry"
            elif sum(len(c.encode("utf8")) for c in context) > 8192:
                state = "context_overflow"
            result.append(
                Span(
                    span_identity(
                        package,
                        raw_hash,
                        heading.version,
                        heading.line,
                        start,
                        stop,
                        chunk_index,
                        text,
                    ),
                    heading.version,
                    heading.line,
                    start,
                    stop,
                    chunk_index,
                    text,
                    context,
                    count,
                    state,
                )
            )
    return result


def parse_changelog(raw: bytes, package: str, runtime) -> ParsedNotes:
    package_name(package)
    if type(raw) is not bytes:
        raise TypeError("immutable release-note buffer required")
    if len(raw) > 262144:
        return ParsedNotes(
            package, b"", "", b"", (), (), (), "incomplete", "notes_byte_limit", len(raw)
        )
    digest = _sha(raw)
    try:
        canonical = raw.decode("utf8").replace("\r\n", "\n").encode("utf8")
        lines = _lines(canonical.decode("utf8"))
    except UnicodeError:
        return ParsedNotes(
            package, raw, digest, b"", (), (), (), "invalid", "notes_invalid_utf8", len(raw)
        )
    if len(lines) > 5000:
        return ParsedNotes(
            package, raw, digest, canonical, (), (), (), "incomplete", "notes_line_limit", len(raw)
        )
    headings = _headings(lines, package)
    candidates = list(
        dict.fromkeys(
            h.raw_version
            for h in headings
            if h.raw_version is not None and len(h.raw_version) <= 256
        )
    )
    reason, info = "notes_parsed", {}
    try:
        if candidates:
            info = dict(zip(candidates, runtime.validate_many(candidates), strict=True))
    except VersionRuntimeError:
        reason = "notes_version_runtime_error"
    normalized = []
    for h in headings:
        v = info.get(h.raw_version)
        state = h.state
        if h.raw_version is not None and state != "foreign":
            state = "ready" if v and v["valid"] else "invalid_version_heading"
        normalized.append(
            Heading(
                h.line,
                h.body_start,
                h.depth,
                h.title,
                h.style,
                h.raw_version,
                v["canonical"] if v and v["valid"] else None,
                state,
            )
        )
    counts = Counter(h.version for h in normalized if h.state == "ready")
    headers = [
        Heading(
            h.line,
            h.body_start,
            h.depth,
            h.title,
            h.style,
            h.raw_version,
            h.version,
            "ambiguous_release" if h.state == "ready" and counts[h.version] > 1 else h.state,
        )
        for h in normalized
    ]
    if not headers or headers[0].line > 1:
        headers.insert(0, Heading(1, 1, 0, "", "preamble", None, None, "unversioned"))
    spans = []
    for index, heading in enumerate(headers):
        end = headers[index + 1].line - 1 if index + 1 < len(headers) else len(lines)
        spans.extend(_spans(lines, heading, end, package, digest))
    return ParsedNotes(
        package,
        raw,
        digest,
        canonical,
        lines,
        tuple(headers),
        tuple(spans),
        "ready" if reason == "notes_parsed" else "incomplete",
        reason,
        len(raw),
    )


@dataclass(frozen=True, slots=True)
class SpanSelection:
    status: str
    spans: tuple[Span, ...]
    selected_total: int
    capped_count: int
    missing_releases: tuple[str, ...]
    ambiguous_releases: tuple[str, ...]
    empty_releases: tuple[str, ...]
    unknown_sections: int
    outside_spans: int
    foreign_spans: int


def select_spans(notes: ParsedNotes, window: WindowResult, runtime, *, max_spans=500):
    if type(max_spans) is not int or not 0 <= max_spans <= 500:
        raise ValueError("explicit remaining run span budget0..500 required")
    if notes.package != window.package:
        raise ValueError("notes/window package mismatch")
    if window.status not in ("ready", "incomplete", "no_upgrade"):
        return SpanSelection("unknown", (), 0, 0, (), (), (), 0, 0, 0)
    try:
        info = runtime.validate_many(list(window.releases)) if window.releases else []
        if any(not v["valid"] for v in info):
            raise VersionRuntimeError("release_version_invalid")
        selected = tuple(v["canonical"] for v in info)
    except VersionRuntimeError:
        return SpanSelection("unknown", (), 0, 0, (), (), (), 0, 0, 0)
    headings = [h for h in notes.headings if h.state != "foreign" and h.version is not None]
    known = {h.version for h in headings}
    foreign_sections = {h.line for h in notes.headings if h.state == "foreign"}
    chosen = [
        s for s in notes.spans if s.release in selected and s.section_start not in foreign_sections
    ]
    ambiguous = tuple(
        v
        for v in selected
        if any(h.version == v and h.state == "ambiguous_release" for h in headings)
    )
    empty = tuple(v for v in selected if v in known and not any(s.release == v for s in chosen))
    missing = tuple(v for v in selected if v not in known)
    unknown = sum(
        h.state not in ("ready", "foreign", "ambiguous_release")
        and (
            h.state in ("unreleased", "invalid_version_heading", "malformed_heading")
            or any(s.section_start == h.line for s in notes.spans)
        )
        for h in notes.headings
    )
    capped = max(0, len(chosen) - max_spans)
    incomplete = (
        not window.complete
        or notes.status != "ready"
        or missing
        or empty
        or ambiguous
        or unknown
        or capped
        or any(s.state != "ready" for s in chosen)
    )
    return SpanSelection(
        "incomplete" if incomplete else "ready",
        tuple(chosen[:max_spans]),
        len(chosen),
        capped,
        missing,
        ambiguous,
        empty,
        unknown,
        sum(
            s.release not in selected and s.section_start not in foreign_sections
            for s in notes.spans
        ),
        sum(s.section_start in foreign_sections for s in notes.spans),
    )
