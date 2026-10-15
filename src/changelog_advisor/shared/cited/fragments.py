"""Retained saved-text fragments; no URL acquisition or HTML interpretation."""

import hashlib
import json
from dataclasses import dataclass
from typing import Literal

from .memory import (
    DEFAULT_BOUNDS,
    AccessPolicy,
    GenerationPolicy,
    MemoryBounds,
    MemorySource,
    SectionSpan,
)
from .models import ArtifactRef, FragmentPointer, Resolution, ResolutionContext, SourceArtifact
from .registry import Registry

FRAGMENT_KEY = ("url#fragment", "saved_web", "fragment")
PROFILE = "saved-web-fragments/1"


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _metadata(text: MemorySource) -> SourceArtifact:
    # MemorySource already binds raw/canonical text, namespace and the exact named windows.
    artifact = json.dumps(
        {"algorithm": PROFILE, "text_artifact_sha256": text.metadata.evidence_artifact_sha256},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf8")
    values = text.metadata.model_dump()
    values.update(source_type="saved_web", evidence_artifact_sha256=_sha(artifact))
    return SourceArtifact.model_validate(values)


@dataclass(frozen=True, slots=True)
class SavedWebSource:
    text: MemorySource
    metadata: SourceArtifact

    @classmethod
    def from_bytes(
        cls,
        *,
        namespace_id: str,
        source_id: str,
        source_revision: str,
        raw: bytes,
        newline_policy: Literal["identity", "crlf-to-lf"],
        fragments: tuple[SectionSpan, ...],
        bounds: MemoryBounds = DEFAULT_BOUNDS,
    ) -> "SavedWebSource":
        """Anchor IDs are exact SectionSpan IDs over retained text, never fetch URLs."""
        text = MemorySource.from_bytes(
            namespace_id=namespace_id,
            source_id=source_id,
            source_revision=source_revision,
            raw=raw,
            newline_policy=newline_policy,
            sections=fragments,
            bounds=bounds,
        )
        return cls(text, _metadata(text))

    def validate_retained(self) -> None:
        if type(self.text) is not MemorySource:
            raise TypeError("immutable retained text source required")
        self.text.validate_retained()
        if SourceArtifact.model_validate(self.metadata) != _metadata(self.text):
            raise ValueError("saved fragment metadata changed")


class SavedFragmentResolver:
    def __init__(
        self,
        sources: tuple[SavedWebSource, ...],
        *,
        access: AccessPolicy,
        generation: GenerationPolicy,
        bounds: MemoryBounds = DEFAULT_BOUNDS,
    ) -> None:
        if type(sources) is not tuple or type(bounds) is not MemoryBounds:
            raise TypeError("explicit immutable source tuple and bounds required")
        bounds.__post_init__()
        if len(sources) > bounds.max_sources:
            raise ValueError("retained source count exceeded")
        index = {}
        total = 0
        for source in sources:
            if type(source) is not SavedWebSource:
                raise TypeError("saved web source required")
            source.validate_retained()
            text = source.text
            if (
                len(text.raw) > bounds.max_source_bytes
                or len(text.lines) > bounds.max_lines
                or len(text.sections) > bounds.max_sections
            ):
                raise ValueError("source exceeds resolver bounds")
            key = (text.namespace_id, source.metadata.source_id, source.metadata.source_revision)
            if key in index:
                raise ValueError("duplicate saved source namespace/identity/revision")
            index[key] = source
            total += len(text.raw)
        if total > bounds.max_retained_bytes:
            raise ValueError("retained byte limit exceeded")
        self._sources = index
        self._access, self._generation = access, generation

    def _admit(
        self, pointer: FragmentPointer, context: ResolutionContext
    ) -> Resolution | SourceArtifact:
        try:
            if (
                ArtifactRef.model_validate(self._access.reference) != context.access_policy_ref
                or ArtifactRef.model_validate(self._generation.reference)
                != context.generation_policy_ref
            ):
                return Resolution(status="unsupported", reason="policy_reference_mismatch")
            decision = self._access.decision(context.namespace_id, pointer.source_id)
            if type(decision) is not str or decision != "allow":
                return Resolution(status="unsupported", reason="access_not_allowed")
            current = self._generation.current(context.namespace_id, pointer.source_id)
            if current is None:
                return Resolution(status="unsupported", reason="current_generation_unknown")
            current = SourceArtifact.model_validate(current)
        except Exception:
            return Resolution(status="unsupported", reason="policy_unavailable")
        if current.source_id != pointer.source_id or current.source_type != "saved_web":
            return Resolution(status="invalid", reason="current_source_identity_mismatch")
        if (
            current.source_revision != pointer.source_revision
            or current.source_sha256 != pointer.source_sha256
            or current.evidence_artifact_sha256 != pointer.evidence_artifact_sha256
        ):
            return Resolution(status="stale", reason="current_generation_mismatch")
        return current

    def resolve(self, pointer, context) -> Resolution:
        try:
            pointer = FragmentPointer.model_validate(pointer)
            context = ResolutionContext.model_validate(context)
        except Exception:
            return Resolution(status="invalid", reason="wire_contract_error")
        if context.generation_mode != "current":
            return Resolution(status="unsupported", reason="generation_mode_unavailable")
        if context.required_scope in ("spatial", "text_and_spatial"):
            return Resolution(status="unsupported", reason="required_scope_unavailable")
        current = self._admit(pointer, context)
        if isinstance(current, Resolution):
            return current
        source = self._sources.get(
            (context.namespace_id, pointer.source_id, pointer.source_revision)
        )
        if source is None:
            return Resolution(status="missing", reason="retained_source_missing")
        try:
            source.validate_retained()
        except Exception:
            return Resolution(status="invalid", reason="retained_source_mismatch")
        if source.metadata != current:
            return Resolution(status="stale", reason="retained_generation_mismatch")
        anchor = next(
            (s for s in source.text.sections if s.section_id == pointer.locator.fragment_id), None
        )
        if anchor is None:
            return Resolution(status="missing", reason="fragment_missing")
        text = source.text
        window = text.canonical[
            text.lines[anchor.line_start - 1].canonical_byte_start : text.lines[
                anchor.line_end - 1
            ].canonical_byte_end
        ]
        quote = pointer.locator.quote
        excerpt = quote.encode("utf8") if quote is not None else window
        if quote is not None and (
            excerpt not in window or _sha(excerpt) != pointer.locator.excerpt_sha256
        ):
            return Resolution(status="invalid", reason="quote_outside_fragment")
        decoded = excerpt.decode("utf8") if excerpt else None
        if decoded is not None and len(decoded) > 32768:
            return Resolution(status="unsupported", reason="excerpt_limit_exceeded")
        final = self._admit(pointer, context)
        if isinstance(final, Resolution):
            return final
        if final != current:
            return Resolution(status="stale", reason="generation_changed_during_resolution")
        try:
            source.validate_retained()
        except Exception:
            return Resolution(status="invalid", reason="retained_source_mismatch")
        if source.metadata != final:
            return Resolution(status="stale", reason="retained_generation_mismatch")
        return Resolution(
            status="resolved",
            reason="literal_fragment_checked",
            checked_source_sha256=source.metadata.source_sha256,
            checked_source_revision=source.metadata.source_revision,
            checked_artifact_sha256=source.metadata.evidence_artifact_sha256,
            scope="text",
            excerpt=decoded,
            excerpt_sha256=_sha(excerpt) if decoded is not None else None,
        )


def install_saved_fragments(registry: Registry, resolver: SavedFragmentResolver) -> None:
    registry.register(FRAGMENT_KEY, resolver)
