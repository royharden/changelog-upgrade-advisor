"""Retained advisory citation fidelity; no acquisition, version math or usage judgment."""

import hashlib
import json
from dataclasses import dataclass

from pydantic import TypeAdapter

from ..cited.memory import AccessPolicy, GenerationPolicy
from ..cited.models import (
    AdvisoryPointer,
    ArtifactRef,
    LogicalID,
    Resolution,
    ResolutionContext,
    SourceArtifact,
)
from ..cited.registry import Registry
from .advisories import Advisory
from .ghsa import normalize_ghsa
from .osv import normalize_osv

ADVISORY_KEY = ("advisory:id", "advisory_record", "id")
PROFILE = "advisory-summary-details/1"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value) -> str:
    return _sha(
        json.dumps(
            value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf8")
    )


def record_projection(record: Advisory) -> dict:
    return {
        "profile": PROFILE,
        "source": record.source,
        "id": record.id,
        "raw_sha256": record.sha256,
        "text": record.summary + "\n" + record.details,
    }


def advisory_source_id(record: Advisory) -> str:
    return "advisory-" + record.source + "-" + record.sha256


def _validate_record(record: Advisory) -> None:
    if type(record) is not Advisory or type(record.raw) is not bytes:
        raise TypeError("immutable canonical advisory record required")
    normalize = {"osv": normalize_osv, "ghsa": normalize_ghsa}.get(record.source)
    if normalize is None or normalize(record.raw, origin=record.origin) != record:
        raise ValueError("advisory raw/derived binding mismatch")


def _metadata(record: Advisory) -> SourceArtifact:
    return SourceArtifact(
        source_id=advisory_source_id(record),
        source_type="advisory_record",
        source_sha256=record.sha256,
        source_revision="sha256:" + record.sha256,
        evidence_artifact_sha256=_digest(record_projection(record)),
        raw_byte_length=len(record.raw),
    )


@dataclass(frozen=True, slots=True)
class AdvisorySource:
    namespace_id: str
    record: Advisory
    metadata: SourceArtifact

    @classmethod
    def from_record(cls, record: Advisory, *, namespace_id: str) -> "AdvisorySource":
        TypeAdapter(LogicalID).validate_python(namespace_id, strict=True)
        _validate_record(record)
        return cls(namespace_id, record, _metadata(record))

    def validate_retained(self) -> None:
        TypeAdapter(LogicalID).validate_python(self.namespace_id, strict=True)
        _validate_record(self.record)
        if SourceArtifact.model_validate(self.metadata) != _metadata(self.record):
            raise ValueError("retained advisory metadata changed")


class AdvisoryRecordResolver:
    def __init__(
        self,
        sources: tuple[AdvisorySource, ...],
        *,
        access: AccessPolicy,
        generation: GenerationPolicy,
        max_sources: int = 1000,
        max_retained_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        if type(sources) is not tuple:
            raise TypeError("immutable advisory source tuple required")
        if (
            type(max_sources) is not int
            or not 1 <= max_sources <= 1000
            or type(max_retained_bytes) is not int
            or not 1 <= max_retained_bytes <= 64 * 1024 * 1024
            or len(sources) > max_sources
        ):
            raise ValueError("advisory source bounds exceeded")
        index = {}
        total = 0
        for source in sources:
            if type(source) is not AdvisorySource:
                raise TypeError("explicit advisory source required")
            source.validate_retained()
            key = (source.namespace_id, source.metadata.source_id, source.metadata.source_revision)
            if key in index:
                raise ValueError("duplicate advisory namespace/identity/revision")
            index[key] = source
            total += len(source.record.raw)
        if total > max_retained_bytes:
            raise ValueError("retained advisory byte bound exceeded")
        self._sources = index
        self._access, self._generation = access, generation

    def _admit(
        self, pointer: AdvisoryPointer, context: ResolutionContext
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
        if current.source_id != pointer.source_id or current.source_type != "advisory_record":
            return Resolution(status="invalid", reason="current_source_identity_mismatch")
        if (
            current.source_revision != pointer.source_revision
            or current.source_sha256 != pointer.source_sha256
            or current.evidence_artifact_sha256 != pointer.evidence_artifact_sha256
        ):
            return Resolution(status="stale", reason="source_identity_changed")
        return current

    def resolve(self, pointer, context) -> Resolution:
        try:
            pointer = AdvisoryPointer.model_validate(pointer)
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
            return Resolution(status="missing", reason="source_not_retained")
        try:
            source.validate_retained()
        except Exception:
            return Resolution(status="invalid", reason="retained_advisory_mismatch")
        if source.metadata != current:
            return Resolution(status="stale", reason="retained_generation_mismatch")
        quote = pointer.locator.quote
        if (
            pointer.locator.advisory_id != source.record.id
            or not quote
            or quote not in record_projection(source.record)["text"]
            or pointer.locator.excerpt_sha256 != _sha(quote.encode("utf8"))
        ):
            return Resolution(status="invalid", reason="literal_quote_mismatch")
        final = self._admit(pointer, context)
        if isinstance(final, Resolution):
            return final
        if final != current:
            return Resolution(status="stale", reason="generation_changed_during_resolution")
        try:
            source.validate_retained()
        except Exception:
            return Resolution(status="invalid", reason="retained_advisory_mismatch")
        if source.metadata != final:
            return Resolution(status="stale", reason="retained_generation_mismatch")
        return Resolution(
            status="resolved",
            reason="literal_quote_resolved",
            scope="text",
            checked_source_sha256=source.metadata.source_sha256,
            checked_source_revision=source.metadata.source_revision,
            checked_artifact_sha256=source.metadata.evidence_artifact_sha256,
            excerpt=quote,
            excerpt_sha256=_sha(quote.encode("utf8")),
        )


def install_advisory_records(registry: Registry, resolver: AdvisoryRecordResolver) -> None:
    registry.register(ADVISORY_KEY, resolver)
