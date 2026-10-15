"""Immutable advisory provenance and conservative union; no usage/reachability judgment."""

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime

from .manifest import decode_json
from .models import package_name
from .runtime import VersionRuntimeError


def identifier(value: str) -> str:
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9:_.-]{1,256}", value) is None:
        raise ValueError("invalid advisory identifier")
    return value


def text(value, *, limit=65536, nullable=False):
    if nullable and value is None:
        return None
    if type(value) is not str or len(value.encode("utf8")) > limit:
        raise ValueError("invalid bounded advisory text")
    return value


def timestamp(value, *, nullable=False):
    value = text(value, limit=128, nullable=nullable)
    if value is not None and datetime.fromisoformat(value).tzinfo is None:
        raise ValueError("timezone-aware advisory timestamp required")
    return value


def decode_record(raw: bytes):
    try:
        result = decode_json(raw, 2 * 1024 * 1024)
    except RecursionError:
        raise ValueError("advisory depth limit") from None
    pending = [(result, 0)]
    count = 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if depth > 32 or count > 100000:
            raise ValueError("advisory structure limit")
        if type(value) is dict:
            pending.extend((v, depth + 1) for v in value.values())
        elif type(value) is list:
            pending.extend((v, depth + 1) for v in value)
    return result


@dataclass(frozen=True, slots=True)
class Affected:
    ecosystem: str
    package: str
    explicit_versions: tuple[str, ...] = ()
    # Each OSV range retains type and events; malformed range is an explicit unsupported atom.
    events: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = ()
    ghsa_range: str | None = None
    first_patched: str | None = None
    functions: tuple[str, ...] = ()
    unsupported: bool = False


@dataclass(frozen=True, slots=True)
class Advisory:
    source: str
    id: str
    aliases: tuple[str, ...]
    modified: str
    withdrawn: str | None
    summary: str
    details: str
    affected: tuple[Affected, ...]
    raw: bytes
    sha256: str
    origin: str


@dataclass(frozen=True, slots=True)
class Membership:
    status: str
    reason: str


def provenance(raw: bytes, origin: str):
    if origin not in ("synthetic", "saved_response"):
        raise ValueError("explicit advisory origin required")
    return hashlib.sha256(raw).hexdigest()


def union(values: list[Membership]) -> Membership:
    if any(value.status == "affected" for value in values):
        return Membership("affected", "supported_alternative_matches")
    unknown = next((v for v in values if v.status == "unknown"), None)
    if unknown is not None:
        return unknown
    if not values:
        return Membership("unknown", "unsupported_or_missing_alternative")
    return Membership("not_affected", "all_applicable_alternatives_outside")


def membership(record: Advisory, package: str, version: str, runtime) -> Membership:
    """Revalidate raw/derived binding. Metadata shape cannot prove source authenticity."""
    package_name(package)
    from .ghsa import normalize_ghsa
    from .ghsa import row_membership as ghsa_row
    from .osv import normalize_osv
    from .osv import row_membership as osv_row

    try:
        normalize, evaluate = {"osv": (normalize_osv, osv_row), "ghsa": (normalize_ghsa, ghsa_row)}[
            record.source
        ]
        if normalize(record.raw, origin=record.origin) != record:
            return Membership("unknown", "advisory_binding_mismatch")
        info = runtime.validate_many([version])[0]
        if not info["valid"]:
            return Membership("unknown", "version_invalid")
        rows = [r for r in record.affected if r.ecosystem == "npm" and r.package == package]
        if not rows:
            return Membership("not_applicable", "package_or_ecosystem_mismatch")
        if record.withdrawn is not None:
            return Membership("withdrawn", "source_record_withdrawn")
        values = []
        for row in rows:
            try:
                values.append(evaluate(row, version, runtime))
            except VersionRuntimeError as error:
                values.append(Membership("unknown", error.reason))
        return union(values)
    except VersionRuntimeError as error:
        return Membership("unknown", error.reason)
    except (KeyError, ValueError, TypeError, AttributeError):
        return Membership("unknown", "advisory_malformed")


@dataclass(frozen=True, slots=True)
class AdvisoryGroup:
    ids: tuple[str, ...]
    records: tuple[Advisory, ...]


def deduplicate(records: tuple[Advisory, ...]) -> tuple[AdvisoryGroup, ...]:
    """Transitive exact-id/alias components; preserve distinct source revisions and withdrawal."""
    if type(records) is not tuple or len(records) > 1000:
        raise ValueError("advisory record limit")
    groups: list[tuple[set[str], list[Advisory]]] = []
    for record in records:
        ids = {identifier(record.id), *(identifier(a) for a in record.aliases)}
        members = [record]
        pending = []
        for known, sources in groups:
            if ids & known:
                ids |= known
                members.extend(sources)
            else:
                pending.append((known, sources))
        # A late bridge may connect a group visited earlier in this pass.
        while any(ids & known for known, _ in pending):
            rest = []
            for known, sources in pending:
                if ids & known:
                    ids |= known
                    members.extend(sources)
                else:
                    rest.append((known, sources))
            pending = rest
        unique = {(m.source, m.id, m.sha256): m for m in members}
        pending.append((ids, sorted(unique.values(), key=lambda r: (r.source, r.id, r.sha256))))
        groups = pending
    return tuple(
        sorted((AdvisoryGroup(tuple(sorted(i)), tuple(r)) for i, r in groups), key=lambda g: g.ids)
    )


def group_membership(group: AdvisoryGroup, package: str, version: str, runtime) -> Membership:
    values = [membership(record, package, version, runtime) for record in group.records]
    applicable = [v for v in values if v.status != "not_applicable"]
    statuses = {v.status for v in applicable}
    if len(statuses) > 1 and statuses & {"affected", "not_affected", "withdrawn"}:
        return Membership("conflict", "source_membership_or_withdrawal_disagrees")
    if not applicable:
        return Membership("not_applicable", "no_applicable_source")
    if statuses == {"withdrawn"}:
        return Membership("withdrawn", "all_applicable_sources_withdrawn")
    return union(applicable)
