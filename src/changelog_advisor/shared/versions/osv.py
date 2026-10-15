"""OSV 1.x npm supplied-record normalization; range events are not GHSA range strings."""

import re

from .advisories import (
    Advisory,
    Affected,
    Membership,
    decode_record,
    identifier,
    provenance,
    text,
    timestamp,
    union,
)
from .runtime import VersionRuntimeError


def normalize_osv(raw: bytes, *, origin: str) -> Advisory:
    payload = decode_record(raw)
    version = payload.get("schema_version", "1.0.0")
    if type(version) is not str or re.fullmatch(r"1\.\d+\.\d+", version) is None:
        raise ValueError("unsupported OSV schema major")
    aliases = payload.get("aliases", [])
    affected = payload.get("affected", [])
    if type(aliases) is not list or len(aliases) > 128 or type(affected) is not list:
        raise ValueError("invalid OSV tables")
    if len(affected) > 128:
        raise ValueError("OSV affected limit")
    rows = []
    for row in affected:
        if type(row) is not dict or type(row.get("package")) is not dict:
            raise ValueError("invalid OSV package row")
        package = row["package"]
        ecosystem = text(package.get("ecosystem"), limit=128)
        name = text(package.get("name"), limit=256)
        versions, ranges = row.get("versions", []), row.get("ranges", [])
        if (
            type(versions) is not list
            or len(versions) > 1000
            or type(ranges) is not list
            or len(ranges) > 128
        ):
            raise ValueError("invalid OSV version/range table")
        atoms = []
        for r in ranges:
            if type(r) is not dict or type(r.get("events")) is not list:
                atoms.append(("unsupported", ()))
                continue
            kind, events = r.get("type"), r["events"]
            malformed = type(kind) is not str or len(events) > 500
            parsed = []
            for event in events[:501]:
                if type(event) is not dict or len(event) != 1:
                    malformed = True
                    continue
                key, value = next(iter(event.items()))
                if key not in ("introduced", "fixed", "last_affected", "limit"):
                    malformed = True
                elif type(value) is not str or not value or len(value) > 256:
                    malformed = True
                else:
                    parsed.append((key, value))
            kinds = {key for key, _ in parsed}
            if "introduced" not in kinds or {"fixed", "last_affected"} <= kinds:
                malformed = True
            atoms.append(("unsupported" if malformed else kind, tuple(parsed)))
        rows.append(
            Affected(ecosystem, name, tuple(text(v, limit=256) for v in versions), tuple(atoms))
        )
    return Advisory(
        "osv",
        identifier(payload.get("id")),
        tuple(identifier(a) for a in aliases),
        timestamp(payload.get("modified")),
        timestamp(payload.get("withdrawn"), nullable=True),
        text(payload.get("summary", "")),
        text(payload.get("details", ""), limit=1024 * 1024),
        tuple(rows),
        raw,
        provenance(raw, origin),
        origin,
    )


def event_membership(kind: str, events: tuple[tuple[str, str], ...], version, runtime):
    if kind not in ("SEMVER", "ECOSYSTEM"):
        return Membership("unknown", "unsupported_osv_range_type")
    # npm ECOSYSTEM uses the same official SemVer authority; GIT is never approximated.
    finite = list(
        dict.fromkeys(v for k, v in events if (k, v) not in (("introduced", "0"), ("limit", "*")))
    )
    if any(not i["valid"] for i in runtime.validate_many(finite)):
        return Membership("unknown", "invalid_osv_boundary")
    ordered = runtime.sort(finite)
    positions = {v: i for i, v in enumerate(ordered)}
    # Distinct equal-precedence boundaries could toggle in a producer-order dependent way.
    ties = runtime.compare_pairs(list(zip(ordered, ordered[1:], strict=False)))
    if any(value == 0 for value in ties):
        return Membership("unknown", "ambiguous_osv_event_precedence")
    values = dict(zip(finite, runtime.compare_pairs([(version, v) for v in finite]), strict=True))
    if len({v for k, v in events if k != "limit"}) != sum(k != "limit" for k, _ in events):
        return Membership("unknown", "duplicate_osv_toggle_boundary")
    limits = [v for k, v in events if k == "limit"]
    if limits and not any(v == "*" or values[v] < 0 for v in limits):
        return Membership("not_affected", "outside_osv_limit_union")
    toggles = [(k, v) for k, v in events if k != "limit"]
    toggles.sort(key=lambda kv: -1 if kv == ("introduced", "0") else positions[kv[1]])
    vulnerable = False
    for key, value in toggles:
        comparison = 1 if (key, value) == ("introduced", "0") else values[value]
        if key == "introduced" and comparison >= 0:
            vulnerable = True
        elif key == "fixed" and comparison >= 0:
            vulnerable = False
        elif key == "last_affected" and comparison > 0:
            vulnerable = False
    return Membership("affected" if vulnerable else "not_affected", "osv_event_membership")


def row_membership(row: Affected, version: str, runtime) -> Membership:
    alternatives = []
    if row.explicit_versions:
        # OSV explicit-version identity is literal, not range precedence/build equality.
        if version in row.explicit_versions:
            return Membership("affected", "osv_explicit_version_identity")
        invalid = any(not v["valid"] for v in runtime.validate_many(list(row.explicit_versions)))
        alternatives.append(
            Membership("unknown" if invalid else "not_affected", "osv_explicit_version_identity")
        )
    for kind, events in row.events:
        try:
            alternatives.append(event_membership(kind, events, version, runtime))
        except VersionRuntimeError as error:
            alternatives.append(Membership("unknown", error.reason))
    return union(alternatives)
