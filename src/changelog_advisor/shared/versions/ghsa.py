"""GitHub REST global advisories; first_patched_version is metadata, not membership."""

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
)


def normalize_ghsa(raw: bytes, *, origin: str) -> Advisory:
    p = decode_record(raw)
    ident = identifier(p.get("ghsa_id"))
    if re.fullmatch(r"GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}", ident) is None:
        raise ValueError("invalid GHSA identity")
    aliases = []
    if p.get("cve_id") is not None:
        aliases.append(identifier(p["cve_id"]))
    ids = p.get("identifiers", [])
    rows = p.get("vulnerabilities", [])
    if type(ids) is not list or len(ids) > 128 or type(rows) is not list or len(rows) > 128:
        raise ValueError("invalid GHSA tables")
    for item in ids:
        if type(item) is not dict:
            raise ValueError("invalid GHSA identifier")
        aliases.append(identifier(item.get("value")))
    affected = []
    for row in rows:
        if type(row) is not dict or type(row.get("package")) is not dict:
            raise ValueError("invalid GHSA package")
        package = row["package"]
        functions = row.get("vulnerable_functions", [])
        if functions is None:
            functions = []
        if type(functions) is not list or len(functions) > 128:
            raise ValueError("invalid GHSA function metadata")
        patched = row.get("first_patched_version")
        # REST string/null only; do not silently accept GraphQL {identifier:...}.
        affected.append(
            Affected(
                text(package.get("ecosystem"), limit=128),
                text(package.get("name"), limit=256),
                ghsa_range=text(row.get("vulnerable_version_range"), nullable=True, limit=256),
                first_patched=text(patched, nullable=True, limit=256),
                functions=tuple(text(v, limit=256) for v in functions),
            )
        )
    return Advisory(
        "ghsa",
        ident,
        tuple(sorted(set(aliases) - {ident})),
        timestamp(p.get("updated_at")),
        timestamp(p.get("withdrawn_at"), nullable=True),
        text(p.get("summary", "")),
        text(p.get("description", ""), limit=1024 * 1024),
        tuple(affected),
        raw,
        provenance(raw, origin),
        origin,
    )


def row_membership(row: Affected, version: str, runtime) -> Membership:
    expression = row.ghsa_range
    if not expression or any(not part.strip() for part in expression.split(",")):
        return Membership("unknown", "ghsa_range_missing_or_malformed")
    # GitHub's comma conjunction becomes npm whitespace AND; || remains OR.
    expression = expression.replace(",", " ")
    result = runtime.satisfies_many([(version, expression)])[0]
    if not result["valid_range"] or not result["valid_version"]:
        return Membership("unknown", "ghsa_range_invalid")
    if result["satisfies"]:
        return Membership("affected", "ghsa_npm_range_matches")
    if runtime.validate_many([version])[0]["prerelease"]:
        # npm range exclusion alone cannot establish security safety for prerelease builds.
        return Membership("unknown", "ghsa_prerelease_outside_unproven")
    return Membership("not_affected", "ghsa_npm_range_outside")
