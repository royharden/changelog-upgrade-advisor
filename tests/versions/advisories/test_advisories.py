"""Synthetic implementation controls; never independent heldout Gold or semantic quality."""

import hashlib
import json
import socket
from dataclasses import replace

import pytest

from changelog_advisor.shared.versions.advisories import (
    deduplicate,
    group_membership,
    membership,
)
from changelog_advisor.shared.versions.ghsa import normalize_ghsa
from changelog_advisor.shared.versions.osv import normalize_osv
from changelog_advisor.shared.versions.runtime import NodeSemver, VersionRuntimeError


class CachedNode(NodeSemver):
    """Actual npm batch oracle; no expected membership table or Python version arithmetic."""

    def __init__(self):
        super().__init__()
        versions = [
            "0.0.0-alpha",
            "0.0.0",
            "0.9.0",
            "1.0.0",
            "1.0.0+one",
            "1.0.0+two",
            "1.0.0+build",
            "1.0.0+other",
            "1.0.0-beta",
            "1.0.0-beta.1",
            "1.0.0-beta.2",
            "1.0.1",
            "1.5.0",
            "1.9.9",
            "2.0.0",
            "2.0.0-beta.1",
            "2.5.0",
            "3.0.0",
            "3.0.0+build",
            "3.5.0",
            "4.0.0",
            "9.0.0",
            "garbage",
            "not-a-version",
        ]
        self.info = dict(zip(versions, super().validate_many(versions), strict=True))
        valid = [v for v in versions if self.info[v]["valid"]]
        ordered = super().sort(valid)
        self.positions = {v: i for i, v in enumerate(ordered)}
        pairs = [(a, b) for a in valid for b in valid]
        self.comparisons = dict(zip(pairs, super().compare_pairs(pairs), strict=True))
        ranges = [
            ">=1.0.0  <2.0.0",
            "<1.0.0 || >=3.0.0  <4.0.0",
            "<=1.0.0",
            ">=1.0.0-beta.1  <1.0.0",
            "<2.0.0",
            "garbage",
            "<3.0.0",
            "<1.0.0",
        ]
        pairs = [(v, r) for v in versions for r in ranges]
        self.ranges = dict(zip(pairs, super().satisfies_many(pairs), strict=True))

    def validate_many(self, versions):
        return [self.info[v] for v in versions]

    def compare_pairs(self, pairs):
        return [self.comparisons[tuple(p)] for p in pairs]

    def sort(self, versions):
        return sorted(versions, key=self.positions.__getitem__)

    def satisfies_many(self, pairs):
        return [self.ranges[tuple(p)] for p in pairs]


@pytest.fixture(scope="module")
def npm():
    with CachedNode() as oracle:
        yield oracle


@pytest.fixture(autouse=True)
def deny_network(monkeypatch):
    def forbidden(*a, **kw):
        raise AssertionError("advisory pure controls cannot dispatch network")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)


def osv(*events, versions=None, kind="SEMVER", **extras):
    row = {"package": {"name": "demo", "ecosystem": "npm"}, "ranges": []}
    if events:
        row["ranges"] = [{"type": kind, "events": list(events)}]
    if versions is not None:
        row["versions"] = versions
    p = {"id": "x_CONTROL-1", "modified": "2026-10-14T12:00:00Z", "affected": [row]}
    p.update(extras)
    return normalize_osv(json.dumps(p).encode(), origin="synthetic")


def ghsa(expression, **extras):
    p = {
        "ghsa_id": "GHSA-abcd-1234-efgh",
        "updated_at": "2026-10-14T12:00:00Z",
        "vulnerabilities": [
            {
                "package": {"name": "demo", "ecosystem": "npm"},
                "vulnerable_version_range": expression,
            }
        ],
    }
    p.update(extras)
    return normalize_ghsa(json.dumps(p).encode(), origin="synthetic")


@pytest.mark.parametrize(
    "version,expected",
    [
        ("0.9.0", "not_affected"),
        ("1.0.0", "affected"),
        ("1.9.9", "affected"),
        ("2.0.0", "not_affected"),
        ("2.5.0", "not_affected"),
        ("3.0.0", "affected"),
        ("3.0.0+build", "affected"),
        ("4.0.0", "not_affected"),
        ("2.0.0-beta.1", "affected"),
    ],
)
def test_osv_reintroduction_union_unsorted(npm, version, expected):
    # Catches treating only the first interval, sorting lexically, or fixed as inclusive.
    record = osv(
        {"fixed": "4.0.0"}, {"introduced": "3.0.0"}, {"fixed": "2.0.0"}, {"introduced": "1.0.0"}
    )
    result = membership(record, "demo", version, npm)
    assert result.status == expected, result


@pytest.mark.parametrize(
    "version,expected",
    [
        ("0.0.0-alpha", "affected"),
        ("0.0.0", "affected"),
        ("1.0.0", "affected"),
        ("1.0.1", "not_affected"),
    ],
)
def test_osv_last_affected_and_unbounded_start(npm, version, expected):
    assert (
        membership(
            osv({"introduced": "0"}, {"last_affected": "1.0.0"}), "demo", version, npm
        ).status
        == expected
    )


@pytest.mark.parametrize(
    "limits,version,expected",
    [
        (["2.0.0", "4.0.0"], "3.0.0", "affected"),
        (["2.0.0", "4.0.0"], "4.0.0", "not_affected"),
        (["2.0.0", "*"], "9.0.0", "affected"),
    ],
)
def test_osv_limit_union(npm, limits, version, expected):
    result = membership(
        osv({"introduced": "0"}, *({"limit": v} for v in limits)), "demo", version, npm
    )
    assert result.status == expected, result


@pytest.mark.parametrize(
    "record",
    [
        osv({"introduced": "0"}, kind="GIT"),
        osv({"introduced": "1.0.0", "fixed": "2.0.0"}),
        osv({"fixed": "2.0.0"}),
        osv({"introduced": "1.0.0"}, {"fixed": "2.0.0"}, {"last_affected": "3.0.0"}),
        osv({"introduced": "garbage"}),
        osv({"introduced": "1.0.0"}, {"fixed": "1.0.0+build"}),
        osv({"introduced": "1.0.0"}, {"fixed": "1.0.0"}),
        osv(),
        osv(versions=["not-a-version"]),
    ],
)
def test_unknown_is_not_safe(npm, record):
    assert membership(record, "demo", "1.0.0", npm).status == "unknown"


def test_explicit_positive_survives_unsupported_alternative(npm):
    record = osv({"introduced": "arbitrary-sha"}, kind="GIT", versions=["1.0.0"])
    assert membership(record, "demo", "1.0.0", npm).status == "affected"
    assert membership(record, "demo", "1.0.1", npm).status == "unknown"


def test_explicit_version_build_identity_and_ecosystem(npm):
    record = osv(versions=["1.0.0+one"])
    assert membership(record, "demo", "1.0.0+two", npm).status == "not_affected"
    assert membership(record, "demo", "1.0.0+one", npm).status == "affected"
    assert (
        membership(osv({"introduced": "0"}, kind="ECOSYSTEM"), "demo", "1.0.0-beta", npm).status
        == "affected"
    )


@pytest.mark.parametrize(
    "expression,version,expected",
    [
        (">=1.0.0, <2.0.0", "1.5.0", "affected"),
        (">=1.0.0, <2.0.0", "2.0.0", "not_affected"),
        ("<1.0.0 || >=3.0.0, <4.0.0", "3.5.0", "affected"),
        ("<1.0.0 || >=3.0.0, <4.0.0", "2.0.0", "not_affected"),
        ("<=1.0.0", "1.0.0+other", "affected"),
        (">=1.0.0-beta.1, <1.0.0", "1.0.0-beta.2", "affected"),
        ("<2.0.0", "1.0.0-beta", "unknown"),
        ("garbage", "1.0.0", "unknown"),
        (None, "1.0.0", "unknown"),
        ("", "1.0.0", "unknown"),
        ("<2.0.0,", "1.0.0", "unknown"),
    ],
)
def test_ghsa_distinct_range_grammar(npm, expression, version, expected):
    result = membership(ghsa(expression), "demo", version, npm)
    assert result.status == expected, result


def test_ghsa_rest_metadata_not_fixed_comparator(npm):
    record = ghsa(
        "<3.0.0",
        vulnerabilities=[
            {
                "package": {"name": "demo", "ecosystem": "npm"},
                "first_patched_version": "2.0.0",
                "vulnerable_version_range": "<3.0.0",
                "vulnerable_functions": ["danger"],
            }
        ],
    )
    assert membership(record, "demo", "2.5.0", npm).status == "affected"
    assert record.affected[0].functions == ("danger",)
    assert record.affected[0].first_patched == "2.0.0"
    assert osv({"introduced": "0"}).affected[0].functions == ()
    with pytest.raises(ValueError):
        ghsa(
            "<3.0.0",
            vulnerabilities=[
                {
                    "package": {"name": "demo", "ecosystem": "npm"},
                    "first_patched_version": {"identifier": "2.0.0"},
                }
            ],
        )


def test_alias_transitive_merge_preserves_sources_and_conflict(npm):
    a = osv({"introduced": "0"}, aliases=["CVE-2050-00001"])
    b = ghsa("<1.0.0", cve_id="CVE-2050-00001")
    c = osv(versions=["1.0.0"], id="x_CONTROL-2", aliases=[b.id])
    groups = deduplicate((a, c, b, a))
    assert len(groups) == 1 and len(groups[0].records) == 3
    assert group_membership(groups[0], "demo", "1.0.0", npm).status == "conflict"
    assert {r.source for r in groups[0].records} == {"osv", "ghsa"}
    assert all(r.sha256 == hashlib.sha256(r.raw).hexdigest() for r in groups[0].records)


def test_withdrawal_identity_and_binding(npm):
    active = osv({"introduced": "0"})
    withdrawn = osv({"introduced": "0"}, withdrawn="2026-10-14T14:00:00Z")
    assert membership(withdrawn, "demo", "1.0.0", npm).status == "withdrawn"
    assert membership(withdrawn, "other", "1.0.0", npm).status == "not_applicable"
    assert (
        group_membership(deduplicate((active, withdrawn))[0], "demo", "1.0.0", npm).status
        == "conflict"
    )
    assert membership(replace(active, summary="tampered"), "demo", "1.0.0", npm).status == "unknown"
    wrong = osv(
        {"introduced": "0"},
        affected=[{"package": {"name": "demo", "ecosystem": "PyPI"}, "versions": ["1.0.0"]}],
    )
    assert membership(wrong, "demo", "1.0.0", npm).status == "not_applicable"
    assert membership(active, "demo", "garbage", npm).status == "unknown"


@pytest.mark.parametrize(
    "mutations",
    [
        {"schema_version": "2.0.0"},
        {"schema_version": "1.bad"},
        {"aliases": ["../secret"]},
        {"modified": "2026-10-14"},
        {"modified": None},
        {"withdrawn": "bad"},
        {"affected": [False]},
        {"affected": [0] * 129},
    ],
)
def test_osv_malformed_rejected(mutations):
    with pytest.raises((ValueError, TypeError)):
        osv(**mutations)


def test_bounded_json_and_duplicate_keys():
    with pytest.raises(ValueError):
        normalize_osv(b'{"id":"x","id":"y"}', origin="synthetic")
    with pytest.raises(ValueError):
        normalize_ghsa(b" " * (2 * 1024 * 1024 + 1), origin="synthetic")
    with pytest.raises(ValueError):
        normalize_osv(osv().raw, origin="live_assumed")


def test_runtime_failure_never_empty_success():
    class Broken:
        def validate_many(self, values):
            raise VersionRuntimeError("version_runtime_unavailable")

    assert membership(osv({"introduced": "0"}), "demo", "1.0.0", Broken()).status == "unknown"


def test_inert_normalizer_and_no_evaluation_process(monkeypatch):
    def forbidden(*a, **kw):
        raise AssertionError("normalizing source must not start a runtime")

    monkeypatch.setattr(NodeSemver, "_request", forbidden)
    record = ghsa("<2.0.0")
    assert record.source == "ghsa" and record.origin == "synthetic"


@pytest.mark.parametrize("depth", [33, 100, 1500])
def test_deep_unused_metadata_rejected(depth):
    raw = b'{"unused":' + b"[" * depth + b"0" + b"]" * depth + b"}"
    with pytest.raises(ValueError, match="depth|structure"):
        normalize_osv(raw, origin="synthetic")


def test_actual_runtime_membership_positive_and_negative():
    # No oracle cache: actual production IPC, source parsing and membership paths together.
    with NodeSemver() as runtime:
        _assert_actual_runtime_membership(runtime)


def _assert_actual_runtime_membership(runtime):
    for record, version, expected in [
        (osv({"introduced": "0"}, {"fixed": "2.0.0"}), "1.0.0", "affected"),
        (osv({"introduced": "0"}, {"fixed": "2.0.0"}), "2.0.0", "not_affected"),
        (ghsa(">=1.0.0, <2.0.0"), "1.5.0", "affected"),
        (ghsa(">=1.0.0, <2.0.0"), "2.0.0", "not_affected"),
    ]:
        result = membership(record, "demo", version, runtime)
        assert result.status == expected, result
