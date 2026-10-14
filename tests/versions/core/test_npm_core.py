"""what_bug_this_catches: ranges/previews become installed truth or Python ordering diverges."""

import json
import socket

import pytest

from changelog_advisor.shared.versions.lockfile import Lockfile
from changelog_advisor.shared.versions.manifest import read_manifest, select_declarations
from changelog_advisor.shared.versions.models import Declaration
from changelog_advisor.shared.versions.pins import resolve_pin
from changelog_advisor.shared.versions.runtime import NodeSemver, VersionRuntimeError
from changelog_advisor.shared.versions.window import read_registry_snapshot, release_window


def encoded(value):
    return json.dumps(value).encode()


@pytest.fixture
def runtime(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("unit source attempted network")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    return NodeSemver()


def catalog(versions, latest=None):
    return read_registry_snapshot(
        encoded(
            {
                "name": "test-pkg",
                "versions": {v: {} for v in versions},
                "dist-tags": {} if latest is None else {"latest": latest},
            }
        ),
        "test-pkg",
        origin="synthetic",
    )


def test_real_pinned_oracle_batch_orders_prereleases_numbers_and_ignores_build(runtime):
    pairs = [
        ("1.9.0", "1.10.0"),
        ("1.0.0-alpha.2", "1.0.0-alpha.10"),
        ("1.0.0-rc.1", "1.0.0"),
        ("1.0.0+first", "1.0.0+second"),
        ("0.9.0", "1.0.0"),
        ("2.0.0", "1.999.999"),
    ]
    assert runtime.compare_pairs(pairs) == [-1, -1, -1, 0, -1, 1]
    info = runtime.validate_many(["1.2.3+build.7", "v1.2.3", "^1.2.3", "1.02.3", "$(command)"])
    assert info[0]["canonical"] == "1.2.3+build.7" and info[1]["canonical"] == "1.2.3"
    assert [item["valid"] for item in info] == [True, True, False, False, False]
    assert runtime.sort(["1.10.0", "1.2.0", "1.0.0-rc.1", "1.0.0"]) == [
        "1.0.0-rc.1",
        "1.0.0",
        "1.2.0",
        "1.10.0",
    ]


def test_real_range_authority_is_distinct_from_window_prerelease_policy(runtime):
    queries = [
        ("1.5.0", "^1.2.0"),
        ("2.0.0", "^1.2.0"),
        ("0.2.9", "^0.2.3"),
        ("0.3.0", "^0.2.3"),
        ("1.2.4", "~1.2.3"),
        ("1.3.0", "~1.2.3"),
        ("1.2.3-beta.1", ">=1.0.0 <2.0.0"),
        ("1.2.3-beta.2", ">=1.2.3-beta.1 <2.0.0"),
        ("1.0.0", ">=1.0.0 <2.0.0 || >=3.0.0"),
        ("1.2.3", "not-a-range"),
    ]
    result = runtime.satisfies_many(queries)
    assert [item["satisfies"] for item in result] == [
        True,
        False,
        True,
        False,
        True,
        False,
        False,
        True,
        True,
        None,
    ]
    assert result[-1]["valid_range"] is False


@pytest.mark.parametrize("version", [1, 2, 3])
def test_lock_versions_direct_pin_and_original_scope(runtime, version):
    payload = {"lockfileVersion": version}
    payload["dependencies" if version == 1 else "packages"] = {
        "test-pkg" if version == 1 else "node_modules/test-pkg": {
            "version": "1.2.3",
            "resolved": "https://credentials.invalid/do-not-follow",
            "scripts": {"postinstall": "never-run"},
        }
    }
    lock = Lockfile(encoded(payload))
    declaration = Declaration("test-pkg", "^1.0.0", "devDependencies")
    result = resolve_pin(declaration, runtime, lock=lock)
    assert result.status == "resolved" and result.version == "1.2.3"
    assert result.provenance == f"lockfile_v{version}" and result.declaration == declaration
    assert result.lock_sha256 == lock.sha256


@pytest.mark.parametrize(
    "spec,override,status,provenance",
    [
        ("1.2.3", None, "resolved", "manifest_exact"),
        ("^1.0.0", None, "unresolved", None),
        ("^1.0.0", "1.2.3", "resolved", "user_asserted"),
        ("^1.0.0", "2.0.0", "conflict", None),
        ("file:../local", "1.2.3", "unresolved", None),
        ("workspace:*", None, "unresolved", None),
        ("npm:other@1.2.3", None, "unresolved", None),
        ("git+https://invalid/repo", None, "unresolved", None),
        ("^1.0.0", "not-a-version", "unresolved", None),
    ],
)
def test_no_catalog_maximum_or_unsupported_source_becomes_installed_pin(
    runtime, spec, override, status, provenance
):
    result = resolve_pin(Declaration("test-pkg", spec, "dependencies"), runtime, override=override)
    assert result.status == status and result.provenance == provenance
    if status != "resolved":
        assert result.version is None


@pytest.mark.parametrize(
    "record,override,expected",
    [
        ({"version": "2.0.0"}, None, "conflict"),
        ({"version": "1.2.3"}, "1.2.4", "conflict"),
        ({"link": True, "version": "1.2.3"}, None, "unresolved"),
        ({"version": "file:../elsewhere"}, None, "unresolved"),
        ({"version": True}, None, "unresolved"),
        ({"link": "true", "version": "1.2.3"}, None, "unresolved"),
    ],
)
def test_conflicting_and_non_npm_lock_pins_stay_visible(runtime, record, override, expected):
    lock = Lockfile(encoded({"lockfileVersion": 3, "packages": {"node_modules/test-pkg": record}}))
    result = resolve_pin(
        Declaration("test-pkg", "^1.0.0", "dependencies"), runtime, lock=lock, override=override
    )
    assert result.status == expected and result.version is None


def test_nested_lock_path_or_missing_record_cannot_supply_direct_installed_truth(runtime):
    lock = Lockfile(
        encoded(
            {
                "lockfileVersion": 3,
                "packages": {"node_modules/parent/node_modules/test-pkg": {"version": "1.2.3"}},
            }
        )
    )
    result = resolve_pin(Declaration("test-pkg", "1.2.3", "dependencies"), runtime, lock=lock)
    assert result.status == "unresolved" and result.reason == "lock_pin_missing"


def test_latest_is_exact_cached_tag_not_numerical_maximum(runtime):
    snapshot = catalog(["1.1.0", "1.9.0", "2.0.0"], latest="1.9.0")
    result = release_window(runtime, snapshot, "1.0.0", "latest")
    assert (
        result.status == "ready"
        and result.target == "1.9.0"
        and result.releases == ("1.1.0", "1.9.0")
    )
    assert result.tag_sha256 is not None and result.snapshot_sha256 == snapshot.sha256
    assert (
        release_window(runtime, catalog(["1.0.0"]), "1.0.0", "latest").reason
        == "latest_tag_missing"
    )


@pytest.mark.parametrize(
    "policy,expected",
    [
        ("default", ("1.1.0", "1.2.0-alpha.1", "1.2.0-beta.2")),
        ("all", ("1.1.0-alpha.1", "1.1.0", "1.2.0-alpha.1", "1.2.0-beta.2")),
        ("none", ("1.1.0", "1.2.0-beta.2")),
    ],
)
def test_explicit_prerelease_target_never_disappears(runtime, policy, expected):
    snapshot = catalog(
        ["1.0.0", "1.1.0-alpha.1", "1.1.0", "1.2.0-alpha.1", "1.2.0-beta.2", "2.0.0"]
    )
    result = release_window(runtime, snapshot, "1.0.0", "1.2.0-beta.2", prerelease=policy)
    assert result.releases == expected and result.complete


def test_prerelease_pin_own_base_and_cap_after_filter(runtime):
    versions = [f"1.0.{i}-alpha.1" for i in range(510)] + ["1.0.0", "1.0.1", "1.1.0"]
    result = release_window(runtime, catalog(versions), "1.0.0-beta.1", "1.1.0")
    assert result.complete and result.releases == ("1.0.0", "1.0.1", "1.1.0")
    many = [f"1.0.{i}" for i in range(1, 502)]
    result = release_window(runtime, catalog(many), "1.0.0", "1.0.501")
    assert (
        result.status == "incomplete"
        and len(result.releases) == 500
        and result.selected_total == 501
    )


@pytest.mark.parametrize(
    "pin,target,status,reason",
    [
        ("1.0.0", "1.0.0", "no_upgrade", "equal_precedence"),
        ("1.0.0+one", "1.0.0+two", "no_upgrade", "equal_precedence"),
        ("2.0.0", "1.0.0", "unsupported", "downgrade_unsupported"),
        ("1.0.0", "9.0.0", "unknown", "target_not_in_catalog"),
    ],
)
def test_equality_downgrade_and_unpublished_target_are_not_successful_upgrades(
    runtime, pin, target, status, reason
):
    result = release_window(runtime, catalog(["1.0.0", "1.0.0+two", "2.0.0"]), pin, target)
    assert result.status == status and result.reason == reason


def test_manifest_scopes_duplicates_and_explicit_subset_no_silent_first_twenty():
    manifest = read_manifest(
        encoded(
            {
                "dependencies": {"same": "^1.0.0"},
                "devDependencies": {"same": "1.2.3"},
                "optionalDependencies": {"optional": "~2.0.0"},
                "scripts": {"postinstall": "do-not-run"},
            }
        )
    )
    assert [item.scope for item in manifest.declarations] == [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
    ]
    large = read_manifest(encoded({"dependencies": {f"pkg{i}": "1.0.0" for i in range(21)}}))
    with pytest.raises(ValueError):
        select_declarations(large)
    assert len(select_declarations(large, ("pkg20",))) == 1
    for raw in (
        b'{"dependencies":{"same":"1","same":"2"}}',
        b'{"dependencies":{"x":true}}',
        b'{"dependencies":{"../escape":"1.0.0"}}',
        b'{"dependencies":[]}',
        b'{"x":NaN}',
    ):
        with pytest.raises(ValueError):
            read_manifest(raw)


@pytest.mark.parametrize(
    "method,argument",
    [
        ("validate_many", ["x" * 257]),
        ("validate_many", [True]),
        ("validate_many", ["1.0.0"] * 10001),
        ("compare_pairs", [("1.0.0", "2.0.0")] * 1001),
    ],
)
def test_bounds_refuse_before_node_transport(runtime, method, argument):
    runtime._transport = lambda *args: pytest.fail("invalid input launched Node")
    with pytest.raises(VersionRuntimeError):
        getattr(runtime, method)(argument)


@pytest.mark.parametrize(
    "kind", ["wrong_id", "extra_action", "invalid_json", "huge", "wrong_result", "timeout"]
)
def test_malformed_runtime_cannot_become_affected_or_unaffected(runtime, kind):
    def transport(node, helper, payload):
        request = json.loads(payload)
        response = {
            "protocol_version": 1,
            "request_id": request["request_id"],
            "ok": True,
            "result": [0],
        }
        if kind == "wrong_id":
            response["request_id"] = "wrong"
        elif kind == "extra_action":
            response["execute"] = "anything"
        elif kind == "invalid_json":
            return 0, b"not-json"
        elif kind == "huge":
            return 0, b"a" * (2 * 1024 * 1024 + 1)
        elif kind == "wrong_result":
            response["result"] = [True]
        else:
            raise VersionRuntimeError("version_runtime_timeout")
        return 0, encoded(response)

    runtime._transport = transport
    with pytest.raises(VersionRuntimeError):
        runtime.compare_pairs([("1.0.0", "2.0.0")])


def test_missing_runtime_is_explicit_unknown_not_python_fallback(runtime, monkeypatch):
    monkeypatch.setattr(
        "changelog_advisor.shared.versions.runtime.shutil.which", lambda value: None
    )
    result = resolve_pin(Declaration("test-pkg", "1.0.0", "dependencies"), runtime)
    assert result.status == "runtime_error" and result.version is None


def test_windows_native_runtime_never_selects_cmd_shim(runtime, monkeypatch):
    import os

    asked = []

    def which(name):
        asked.append(name)
        return "trusted-native-executable"

    def transport(node, helper, payload):
        request = json.loads(payload)
        assert node == "trusted-native-executable"
        return 0, encoded(
            {"protocol_version": 1, "request_id": request["request_id"], "ok": True, "result": [-1]}
        )

    monkeypatch.setattr("changelog_advisor.shared.versions.runtime.shutil.which", which)
    runtime._transport = transport
    assert runtime.compare_pairs([("1.0.0", "2.0.0")]) == [-1]
    assert asked == ["node.exe" if os.name == "nt" else "node"]


@pytest.mark.parametrize("record", [True, {"version": "wrong"}, {"name": "wrong-package"}])
def test_catalog_record_keys_do_not_fabricate_publication_when_identity_invalid(record):
    raw = encoded({"name": "test-pkg", "versions": {"1.0.0": record}})
    with pytest.raises(ValueError):
        read_registry_snapshot(raw, "test-pkg", origin="synthetic")
