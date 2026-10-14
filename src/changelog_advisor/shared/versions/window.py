"""Release windows over a supplied immutable catalog. No numerical-maximum latest guess."""

import hashlib
import json

from .manifest import decode_json
from .models import RegistrySnapshot, WindowResult, package_name
from .runtime import NodeSemver, VersionRuntimeError


def read_registry_snapshot(
    raw: bytes, package: str, *, origin: str, fetched_at: str | None = None
) -> RegistrySnapshot:
    package_name(package)
    if origin not in ("synthetic", "saved_response"):
        raise ValueError("explicit catalog origin required")
    payload = decode_json(raw, 32 * 1024 * 1024)
    if payload.get("name") != package or type(payload.get("versions")) is not dict:
        raise ValueError("registry package identity or versions missing")
    versions = tuple(payload["versions"])
    for version, record in payload["versions"].items():
        if (
            type(record) is not dict
            or ("version" in record and record["version"] != version)
            or ("name" in record and record["name"] != package)
        ):
            raise ValueError("registry version record identity mismatch")
    tags = payload.get("dist-tags", {})
    if fetched_at is not None and type(fetched_at) is not str:
        raise ValueError("explicit retrieval timestamp must be a string or unknown")
    if (
        len(versions) > 10000
        or any(len(value) > 256 for value in versions)
        or type(tags) is not dict
        or len(tags) > 128
        or any(type(value) is not str or len(value) > 256 for value in tags.values())
    ):
        raise ValueError("registry metadata limits exceeded")
    return RegistrySnapshot(
        package,
        versions,
        tuple(sorted(tags.items())),
        hashlib.sha256(raw).hexdigest(),
        origin,
        fetched_at,
    )


def release_window(
    runtime: NodeSemver, snapshot: RegistrySnapshot, pin: str, target: str, *, prerelease="default"
) -> WindowResult:
    mode = "dist_tag_latest" if target == "latest" else "explicit"
    tag_hash = None
    actual_target = dict(snapshot.dist_tags).get("latest") if target == "latest" else target
    if target == "latest" and actual_target is not None:
        tag_hash = hashlib.sha256(
            json.dumps(
                {"package": snapshot.package, "tag": "latest", "version": actual_target},
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()

    def result(status, reason, releases=(), total=0, excluded=0, complete=False):
        return WindowResult(
            snapshot.package,
            status,
            pin,
            actual_target,
            tuple(releases),
            complete,
            total,
            excluded,
            snapshot.sha256,
            mode,
            tag_hash,
            reason,
        )

    if actual_target is None:
        return result("unknown", "latest_tag_missing")
    try:
        info = runtime.validate_many([pin, actual_target])
        catalog = runtime.validate_many(list(snapshot.versions))
        if (
            not info[0]["valid"]
            or not info[1]["valid"]
            or any(not value["valid"] for value in catalog)
        ):
            return result("unknown", "catalog_or_pin_version_invalid")
        normalized = [item["canonical"] for item in catalog]
        if len(set(normalized)) != len(normalized):
            return result("unknown", "ambiguous_catalog_version_identity")
        if info[1]["canonical"] not in normalized:
            return result("unknown", "target_not_in_catalog")
        actual_target = info[1]["canonical"]
        comparison = runtime.compare_pairs([(actual_target, pin)])[0]
        if comparison < 0:
            return result("unsupported", "downgrade_unsupported")
        if comparison == 0:
            return result("no_upgrade", "equal_precedence", complete=True)
        selected = runtime.between(list(snapshot.versions), pin, actual_target, prerelease)
        return result(
            "ready" if selected["complete"] else "incomplete",
            "release_window_recorded",
            selected["selected"],
            selected["selected_total"],
            selected["excluded_prereleases"],
            selected["complete"],
        )
    except VersionRuntimeError as error:
        return result("runtime_error", error.reason)
