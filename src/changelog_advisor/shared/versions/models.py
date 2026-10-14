"""Version provenance, not assertions about an installed filesystem or a live registry."""

import re
from dataclasses import dataclass

SCOPES = ("dependencies", "devDependencies", "optionalDependencies")


def package_name(value: str) -> str:
    if (
        type(value) is not str
        or len(value) > 214
        or re.fullmatch(r"(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*", value)
        is None
    ):
        raise ValueError("unsupported npm package identity")
    return value


@dataclass(frozen=True, slots=True)
class Declaration:
    name: str
    spec: str
    scope: str


@dataclass(frozen=True, slots=True)
class Manifest:
    sha256: str
    declarations: tuple[Declaration, ...]


@dataclass(frozen=True, slots=True)
class LockPin:
    version: str | None
    reason: str | None
    lock_version: int
    locator: str


@dataclass(frozen=True, slots=True)
class PinResult:
    declaration: Declaration
    status: str
    version: str | None
    provenance: str | None
    reason: str
    original_pin: str | None = None
    lock_sha256: str | None = None
    lock_locator: str | None = None


@dataclass(frozen=True, slots=True)
class RegistrySnapshot:
    package: str
    versions: tuple[str, ...]
    dist_tags: tuple[tuple[str, str], ...]
    sha256: str
    origin: str
    fetched_at: str | None


@dataclass(frozen=True, slots=True)
class WindowResult:
    package: str
    status: str
    pin: str
    target: str | None
    releases: tuple[str, ...]
    complete: bool
    selected_total: int
    excluded_prereleases: int
    snapshot_sha256: str
    target_mode: str
    tag_sha256: str | None
    reason: str
