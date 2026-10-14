"""Installed truth is a declared exact pin, never the highest satisfying catalog entry."""

from .lockfile import Lockfile
from .models import Declaration, PinResult
from .runtime import NodeSemver, VersionRuntimeError


def resolve_pin(
    declaration: Declaration,
    runtime: NodeSemver,
    *,
    lock: Lockfile | None = None,
    override: str | None = None,
) -> PinResult:
    def outcome(status, reason, version=None, provenance=None, original=None, locator=None):
        return PinResult(
            declaration,
            status,
            version,
            provenance,
            reason,
            original,
            lock.sha256 if lock else None,
            locator,
        )

    spec = declaration.spec
    if spec.startswith(
        ("file:", "link:", "git:", "git+", "workspace:", "npm:", "http:", "https:", "github:")
    ):
        return outcome("unresolved", "declaration_source_unsupported")
    locked = lock.pin(declaration.name) if lock else None
    if locked and locked.reason:
        return outcome("unresolved", locked.reason, locator=locked.locator)
    raw_pin = locked.version if locked else override if override is not None else spec
    try:
        inputs = [raw_pin, spec] + ([override] if locked and override is not None else [])
        validation = runtime.validate_many(inputs)
        pin = validation[0]
        if not pin["valid"]:
            return outcome(
                "unresolved",
                "installed_pin_required"
                if not locked and override is None
                else "pin_version_invalid",
                locator=locked.locator if locked else None,
            )
        if locked and override is not None:
            asserted = validation[2]
            if not asserted["valid"] or asserted["canonical"] != pin["canonical"]:
                return outcome("conflict", "override_lock_conflict", locator=locked.locator)
        range_result = runtime.satisfies_many([(pin["canonical"], spec)])[0]
        if not range_result["valid_range"]:
            return outcome("unresolved", "declaration_range_unsupported")
        if not range_result["satisfies"]:
            return outcome(
                "conflict", "pin_manifest_conflict", locator=locked.locator if locked else None
            )
        provenance = (
            f"lockfile_v{lock.version}"
            if locked
            else ("user_asserted" if override is not None else "manifest_exact")
        )
        return outcome(
            "resolved",
            "exact_pin_recorded",
            pin["canonical"],
            provenance,
            raw_pin,
            locked.locator if locked else None,
        )
    except VersionRuntimeError as error:
        return outcome("runtime_error", error.reason)
