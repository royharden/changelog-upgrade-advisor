"""Direct npm lock records only; no path walking, installs, resolved URL or hook use."""

import hashlib

from .manifest import decode_json
from .models import LockPin, package_name


class Lockfile:
    def __init__(self, raw: bytes):
        payload = decode_json(raw, 32 * 1024 * 1024)
        version = payload.get("lockfileVersion")
        if type(version) is not int or version not in (1, 2, 3):
            raise ValueError("unsupported lockfile version")
        table = payload.get("dependencies", {}) if version == 1 else payload.get("packages")
        if type(table) is not dict or len(table) > 250000:
            raise ValueError("missing or oversized lock table")
        self.sha256 = hashlib.sha256(raw).hexdigest()
        self.version, self._table = version, table

    def pin(self, name: str) -> LockPin:
        package_name(name)
        locator = name if self.version == 1 else f"node_modules/{name}"
        item = self._table.get(locator)
        if item is None:
            return LockPin(None, "lock_pin_missing", self.version, locator)
        if type(item) is not dict:
            return LockPin(None, "lock_record_invalid", self.version, locator)
        if "link" in item and type(item["link"]) is not bool:
            return LockPin(None, "lock_record_invalid", self.version, locator)
        if item.get("link") is True:
            return LockPin(None, "lock_link_unsupported", self.version, locator)
        version = item.get("version")
        if type(version) is not str or not version or len(version) > 256:
            return LockPin(None, "lock_version_invalid", self.version, locator)
        return LockPin(version, None, self.version, locator)
