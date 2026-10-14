"""Bounded supplied npm JSON; scripts/URLs are data and never executed/fetched."""

import hashlib
import json

from .models import SCOPES, Declaration, Manifest, package_name


def decode_json(raw: bytes, limit: int) -> dict:
    if type(raw) is not bytes or len(raw) > limit:
        raise ValueError("immutable JSON buffer exceeds declared limit")

    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def constant(value):
        raise ValueError("nonfinite JSON scalar")

    result = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    if type(result) is not dict:
        raise ValueError("npm JSON root must be an object")
    return result


def read_manifest(raw: bytes) -> Manifest:
    payload = decode_json(raw, 1024 * 1024)
    declarations = []
    for scope in SCOPES:
        table = payload.get(scope, {})
        if type(table) is not dict:
            raise ValueError("dependency scope must be an object")
        for name, spec in table.items():
            package_name(name)
            if type(spec) is not str or not spec or len(spec) > 256:
                raise ValueError("dependency declaration must be a bounded nonempty string")
            declarations.append(Declaration(name, spec, scope))
    return Manifest(hashlib.sha256(raw).hexdigest(), tuple(declarations))


def select_declarations(
    manifest: Manifest, selected: tuple[str, ...] | None = None
) -> tuple[Declaration, ...]:
    names = {item.name for item in manifest.declarations}
    if selected is None:
        if len(names) > 20:
            raise ValueError("explicit package subset required above 20 direct packages")
        return manifest.declarations
    if type(selected) is not tuple or len(selected) > 20 or len(set(selected)) != len(selected):
        raise ValueError("invalid explicit package subset")
    if not set(selected) <= names:
        raise ValueError("selected package absent from manifest")
    return tuple(item for item in manifest.declarations if item.name in selected)
