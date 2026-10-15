"""what_bug_this_catches: moving Python files loses the sole npm helper/dependency."""

import json
import shutil
import subprocess
import sys
from pathlib import Path


def test_detached_complete_versions_closure_uses_actual_npm_oracle(tmp_path):
    root = Path(__file__).resolve().parents[3]
    namespace = tmp_path / "portable"
    namespace.mkdir()
    (namespace / "__init__.py").write_text("", encoding="utf-8")
    destination = namespace / "versions"
    destination.mkdir()
    source = root / "src/changelog_advisor/shared/versions"
    for name in (
        "__init__.py",
        "models.py",
        "runtime.py",
        "manifest.py",
        "lockfile.py",
        "pins.py",
        "window.py",
        "semver.mjs",
    ):
        shutil.copyfile(source / name, destination / name)
    # Already installed, pinned ISC dependency; no install/network/workspace import.
    dependency = tmp_path / "node_modules" / "semver"
    shutil.copytree(root / "node_modules/semver", dependency)
    assert (dependency / "LICENSE").is_file()
    script = r"""
import sys,json,socket,subprocess
from pathlib import Path
owner=Path(sys.argv[2]).resolve()
sys.path=[path for path in sys.path if Path(path).resolve() not in (owner,owner/"src")]
sys.path.insert(0,sys.argv[1])
def forbidden(*args,**kwargs):raise AssertionError("inert import attempted execution/network")
original=subprocess.Popen
subprocess.Popen=forbidden
socket.create_connection=forbidden
from portable.versions.runtime import NodeSemver
from portable.versions.manifest import read_manifest
from portable.versions.pins import resolve_pin
from portable.versions.window import read_registry_snapshot,release_window
subprocess.Popen=original
runtime=NodeSemver()
manifest=read_manifest(b'{"dependencies":{"pkg":"1.0.0"}}')
pin=resolve_pin(manifest.declarations[0],runtime)
assert pin.version=="1.0.0" and pin.provenance=="manifest_exact"
catalog=read_registry_snapshot(b'{"name":"pkg","versions":{"1.0.0":{},"1.1.0":{},"2.0.0":{}},"dist-tags":{"latest":"1.1.0"}}',"pkg",origin="synthetic")
window=release_window(runtime,catalog,pin.version,"latest")
assert window.releases==("1.1.0",) and window.complete
runtime.close()
assert not any(name.startswith("changelog_advisor") for name in sys.modules)
print(json.dumps(dict(pin=pin.version,target=window.target,complete=window.complete,owner_imports=0)))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(tmp_path), str(root)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=35,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "pin": "1.0.0",
        "target": "1.1.0",
        "complete": True,
        "owner_imports": 0,
    }
