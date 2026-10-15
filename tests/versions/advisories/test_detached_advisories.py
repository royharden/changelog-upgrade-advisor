"""what_bug_this_catches: advisory export imports its owner app or loses npm closure."""

import json
import shutil
import subprocess
import sys
from pathlib import Path


def test_detached_advisory_closure(tmp_path):
    root = Path(__file__).resolve().parents[3]
    module = tmp_path / "renamed_versions"
    module.mkdir()
    for name in (
        "__init__.py",
        "models.py",
        "manifest.py",
        "runtime.py",
        "semver.mjs",
        "advisories.py",
        "osv.py",
        "ghsa.py",
    ):
        shutil.copyfile(root / "src/changelog_advisor/shared/versions" / name, module / name)
    shutil.copytree(root / "node_modules/semver", tmp_path / "node_modules/semver")
    script = r"""
import sys,json,socket,subprocess
from pathlib import Path
owner=Path(sys.argv[2]).resolve()
sys.path=[p for p in sys.path if Path(p).resolve() not in (owner,owner/'src')]
sys.path.insert(0,sys.argv[1])
def forbidden(*a,**kw):raise AssertionError('unexpected import/network')
original=subprocess.Popen;subprocess.Popen=forbidden;socket.create_connection=forbidden
socket.socket.connect=forbidden
from renamed_versions.advisories import membership,deduplicate,group_membership
from renamed_versions.osv import normalize_osv
from renamed_versions.ghsa import normalize_ghsa
from renamed_versions.runtime import NodeSemver
a=normalize_osv(b'{"id":"x_CONTROL-1","aliases":["CVE-2050-00001"],"modified":"2026-10-14T12:00:00Z","affected":[{"package":{"name":"demo","ecosystem":"npm"},"versions":["1.0.0"]}]}',origin='synthetic')
b=normalize_ghsa(b'{"ghsa_id":"GHSA-abcd-1234-efgh","cve_id":"CVE-2050-00001","updated_at":"2026-10-14T12:00:00Z","vulnerabilities":[{"package":{"name":"demo","ecosystem":"npm"},"vulnerable_version_range":"<1.0.0"}]}',origin='synthetic')
subprocess.Popen=original;r=NodeSemver()
assert membership(a,'demo','1.0.0',r).status=='affected'
assert membership(a,'wrong','1.0.0',r).status=='not_applicable'
assert group_membership(deduplicate((a,b))[0],'demo','1.0.0',r).status=='conflict'
assert not any(n.startswith('changelog_advisor') for n in sys.modules)
print(json.dumps({'owner_imports':0,'network':0,'actual_npm':True}))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(tmp_path), str(root)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=35,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"owner_imports": 0, "network": 0, "actual_npm": True}
