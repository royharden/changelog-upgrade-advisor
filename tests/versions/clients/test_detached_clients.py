"""what_bug_this_catches: moving clients misses closure or starts network/Node on import."""

import json
import shutil
import subprocess
import sys
from pathlib import Path


def test_detached_clients_inert_and_full_paths(tmp_path):
    root = Path(__file__).resolve().parents[3]
    namespace = tmp_path / "portable_versions"
    namespace.mkdir()
    for name in (
        "__init__.py",
        "models.py",
        "runtime.py",
        "manifest.py",
        "window.py",
        "advisories.py",
        "osv.py",
        "ghsa.py",
        "cache.py",
        "network.py",
        "clients.py",
        "semver.mjs",
    ):
        shutil.copyfile(root / "src/changelog_advisor/shared/versions" / name, namespace / name)
    script = r"""
import sys,json,socket,subprocess
from pathlib import Path
owner=Path(sys.argv[2]).resolve()
sys.path=[p for p in sys.path if Path(p).resolve() not in (owner,owner/'src')]
sys.path.insert(0,sys.argv[1])
def forbidden(*a,**kw):raise AssertionError('unexpected process/network')
subprocess.Popen=forbidden;socket.create_connection=forbidden;socket.getaddrinfo=forbidden
socket.socket.connect=forbidden
from portable_versions.clients import Clients
from portable_versions.cache import ResponseCache
from portable_versions.network import Response
class Synthetic:
 def send(self,req,**kw):
  body=b'{"vulns":[]}' if req.endpoint=='osv_query' else b'[]'
  return Response(200,body,(),'synthetic','2026-10-14T12:00:00Z')
c=Clients(ResponseCache(),mode='injected',transport=Synthetic())
assert c.query('osv','demo','1.0.0').complete
assert c.query('ghsa','demo','1.0.0').complete
loaded=ResponseCache.from_bytes(c.cache.to_bytes())
offline=Clients(loaded,transport=Synthetic())
assert offline.query('osv','demo','1.0.0').complete
assert offline.query('osv','missing','1.0.0').status=='not_fetched'
assert not any(n.startswith('changelog_advisor') for n in sys.modules)
print(json.dumps({'owner_imports':0,'network':0,'node':0}))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(tmp_path), str(root)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"owner_imports": 0, "network": 0, "node": 0}
