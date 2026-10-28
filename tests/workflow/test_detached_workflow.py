"""what_bug_this_catches: the real CLI depends on the owner checkout or missing assets."""

import json
import shutil
import subprocess
import sys
from pathlib import Path


def test_complete_local_source_closure_runs_normal_and_refusal_away_from_owner(tmp_path):
    root = Path(__file__).resolve().parents[2]
    app = tmp_path / "copy"
    shutil.copytree(
        root / "src/changelog_advisor",
        app / "src/changelog_advisor",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    shutil.copytree(root / "node_modules/semver", app / "node_modules/semver")
    assert (app / "node_modules/semver/LICENSE").is_file()
    script = r"""
import importlib.abc, json, socket, sys
from pathlib import Path
app,owner=map(Path,sys.argv[1:])
sys.path=[p for p in sys.path if Path(p).resolve() not in (owner,owner/'src')]
sys.path.insert(0,str(app/'src'))
def denied(*a,**k): raise AssertionError('offline CLI attempted network')
socket.create_connection=denied; socket.socket.connect=denied; socket.getaddrinfo=denied
class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name.split('.')[0] in ('openai','typesafe','anthropic','llm_router_eval'):
            raise AssertionError('offline CLI attempted SDK/owner import')
sys.meta_path.insert(0,Guard())
from changelog_advisor.__main__ import main
for label,extra,expected in [('normal',[],0),('refusal',['--refusal'],3)]:
    out=app/label
    code=main(['demo',*extra,'--out',str(out)])
    assert code==expected,(label,code)
    report=json.loads((out/'checklist.json').read_text())
    assert report['counts']['packages']==5 and report['counts']['advisory_records']==2
    assert report['provider_calls']==0
    assert (out/'checklist.md').is_file() and (out/'checklist.html').is_file()
for name,module in tuple(sys.modules.items()):
    if name=='changelog_advisor' or name.startswith('changelog_advisor.'):
        Path(module.__file__).resolve().relative_to(app/'src')
print(json.dumps({'normal_exit':0,'refusal_exit':3,'owner_imports':0,'provider_calls':0}))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(app), str(root)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        # Two local demos can outlast 90s when semver calls are slow but still bounded.
        timeout=240,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout.splitlines()[-1]) == {
        "normal_exit": 0,
        "refusal_exit": 3,
        "owner_imports": 0,
        "provider_calls": 0,
    }
