"""what_bug_this_catches: portable rendering needs its app or hides unsupported evidence."""

import json
import shutil
import subprocess
import sys
from pathlib import Path


def test_detached_renderer_from_actual_memory_assessment(tmp_path):
    root = Path(__file__).resolve().parents[2]
    destination = tmp_path / "portable/cited"
    destination.mkdir(parents=True)
    (destination.parent / "__init__.py").write_text("", encoding="utf8")
    for name in (
        "__init__.py",
        "models.py",
        "rowcanonical.py",
        "registry.py",
        "memory.py",
        "assessment.py",
        "markdown.py",
    ):
        shutil.copyfile(root / "src/changelog_advisor/shared/cited" / name, destination / name)
    script = r"""
import json,os,socket,subprocess,sys
from pathlib import Path
from pydantic import BaseModel
class Probe(BaseModel): n:int
assert Probe(n=1).n==1
owner=Path(sys.argv[2]).resolve()
sys.path=[p for p in sys.path if Path(p).resolve() not in (owner,owner/'src')]
sys.path.insert(0,sys.argv[1])
def denied(*a,**k):raise AssertionError('source/Node/network effect forbidden')
getenv=os.getenv
def guarded(name,*a):
    return getenv(name,*a) if name=='PYDANTIC_DISABLE_PLUGINS' else denied()
os.getenv=guarded
socket.create_connection=denied;socket.socket.connect=denied
subprocess.run=denied;subprocess.Popen=denied
Path.read_bytes=denied;Path.read_text=denied
from portable.cited import ArtifactRef,Finding,Registry,ResolutionContext
from portable.cited.assessment import assess_required_evidence
from portable.cited.markdown import render_assessment
from portable.cited.memory import MemorySource,MemoryTextResolver,install_supplied_text
from portable.cited.models import SuppliedLinePointer,LineLocator
s=MemorySource.from_bytes(namespace_id='ns',source_id='notes',source_revision='r1',
    raw=b'Literal <script>text</script>\n',newline_policy='identity')
class Policy:
    reference=ArtifactRef(artifact_id='p',artifact_sha256='a'*64,profile_id='p/1')
    def decision(self,n,i):return 'allow' if (n,i)==('ns','notes') else 'deny'
    def current(self,n,i):return s.metadata if (n,i)==('ns','notes') else None
p=Policy();ctx=ResolutionContext(namespace_id='ns',access_policy_ref=p.reference,
    generation_policy_ref=p.reference)
pointer=SuppliedLinePointer(kind='file:line',source_type='supplied_text',locator_subtype='line',
    source_id='notes',source_revision='r1',source_sha256=s.metadata.source_sha256,
    evidence_artifact_sha256=s.metadata.evidence_artifact_sha256,
    locator=LineLocator(line_start=1,line_end=1))
f=Finding(id='claim',text='Potential change',verdict='partial',evidence=(pointer,))
r=Registry();install_supplied_text(r,MemoryTextResolver((s,),access=p,generation=p))
supported=render_assessment(assess_required_evidence(f,r,ctx))
unsupported=render_assessment(assess_required_evidence(f,Registry(),ctx))
assert 'Verdict: partial' in supported and '&lt;script&gt;' in supported
assert '<script>' not in supported
assert 'Verdict: unsupported' in unsupported and 'unresolved 1' in unsupported
assert not any(n.startswith(('changelog_advisor','openai','typesafe')) for n in sys.modules)
print(json.dumps(dict(resolved=1,unresolved=1,owner_imports=0,node_calls=0)))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", script, str(tmp_path), str(root)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf8",
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "resolved": 1,
        "unresolved": 1,
        "owner_imports": 0,
        "node_calls": 0,
    }
