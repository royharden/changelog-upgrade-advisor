"""what_bug_this_catches: saved-fragment export needs the app, network, Node or credentials."""

import json
import shutil
import subprocess
import sys
from pathlib import Path


def test_detached_fragment_resolution_and_required_evidence_downgrade(tmp_path):
    root = Path(__file__).resolve().parents[2]
    destination = tmp_path / "portable/cited"
    destination.mkdir(parents=True)
    (destination.parent / "__init__.py").write_text("", encoding="utf8")
    for name in (
        "__init__.py",
        "models.py",
        "registry.py",
        "rowcanonical.py",
        "memory.py",
        "assessment.py",
        "fragments.py",
    ):
        shutil.copyfile(root / "src/changelog_advisor/shared/cited" / name, destination / name)
    script = r"""
import hashlib,json,os,socket,subprocess,sys
from pathlib import Path
from pydantic import BaseModel
class Probe(BaseModel):
    n:int
assert Probe(n=1).n==1
owner=Path(sys.argv[2]).resolve()
sys.path=[p for p in sys.path if Path(p).resolve() not in (owner,owner/'src')]
sys.path.insert(0,sys.argv[1])
def denied(*a,**k): raise AssertionError('ungranted source/Node/network access')
old_getenv=os.getenv
def getenv(name,*a):
    if name=='PYDANTIC_DISABLE_PLUGINS': return old_getenv(name,*a)
    return denied()
os.getenv=getenv
socket.create_connection=denied;socket.socket.connect=denied
subprocess.run=denied;subprocess.Popen=denied
Path.read_bytes=denied;Path.read_text=denied
from portable.cited import ArtifactRef,Finding,Registry,ResolutionContext
from portable.cited.assessment import assess_required_evidence
from portable.cited.fragments import SavedWebSource,SavedFragmentResolver,install_saved_fragments
from portable.cited.memory import SectionSpan
from portable.cited.models import FragmentPointer,FragmentLocator
raw='Release\r\nLiteral é change\r\nOutside\r\n'.encode()
source=SavedWebSource.from_bytes(namespace_id='ns',source_id='capture',source_revision='r1',
    raw=raw,newline_policy='crlf-to-lf',fragments=(SectionSpan('anchor',2,2),))
class Policy:
    reference=ArtifactRef(artifact_id='p',artifact_sha256='a'*64,profile_id='p/1')
    def decision(self,namespace,identity):
        return 'allow' if (namespace,identity)==('ns','capture') else 'deny'
    def current(self,namespace,identity):
        return source.metadata if (namespace,identity)==('ns','capture') else None
p=Policy()
ctx=ResolutionContext(namespace_id='ns',access_policy_ref=p.reference,generation_policy_ref=p.reference)
registry=Registry();install_saved_fragments(registry,SavedFragmentResolver((source,),access=p,generation=p))
common=dict(kind='url#fragment',source_type='saved_web',locator_subtype='fragment',source_id='capture',
    source_revision='r1',source_sha256=source.metadata.source_sha256,
    evidence_artifact_sha256=source.metadata.evidence_artifact_sha256)
def ptr(quote):
    return FragmentPointer(**common,locator=FragmentLocator(fragment_id='anchor',quote=quote,
        excerpt_sha256=hashlib.sha256(quote.encode()).hexdigest()))
good,bad=ptr('Literal é'),ptr('Outside')
assert registry.resolve(good,ctx).excerpt=='Literal é'
assert registry.resolve(bad,ctx).status=='invalid'
finding=Finding(id='claim',text='Potential change',verdict='partial',evidence=(good,bad))
assessment=assess_required_evidence(finding,registry,ctx)
assert assessment.required_count==2 and assessment.resolved_count==1
assert assessment.finding.verdict=='unsupported'
for name in sys.modules:
    assert not name.startswith(('changelog_advisor','openai','typesafe','httpx','requests'))
print(json.dumps(dict(resolved=1,invalid=1,required=2,verdict='unsupported',owner_imports=0)))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(tmp_path), str(root)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf8",
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "resolved": 1,
        "invalid": 1,
        "required": 2,
        "verdict": "unsupported",
        "owner_imports": 0,
    }
