"""what_bug_this_catches: moved parser/citation bridge imports owner or loses exact source."""

import json
import shutil
import subprocess
import sys
from pathlib import Path


def test_detached_parser_and_optional_source_bridge(tmp_path):
    root = Path(__file__).resolve().parents[2]
    base = tmp_path / "renamed" / "shared"
    base.mkdir(parents=True)
    (base / "__init__.py").write_text("", encoding="utf8")
    (base.parent / "__init__.py").write_text("", encoding="utf8")
    for component, names in {
        "versions": (
            "__init__.py",
            "models.py",
            "runtime.py",
            "semver.mjs",
            "changelog.py",
            "sources.py",
        ),
        "cited": (
            "__init__.py",
            "models.py",
            "registry.py",
            "schema.py",
            "memory.py",
            "assessment.py",
        ),
    }.items():
        destination = base / component
        destination.mkdir()
        for name in names:
            shutil.copyfile(
                root / "src/changelog_advisor/shared" / component / name, destination / name
            )
    shutil.copytree(root / "node_modules/semver", tmp_path / "node_modules/semver")
    assert (tmp_path / "node_modules/semver/LICENSE").is_file()
    script = r"""
import sys,socket,subprocess,json
from pathlib import Path
owner=Path(sys.argv[2]).resolve()
sys.path=[p for p in sys.path if Path(p).resolve() not in (owner,owner/'src')]
sys.path.insert(0,sys.argv[1])
def denied(*a,**kw):raise AssertionError('unexpected process/network')
original=subprocess.Popen;subprocess.Popen=denied;socket.create_connection=denied
socket.socket.connect=denied
from renamed.shared.versions.changelog import parse_changelog,select_spans
from renamed.shared.versions.sources import make_span_source,span_pointer
from renamed.shared.versions.runtime import NodeSemver
from renamed.shared.cited import Registry,ArtifactRef,ResolutionContext,Finding
from renamed.shared.cited.memory import MemoryTextResolver,install_supplied_text
from renamed.shared.cited.assessment import assess_required_evidence
subprocess.Popen=original
with NodeSemver() as oracle:
 notes=parse_changelog('## 1.2.3\r\n- Removed é\r\n'.encode(),'demo',oracle)
assert notes.status=='ready'
source=make_span_source(notes,notes.spans,namespace_id='namespace',source_id='notes')
pointer=span_pointer(source,notes.spans[0])
class Access:
 reference=ArtifactRef(artifact_id='access',artifact_sha256='a'*64,profile_id='access/1')
 def decision(self,*a):return 'allow'
class Generation:
 reference=ArtifactRef(artifact_id='generation',artifact_sha256='b'*64,profile_id='generation/1')
 def current(self,*a):return source.metadata
registry=Registry();install_supplied_text(registry,MemoryTextResolver((source,),access=Access(),generation=Generation()))
context=ResolutionContext(namespace_id='namespace',access_policy_ref=Access.reference,generation_policy_ref=Generation.reference,required_scope='text')
finding=Finding(id='entry',text='potential change',verdict='partial',evidence=(pointer,))
result=assess_required_evidence(finding,registry,context)
assert result.resolved_count==1 and result.finding.verdict=='partial'
assert result.resolutions[0].excerpt=='- Removed é\n'
foreign=context.model_copy(update={'namespace_id':'foreign'})
assert registry.resolve(pointer,foreign).status!='resolved'
assert not any(n.startswith('changelog_advisor') for n in sys.modules)
print(json.dumps({'owner_imports':0,'literal_resolutions':1,'semantic_verdict':'partial','network':0}))
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, str(tmp_path), str(root)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        encoding="utf8",
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "owner_imports": 0,
        "literal_resolutions": 1,
        "semantic_verdict": "partial",
        "network": 0,
    }
