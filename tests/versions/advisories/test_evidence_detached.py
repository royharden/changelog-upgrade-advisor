"""what_bug_this_catches: optional advisory fidelity export needs owner app or npm execution."""

import json
import shutil
import subprocess
import sys
from pathlib import Path


def test_detached_advisory_evidence_without_node_owner_or_effects(tmp_path):
    root = Path(__file__).resolve().parents[3]
    package = tmp_path / "portable"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf8")
    closure = {
        "cited": (
            "__init__.py",
            "models.py",
            "rowcanonical.py",
            "registry.py",
            "memory.py",
            "assessment.py",
        ),
        "versions": (
            "__init__.py",
            "models.py",
            "manifest.py",
            "runtime.py",
            "advisories.py",
            "osv.py",
            "ghsa.py",
            "evidence.py",
        ),
    }
    for directory, names in closure.items():
        (package / directory).mkdir()
        for name in names:
            shutil.copyfile(
                root / "src/changelog_advisor/shared" / directory / name, package / directory / name
            )
    script = r"""
import hashlib,json,os,socket,subprocess,sys
from pathlib import Path
from pydantic import BaseModel
class Probe(BaseModel): n:int
assert Probe(n=1).n==1
owner=Path(sys.argv[2]).resolve()
sys.path=[p for p in sys.path if Path(p).resolve() not in (owner,owner/'src')]
sys.path.insert(0,sys.argv[1])
def denied(*a,**k):raise AssertionError('ungranted source/network/Node effect')
getenv=os.getenv
def guarded(name,*a):
    return getenv(name,*a) if name=='PYDANTIC_DISABLE_PLUGINS' else denied()
os.getenv=guarded
socket.create_connection=denied;socket.socket.connect=denied;socket.getaddrinfo=denied
subprocess.Popen=denied;subprocess.run=denied
Path.read_bytes=denied;Path.read_text=denied
from portable.cited import ArtifactRef,Finding,Registry,ResolutionContext
from portable.cited.assessment import assess_required_evidence
from portable.cited.models import AdvisoryPointer,AdvisoryLocator
from portable.versions.evidence import (
    AdvisorySource,AdvisoryRecordResolver,install_advisory_records,
)
from portable.versions.osv import normalize_osv
from portable.versions.ghsa import normalize_ghsa
records=(
 normalize_osv(b'{"id":"OSV-1","modified":"2026-10-15T00:00:00Z",'
     b'"summary":"literal OSV"}',origin='synthetic'),
 normalize_ghsa(b'{"ghsa_id":"GHSA-aaaa-bbbb-cccc","updated_at":"2026-10-15T00:00:00Z",'
     b'"summary":"literal GHSA"}',origin='synthetic'),
)
sources=tuple(AdvisorySource.from_record(r,namespace_id='ns') for r in records)
class Policy:
    reference=ArtifactRef(artifact_id='p',artifact_sha256='a'*64,profile_id='p/1')
    def decision(self,ns,identity):
        known=any(s.metadata.source_id==identity for s in sources)
        return 'allow' if ns=='ns' and known else 'deny'
    def current(self,ns,identity):
        return next((s.metadata for s in sources
            if ns=='ns' and s.metadata.source_id==identity),None)
p=Policy();registry=Registry()
install_advisory_records(registry,AdvisoryRecordResolver(sources,access=p,generation=p))
ctx=ResolutionContext(namespace_id='ns',access_policy_ref=p.reference,generation_policy_ref=p.reference)
def ptr(s,quote):
    return AdvisoryPointer(kind='advisory:id',source_type='advisory_record',locator_subtype='id',
      source_id=s.metadata.source_id,source_sha256=s.metadata.source_sha256,
      source_revision=s.metadata.source_revision,evidence_artifact_sha256=s.metadata.evidence_artifact_sha256,
      locator=AdvisoryLocator(advisory_id=s.record.id,quote=quote,
        excerpt_sha256=hashlib.sha256(quote.encode()).hexdigest()))
good=tuple(ptr(s,s.record.summary) for s in sources)
bad=ptr(sources[0],'missing quote')
assert all(registry.resolve(p,ctx).status=='resolved' for p in good)
assert registry.resolve(bad,ctx).status=='invalid'
f=Finding(id='claim',text='Potential impact',verdict='partial',evidence=(*good,bad))
a=assess_required_evidence(f,registry,ctx)
assert a.required_count==3 and a.resolved_count==2 and a.finding.verdict=='unsupported'
assert not any(n.startswith(('changelog_advisor','openai','typesafe')) for n in sys.modules)
print(json.dumps(dict(resolved=2,invalid=1,required=3,verdict='unsupported',node_calls=0)))
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
        "resolved": 2,
        "invalid": 1,
        "required": 3,
        "verdict": "unsupported",
        "node_calls": 0,
    }
