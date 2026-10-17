"""what_bug_this_catches: a vendored initializer eagerly loads the SDK worker's parent.

Fresh import graphs are separate controls, not native dispatch or latency proof.
"""

import hashlib
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import changelog_advisor

PACKAGE = Path(changelog_advisor.__file__).resolve().parent
PUBLIC_NAMES = [
    "FixtureIndex",
    "ContentValidator",
    "GenerationRepairPolicy",
    "ModelSupport",
    "Provider",
    "ProviderConfig",
    "ProviderError",
    "ProjectCredential",
    "SDKTransport",
    "TransportFailure",
    "TransportReply",
    "build_generation_repair_request",
    "models",
]


def fresh_graph(body):
    """Import the parent-selected source edition in a fresh bounded interpreter."""
    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "PATH", "TEMP", "TMP"}
    }
    env.update(
        PYTHONPATH=str(PACKAGE.parent),
        PYTHONDONTWRITEBYTECODE="1",
        PYTHONUTF8="1",
        ADVISOR_TEST_PACKAGE=str(PACKAGE),
    )
    prelude = """
import hashlib
import importlib
import json
import os
import socket
import sys
from pathlib import Path

def denied(*args, **kwargs):
    raise AssertionError("fresh graph control attempted network")

socket.create_connection = denied
socket.socket.connect = denied
socket.getaddrinfo = denied
expected = Path(os.environ["ADVISOR_TEST_PACKAGE"]).resolve()
public_names = PUBLIC_NAMES_VALUE
prefix = "changelog_advisor.shared.providers"
heavy = [prefix + ".controller", prefix + ".models", prefix + ".sdk",
         "changelog_advisor.shared.callledger", "pydantic", "openai", "typesafe_sdk", "httpx2"]

def assert_light():
    present = [name for name in sys.modules
               if any(name == item or name.startswith(item + ".") for item in heavy)]
    assert not present, present

def pin(module):
    path = Path(module.__file__).resolve()
    assert path.is_relative_to(expected), (path, expected)
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

def emit(kind, modules):
    print(json.dumps({"kind": kind, "pid": os.getpid(), "python": sys.executable,
                      "package": str(expected),
                      "origins": {name: pin(mod) for name, mod in modules.items()},
                      "module_graph": sorted(sys.modules)}))
""".replace("PUBLIC_NAMES_VALUE", repr(PUBLIC_NAMES))
    program = prelude + textwrap.dedent(body)
    process = subprocess.Popen(
        [sys.executable, "-B", "-c", program],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    try:
        stdout, stderr = process.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=5)
        raise AssertionError("fresh graph control exceeded 20 seconds") from None
    assert process.returncode == 0, stderr.decode("utf-8", errors="replace")
    record = json.loads(stdout)
    record.update(
        launcher_pid=process.pid,
        launcher_exit_code=process.returncode,
        program_sha256=hashlib.sha256(program.encode()).hexdigest(),
    )
    return record


def test_bare_provider_package_preserves_lazy_graph(record_property):
    """what_bug_this_catches: package import/dir/unknown attributes load heavy parents."""
    record = fresh_graph("""
        import changelog_advisor.shared.providers as providers
        assert providers.__all__ == public_names
        assert set(public_names) <= set(dir(providers))
        assert_light()
        try:
            providers.this_export_does_not_exist
        except AttributeError:
            pass
        else:
            raise AssertionError("unknown export accepted")
        assert_light()
        emit("bare-provider-import", {"providers": providers})
    """)
    record_property("fresh_graph", json.dumps(record, sort_keys=True))


def test_fresh_sdk_worker_import_graph_and_source_origin(record_property):
    """what_bug_this_catches: importing the worker loads controller/accounting/SDKs."""
    record = fresh_graph("""
        import changelog_advisor.shared.providers as providers
        import changelog_advisor.shared.providers.sdk_worker as worker
        assert_light()
        emit("worker-module-import-only", {"providers": providers, "worker": worker})
    """)
    record_property("fresh_graph", json.dumps(record, sort_keys=True))


def test_all_public_exports_preserve_canonical_identity(record_property):
    """what_bug_this_catches: lazy exports drop/recreate classes or change models identity."""
    record = fresh_graph("""
        import changelog_advisor.shared.providers as providers
        from changelog_advisor.shared.providers import *
        contract = {
            "FixtureIndex": "captures", "ContentValidator": "repair",
            "GenerationRepairPolicy": "repair", "ModelSupport": "adapters",
            "Provider": "controller", "ProviderConfig": "adapters", "ProviderError": "controller",
            "ProjectCredential": "sdk", "SDKTransport": "sdk", "TransportFailure": "controller",
            "TransportReply": "controller", "build_generation_repair_request": "repair",
            "models": "models",
        }
        assert providers.__all__ == public_names
        origins = {"providers": providers}
        for name, leaf in contract.items():
            module = importlib.import_module(prefix + "." + leaf)
            expected_object = module if name == "models" else getattr(module, name)
            assert getattr(providers, name) is expected_object
            assert getattr(providers, name) is getattr(providers, name)
            assert globals()[name] is expected_object
            origins[leaf] = module
        emit("public-canonical-identity", origins)
    """)
    record_property("fresh_graph", json.dumps(record, sort_keys=True))
