"""what_bug_this_catches: a vendored initializer eagerly loads the SDK worker's parent.

Fresh import graphs are separate controls, not native dispatch or latency proof.
"""

import hashlib
import json
import os
import signal
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

import changelog_advisor
from changelog_advisor.shared.providers.sdk import _WindowsJob

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


class GraphRunError(AssertionError):
    """A failed graph control retains its actual custody observation."""

    def __init__(self, message, observation):
        super().__init__(message)
        self.observation = observation


class GraphTimeout(GraphRunError):
    pass


class GraphCleanupError(GraphRunError):
    pass


def owned_graph(program, env):
    """Own before execution; always reap independently of kill/poll success."""
    started = time.monotonic()
    job = process = None
    assigned = timed_out = reaped = False
    active_after = total_members = None
    members_before = None
    execution_error = None
    errors, readers, chunks = [], [], {}

    def read_pipe(name, pipe):
        try:
            chunks[name] = pipe.read(262145)
        except (OSError, ValueError) as exc:
            errors.append(f"{name}_read:{type(exc).__name__}")

    try:
        if os.name == "nt":
            job = _WindowsJob()
            flags = {"creationflags": subprocess.CREATE_NO_WINDOW | 0x00000004}
        elif os.name == "posix" and hasattr(os, "waitid"):
            flags = {"start_new_session": True}
        else:
            raise RuntimeError("owned graph controls need Job or POSIX waitid")
        process = subprocess.Popen(
            [sys.executable, "-B", "-c", program],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            **flags,
        )
        if job is not None:
            job.assign(process)
            assigned = True
        for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
            reader = threading.Thread(target=read_pipe, args=(name, pipe), daemon=True)
            readers.append(reader)
            reader.start()
        if job is not None:
            process.wait(timeout=max(0.001, 20 - (time.monotonic() - started)))
        else:
            # Keep the session leader unreaped until group termination. Its PID
            # cannot be reused to identify somebody else's process group.
            while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is None:
                if time.monotonic() - started >= 20:
                    raise subprocess.TimeoutExpired(process.args, 20)
                time.sleep(0.005)
    except subprocess.TimeoutExpired:
        timed_out = True
    except Exception as exc:
        execution_error = f"{type(exc).__name__}:{exc}"
    finally:
        operation_elapsed = time.monotonic() - started
        cleanup_started = time.monotonic()
        if job is not None:
            try:
                status = job.Accounting()
                if not job.k.QueryInformationJobObject(
                    job.handle, 1, job.ctypes.byref(status), job.ctypes.sizeof(status), None
                ):
                    raise OSError("Job accounting query failed")
                total_members = status.total
                raw = job.ctypes.create_string_buffer(
                    8 + job.ctypes.sizeof(job.ctypes.c_size_t) * 16
                )
                if job.k.QueryInformationJobObject(
                    job.handle, 3, raw, job.ctypes.sizeof(raw), None
                ):
                    assigned_count = job.ctypes.c_uint32.from_buffer(raw, 0).value
                    listed_count = job.ctypes.c_uint32.from_buffer(raw, 4).value
                    members_before = {
                        "assigned": assigned_count,
                        "listed": listed_count,
                        "pids": list((job.ctypes.c_size_t * listed_count).from_buffer(raw, 8))
                        if listed_count <= 16
                        else [],
                        "complete": assigned_count == listed_count and listed_count <= 16,
                    }
                else:
                    members_before = {"complete": False, "error": "Job PID-list query failed"}
            except Exception as exc:
                errors.append(f"job_accounting:{type(exc).__name__}")
            try:
                active_after = job.close()
            except Exception as exc:
                errors.append(f"job_close:{type(exc).__name__}")
        if process is not None:
            try:
                if job is not None:
                    # Direct handle ownership also covers assignment failure
                    # while this launcher is still suspended and unassigned.
                    process.kill()
                else:
                    os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except Exception as exc:
                errors.append(f"launcher_kill:{type(exc).__name__}")
            try:
                # Never make this wait conditional on kill() or poll().
                process.wait(timeout=max(0.001, min(5, 20 - (time.monotonic() - cleanup_started))))
                reaped = process.returncode is not None
            except Exception as exc:
                errors.append(f"launcher_reap:{type(exc).__name__}")
            reader_deadline = min(cleanup_started + 20, time.monotonic() + 5)
            for reader in readers:
                reader.join(timeout=max(0, reader_deadline - time.monotonic()))
                if reader.is_alive():
                    errors.append("pipe_reader_not_joined")
            if not any(reader.is_alive() for reader in readers):
                for pipe in (process.stdout, process.stderr):
                    try:
                        pipe.close()
                    except Exception as exc:
                        errors.append(f"pipe_close:{type(exc).__name__}")
        cleanup_elapsed = time.monotonic() - cleanup_started
        if cleanup_elapsed > 20:
            errors.append("cleanup_deadline_exceeded")
    observation = {
        "launcher_pid": process.pid if process is not None else None,
        "launcher_exit_code": process.returncode if process is not None else None,
        "launcher_reaped": reaped,
        "assigned_before_execution": assigned,
        "containment": "windows-job" if job is not None else "posix-session",
        "active_owned_processes_after": active_after,
        "total_job_members_observed": total_members,
        "job_members_before_close": members_before,
        "owned_tree_closed": reaped and not errors and (job is None or active_after == 0),
        "timed_out": timed_out,
        "operation_limit_seconds": 20,
        "operation_elapsed_seconds": operation_elapsed,
        "cleanup_limit_seconds": 20,
        "cleanup_elapsed_seconds": cleanup_elapsed,
        "cleanup_errors": errors,
        "execution_error": execution_error,
        "program_sha256": hashlib.sha256(program.encode()).hexdigest(),
        "stdout": chunks.get("stdout", b"").decode("utf-8", errors="replace"),
        "stderr": chunks.get("stderr", b"").decode("utf-8", errors="replace"),
    }
    if errors or not observation["owned_tree_closed"]:
        raise GraphCleanupError("graph cleanup could not be established", observation)
    if timed_out:
        raise GraphTimeout("fresh graph control exceeded 20 seconds", observation)
    if execution_error or process.returncode:
        raise GraphRunError("graph process failed", observation)
    if any(len(value) > 262144 for value in chunks.values()):
        raise GraphRunError("graph output exceeded control bound", observation)
    return observation


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
    execution = owned_graph(program, env)
    record = json.loads(execution["stdout"])
    record.update(execution)
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


def test_graph_timeout_closes_interpreter_and_descendant(record_property):
    """what_bug_this_catches: a timed-out launcher leaves descendants holding pipes."""
    with pytest.raises(GraphTimeout) as caught:
        fresh_graph("""
            import subprocess
            import time
            descendant = (
                "import json,os,time; "
                "print(json.dumps({'probe':'descendant', 'pid':os.getpid()}), flush=True); "
                "time.sleep(60)"
            )
            subprocess.Popen([sys.executable, "-B", "-c", descendant],
                stdout=sys.stdout, stderr=sys.stderr,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            print(json.dumps({"probe": "interpreter", "pid": os.getpid()}), flush=True)
            time.sleep(60)
        """)
    observed = caught.value.observation
    record_property("graph_timeout", json.dumps(observed, sort_keys=True))
    probes = [json.loads(line) for line in observed["stdout"].splitlines()]
    assert {row["probe"] for row in probes} == {"interpreter", "descendant"}
    assert len({row["pid"] for row in probes}) == 2
    assert observed["timed_out"] and observed["launcher_reaped"]
    assert observed["owned_tree_closed"] and not observed["cleanup_errors"]
    assert observed["operation_limit_seconds"] == 20
    if os.name == "nt":
        assert observed["assigned_before_execution"]
        assert observed["active_owned_processes_after"] == 0
        assert observed["total_job_members_observed"] >= 3


def test_graph_program_error_still_closes_owned_tree(record_property):
    """what_bug_this_catches: a nonzero graph exit bypasses owned cleanup/reaping."""
    with pytest.raises(GraphRunError) as caught:
        fresh_graph("raise RuntimeError('authored graph control failure')")
    observed = caught.value.observation
    assert observed["launcher_exit_code"] != 0 and not observed["timed_out"]
    assert observed["launcher_reaped"] and observed["owned_tree_closed"]
    assert "authored graph control failure" in observed["stderr"]
    record_property("graph_program_error", json.dumps(observed, sort_keys=True))


@pytest.mark.skipif(os.name != "nt", reason="Windows Job error-control contract")
def test_job_close_error_fails_closed_but_launcher_is_reaped(monkeypatch, record_property):
    """what_bug_this_catches: cleanup uncertainty becomes success or skips reaping."""
    closed = []

    class UncertainClose(_WindowsJob):
        def close(self):
            closed.append(super().close())
            raise OSError("authored close-observation failure")

    monkeypatch.setattr(sys.modules[__name__], "_WindowsJob", UncertainClose)
    with pytest.raises(GraphCleanupError) as caught:
        fresh_graph("print('{}')")
    observed = caught.value.observation
    assert closed == [0] and observed["launcher_reaped"]
    assert observed["active_owned_processes_after"] is None
    assert not observed["owned_tree_closed"]
    assert "job_close:OSError" in observed["cleanup_errors"]
    record_property("graph_cleanup_error", json.dumps(observed, sort_keys=True))


@pytest.mark.skipif(os.name != "nt", reason="Windows handle wait remains independent of kill/poll")
def test_kill_and_poll_errors_cannot_skip_independent_reap(monkeypatch, record_property):
    """what_bug_this_catches: kill/poll failure short-circuits the final handle wait."""
    actual_popen = subprocess.Popen
    waited = []

    def launch(*args, **kwargs):
        process = actual_popen(*args, **kwargs)
        actual_wait = process.wait

        def wait(*args, **kwargs):
            waited.append(True)
            return actual_wait(*args, **kwargs)

        def denied(*args, **kwargs):
            raise OSError("authored kill/poll observation failure")

        process.wait = wait
        process.kill = process.poll = denied
        return process

    monkeypatch.setattr(subprocess, "Popen", launch)
    with pytest.raises(GraphCleanupError) as caught:
        fresh_graph("print('{}')")
    observed = caught.value.observation
    assert len(waited) >= 2 and observed["launcher_reaped"]
    assert observed["active_owned_processes_after"] == 0
    assert not observed["owned_tree_closed"]
    assert "launcher_kill:OSError" in observed["cleanup_errors"]
    record_property("graph_kill_error", json.dumps(observed, sort_keys=True))


@pytest.mark.skipif(os.name != "nt", reason="Windows pre-execution suspended assignment")
def test_assignment_error_reaps_unassigned_suspended_launcher(monkeypatch, record_property):
    """what_bug_this_catches: failed Job assignment leaves a suspended launcher alive."""

    class AssignmentFailure(_WindowsJob):
        def assign(self, process):
            raise OSError("authored Job assignment failure")

    monkeypatch.setattr(sys.modules[__name__], "_WindowsJob", AssignmentFailure)
    with pytest.raises(GraphRunError) as caught:
        fresh_graph("raise AssertionError('unassigned launcher must not execute')")
    observed = caught.value.observation
    assert not observed["assigned_before_execution"]
    assert observed["total_job_members_observed"] == 0
    assert observed["active_owned_processes_after"] == 0
    assert observed["launcher_reaped"] and observed["owned_tree_closed"]
    assert observed["stdout"] == observed["stderr"] == ""
    assert "authored Job assignment failure" in observed["execution_error"]
    record_property("graph_assignment_error", json.dumps(observed, sort_keys=True))
