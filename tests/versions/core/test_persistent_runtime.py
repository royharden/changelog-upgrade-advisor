"""what_bug_this_catches: reused npm IPC escapes its deadline, framing or cleanup bounds."""

import json
import queue
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from changelog_advisor.shared.versions import runtime as module
from changelog_advisor.shared.versions.runtime import NodeSemver, VersionRuntimeError, _Worker


def response(payload, **overrides):
    request = json.loads(payload)
    value = {
        "protocol_version": 1,
        "request_id": request["request_id"],
        "ok": True,
        "result": [],
    }
    value.update(overrides)
    return 0, json.dumps(value).encode()


def test_actual_lazy_repeated_oracle_and_owned_close(monkeypatch, record_property):
    original = subprocess.Popen
    launches = []

    def launch(*args, **kwargs):
        assert kwargs["shell"] is False
        assert "NODE_OPTIONS" not in kwargs["env"]
        child = original(*args, **kwargs)
        launches.append(child)
        return child

    monkeypatch.setattr(subprocess, "Popen", launch)
    monkeypatch.setenv("NODE_OPTIONS", "synthetic forbidden loader")
    oracle = NodeSemver()
    assert launches == [] and oracle._worker is None
    timings = []
    with oracle:
        for _ in range(3):
            start = time.monotonic()
            assert oracle.compare_pairs([("1.9.0", "1.10.0"), ("1.0.0+a", "1.0.0+b")]) == [-1, 0]
            timings.append(time.monotonic() - start)
        assert len(launches) == 1
        assert oracle.validate_many(["1.0.0-beta", "invalid"])[1]["valid"] is False
        assert oracle.satisfies_many([("1.0.0-beta", ">=0.0.0")])[0]["satisfies"] is False
        worker = oracle._worker
    assert launches[0].poll() is not None and not worker.pending
    oracle.close()
    with pytest.raises(VersionRuntimeError, match="closed"):
        oracle.sort([])
    record_property("actual_request_seconds", json.dumps(timings))
    record_property("actual_owned_launches", len(launches))


def test_actual_original_eof_single_object_helper_compatibility():
    node = module.shutil.which("node.exe" if module.os.name == "nt" else "node")
    helper = Path(module.__file__).with_name("semver.mjs")
    payload = json.dumps(
        {
            "protocol_version": 1,
            "request_id": "eof-control",
            "operation": "compare_pairs",
            "args": {"pairs": [["1.9.0", "1.10.0"]]},
        }
    ).encode()
    code, raw = module._transport(node, helper, payload)
    assert code == 0 and json.loads(raw)["result"] == [-1]


def test_partial_writer_sends_entire_large_frame_before_success():
    worker = _Worker()
    received = bytearray()

    class PartialPipe:
        def write(self, body):
            part = bytes(body[:7])
            received.extend(part)
            if received.endswith(b"\n"):
                worker.response.put(b"{}")
            return len(part)

    worker.process = SimpleNamespace(stdin=PartialPipe())
    payload = b"x" * 64000
    assert worker.exchange(payload, time.monotonic() + 5) == (0, b"{}")
    assert received == payload + b"\n" and not any(t.is_alive() for t in worker.threads)


@pytest.mark.parametrize("fault", ["wrong_id", "extra_field", "duplicate", "too_large"])
def test_corrupt_responses_refused_and_context_aborted(fault):
    oracle = NodeSemver()

    def transport(node, helper, payload):
        if fault == "wrong_id":
            return response(payload, request_id="wrong")
        if fault == "extra_field":
            return response(payload, action="execute")
        if fault == "duplicate":
            return 0, b'{"ok":true,"ok":false}'
        return 0, b"x" * (module.MAX_ENVELOPE + 1)

    oracle._transport = transport
    with pytest.raises(VersionRuntimeError):
        oracle.validate_many([])
    oracle.close()


def test_result_validation_stays_inside_whole_operation_deadline(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    oracle = NodeSemver()

    def transport(node, helper, payload):
        result = response(payload)
        clock[0] += 30.01
        return result

    oracle._transport = transport
    with pytest.raises(VersionRuntimeError, match="timeout"):
        oracle.validate_many([])
    oracle.close()


def test_lock_wait_has_deadline_and_never_launches(monkeypatch):
    class Busy:
        def acquire(self, timeout):
            assert 0 < timeout <= 30
            return False

    oracle = NodeSemver()
    # Real calls use the 30s bound. This fingerprint only keeps the test off
    # the cold-start branch; it still must not launch a process.
    oracle._fingerprint = b"steady"
    oracle._lock = Busy()
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("busy context launched"))
    with pytest.raises(VersionRuntimeError, match="timeout"):
        oracle.validate_many([])


def test_dependency_drift_refused_before_worker_creation(monkeypatch):
    oracle = NodeSemver()
    oracle._fingerprint = b"original"
    monkeypatch.setattr(module, "_identity", lambda helper: b"changed")
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("drift started worker"))
    with pytest.raises(VersionRuntimeError, match="dependency_changed"):
        oracle.validate_many([])
    assert oracle._worker is None
    oracle.close()


def test_request_limit_retires_owned_worker_after_validation(monkeypatch):
    class Worker:
        def __init__(self):
            self.requests = 999
            self.started = time.monotonic()
            self.cancelled = SimpleNamespace(is_set=lambda: False)
            self.pending = True
            self.process = None

        def start(self, *a):
            pass

        def exchange(self, payload, deadline):
            self.requests += 1
            return response(payload)

        def stop(self):
            self.pending = False

    monkeypatch.setattr(module, "_Worker", Worker)
    monkeypatch.setattr(module, "_identity", lambda helper: b"same")
    oracle = NodeSemver()
    assert oracle.validate_many([]) == [] and oracle._worker is None
    assert oracle.validate_many([]) == [] and oracle._worker is None
    oracle.close()


def test_explicit_pending_termination_refuses_new_process(monkeypatch):
    oracle = NodeSemver()
    pending = SimpleNamespace(
        stop=lambda: None, pending=True, process=SimpleNamespace(poll=lambda: None, pid=98765)
    )
    oracle._worker = pending
    oracle._abort()
    assert oracle.pending_pids == {98765}
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("pending process bypass"))
    with pytest.raises(VersionRuntimeError, match="cleanup_pending"):
        oracle.validate_many([])
    with pytest.raises(VersionRuntimeError, match="cleanup_pending"):
        oracle.close()


@pytest.mark.parametrize(
    "fault", ["two_frames", "trailing_bytes", "oversize", "stderr", "eof", "lifetime"]
)
def test_actual_reader_loops_reject_flood_trailing_and_eof(monkeypatch, fault):
    class ReadPipe:
        def __init__(self):
            self.chunks = queue.Queue()

        def read(self, limit):
            return self.chunks.get()

        def close(self):
            pass

    class Process:
        pid = 98766  # Synthetic owned process object; no OS PID is acted on.

        def __init__(self):
            self.stdout, self.stderr = ReadPipe(), ReadPipe()
            self.stdin = self
            self.dead = False

        def write(self, body):
            if fault == "stderr":
                self.stderr.chunks.put(b"x" * 8193)
            elif fault == "eof":
                self.stdout.chunks.put(b"")
            else:
                self.stdout.chunks.put(
                    {
                        "two_frames": b"{}\n{}\n",
                        "trailing_bytes": b"{}\npartial",
                        "oversize": b"x" * (module.MAX_ENVELOPE + 1),
                    }[fault]
                )
            return len(body)

        def kill(self):
            self.dead = True
            self.stdout.chunks.put(b"")
            self.stderr.chunks.put(b"")

        def poll(self):
            return 0 if self.dead else None

        def wait(self, timeout):
            return self.poll()

        def close(self):
            pass

    process = Process()
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
    worker = _Worker()
    try:
        worker.start("test-only", Path("test-only"), time.monotonic() + 5)
        assert 119 < worker.timer.interval <= 120
        if fault == "lifetime":
            worker.timer.function(*worker.timer.args)
        with pytest.raises(VersionRuntimeError):
            worker.exchange(b"{}", time.monotonic() + 5)
    finally:
        worker.stop()
    assert process.dead and not worker.pending


def test_startup_timeout_retains_launch_until_actual_late_cleanup(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    closed = []

    class LateProcess:
        pid = 98767  # Synthetic process object; no foreign OS PID lookup or kill.
        stdin = stdout = stderr = SimpleNamespace(close=lambda: closed.append(True))
        dead = False

        def kill(self):
            self.dead = True

        def wait(self, timeout):
            return 0

        def poll(self):
            return 0 if self.dead else None

    process = LateProcess()

    def launch(*args, **kwargs):
        entered.set()
        assert release.wait(2)
        return process

    monkeypatch.setattr(subprocess, "Popen", launch)
    worker = _Worker()
    try:
        with pytest.raises(VersionRuntimeError, match="startup_pending"):
            worker.start("test-only", Path("test-only"), time.monotonic() + 0.05)
        assert entered.is_set() and worker.pending and worker.process is None
    finally:
        release.set()
        worker.stop()
    assert process.dead and not worker.pending and len(closed) == 3


def test_helper_and_actual_dependency_file_changes_change_identity(tmp_path):
    module_dir = tmp_path / "node_modules/semver"
    module_dir.mkdir(parents=True)
    (module_dir / "package.json").write_text('{"version":"7.8.5"}', encoding="utf8")
    dependency = module_dir / "index.js"
    dependency.write_text("// first pinned bytes", encoding="utf8")
    helper = tmp_path / "semver.mjs"
    helper.write_text("// first helper bytes", encoding="utf8")
    first = module._identity(helper)
    helper.write_text("// changed helper bytes", encoding="utf8")
    second = module._identity(helper)
    dependency.write_text("// changed dependency bytes", encoding="utf8")
    third = module._identity(helper)
    assert len({first, second, third}) == 3


def test_concurrent_operations_are_serialized_and_close_on_exception(monkeypatch):
    oracle = NodeSemver()
    entered = threading.Event()
    released = threading.Event()
    calls = []

    def transport(node, helper, payload):
        calls.append(json.loads(payload)["request_id"])
        if len(calls) == 1:
            entered.set()
            assert released.wait(2)
        return response(payload)

    oracle._transport = transport
    errors = []

    def run():
        try:
            assert oracle.validate_many([]) == []
        except Exception as error:
            errors.append(error)

    first = threading.Thread(target=run)
    second = threading.Thread(target=run)
    first.start()
    assert entered.wait(2)
    second.start()
    assert len(calls) == 1
    released.set()
    first.join(3)
    second.join(3)
    assert not first.is_alive() and not second.is_alive() and not errors
    assert len(calls) == 2 and calls[0] != calls[1]
    with pytest.raises(ValueError, match="exception control"), oracle:
        raise ValueError("exception control")
    assert oracle._closed
