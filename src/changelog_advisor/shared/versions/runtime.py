"""Bounded fixed-helper IPC; imports never start Node. No Python version comparator."""

import hashlib
import json
import os
import queue
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path

MAX_ENVELOPE = 2 * 1024 * 1024


class VersionRuntimeError(RuntimeError):
    def __init__(self, reason: str, pending_pid: int | None = None):
        super().__init__(reason)
        self.reason = reason
        self.pending_pid = pending_pid


def _json(raw: bytes):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate protocol field")
            result[key] = value
        return result

    def bad_constant(value):
        raise ValueError("nonfinite protocol number")

    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=bad_constant)


def _transport(node: str, helper: Path, payload: bytes) -> tuple[int, bytes]:
    started = time.monotonic()
    # Do not propagate secret environment variables, NODE_OPTIONS/DEBUG/PATH loaders.
    env = {
        name: value
        for name in ("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "TEMP", "TMP")
        if (value := os.environ.get(name)) is not None
    }
    process = subprocess.Popen(
        [node, str(helper)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        env=env,
        bufsize=0,
    )
    over = threading.Event()
    stream_error = threading.Event()
    output: list[bytes] = []

    def read(stream, limit, capture):
        total = 0
        try:
            while chunk := stream.read(16384):
                total += len(chunk)
                if total > limit:
                    over.set()
                    try:
                        process.kill()
                    except OSError:
                        pass
                    break
                if capture:
                    output.append(chunk)
        except (OSError, ValueError):
            stream_error.set()

    def write():
        try:
            remaining = memoryview(payload)
            while remaining:
                written = process.stdin.write(remaining)
                if not written:
                    raise OSError("short protocol write")
                remaining = remaining[written:]
            process.stdin.close()
        except (BrokenPipeError, OSError):
            pass

    threads = [
        threading.Thread(target=read, args=(process.stdout, MAX_ENVELOPE, True), daemon=True),
        threading.Thread(target=read, args=(process.stderr, 8192, False), daemon=True),
        threading.Thread(target=write, daemon=True),
    ]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        process.wait(timeout=max(0, 5 - (time.monotonic() - started)))
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            # An asynchronous OS termination must not escape as success or raw traceback.
            pass
    finally:
        for thread in threads:
            thread.join(timeout=1)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
    if timed_out:
        pending = process.pid if process.poll() is None else None
        raise VersionRuntimeError(
            "version_runtime_cleanup_pending" if pending else "version_runtime_timeout",
            pending_pid=pending,
        )
    if over.is_set():
        raise VersionRuntimeError("version_runtime_output_limit")
    if stream_error.is_set() or any(thread.is_alive() for thread in threads):
        raise VersionRuntimeError("version_runtime_stream_error")
    return process.returncode, b"".join(output)


def _remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise VersionRuntimeError("version_runtime_timeout")
    return value


def _operation(method):
    """One deadline covers validation, lock, startup, IO and result validation."""

    def run(self, *args, **kwargs):
        deadline = time.monotonic() + 5
        if not self._lock.acquire(timeout=_remaining(deadline)):
            raise VersionRuntimeError("version_runtime_timeout")
        self._local.deadline = deadline
        try:
            result = method(self, *args, **kwargs)
            _remaining(deadline)
            if self._worker is not None and self._worker.requests >= 1000:
                self._abort()
                if self._worker is not None:
                    raise VersionRuntimeError("version_runtime_cleanup_pending")
                _remaining(deadline)
            return result
        except VersionRuntimeError as error:
            self._abort()
            if error.pending_pid is not None:
                self.pending_pids.add(error.pending_pid)
            raise
        finally:
            self._local.deadline = None
            self._lock.release()

    return run


def _identity(helper):
    """Fixed helper and actual pinned npm module bytes; no configurable loader."""
    module = next(
        (
            p / "node_modules/semver"
            for p in helper.parents
            if (p / "node_modules/semver/package.json").is_file()
        ),
        None,
    )
    if module is None:
        raise VersionRuntimeError("version_runtime_unavailable")
    metadata = _json((module / "package.json").read_bytes())
    if metadata.get("version") != "7.8.5":
        raise VersionRuntimeError("version_runtime_dependency_changed")
    files = sorted(module.rglob("*.js")) + [module / "package.json"]
    if len(files) > 256:
        raise VersionRuntimeError("version_runtime_dependency_changed")
    digest = hashlib.sha256(helper.read_bytes())
    total = 0
    for path in files:
        if path.is_symlink() or path.resolve().is_relative_to(module.resolve()) is False:
            raise VersionRuntimeError("version_runtime_dependency_changed")
        body = path.read_bytes()
        total += len(body)
        if total > 4 * 1024 * 1024:
            raise VersionRuntimeError("version_runtime_dependency_changed")
        digest.update(str(path.relative_to(module)).encode("utf8"))
        digest.update(hashlib.sha256(body).digest())
    return digest.digest()


class _Worker:
    """Exactly one owned stdio process, bounded frames and explicit cleanup state."""

    def __init__(self):
        self.process = None
        self.threads = []
        self.cancelled = threading.Event()
        self.failed = threading.Event()
        self.response = queue.Queue(maxsize=1)
        self.active = False
        self.started = time.monotonic()
        self.requests = 0
        self.reason = "version_runtime_stream_error"
        self.timer = None

    @property
    def pending(self):
        return any(t.is_alive() for t in self.threads) or (
            self.process is not None and self.process.poll() is None
        )

    def stop(self):
        self.cancelled.set()
        if self.timer is not None:
            self.timer.cancel()
        p = self.process
        if p is not None:
            if p.poll() is None:
                try:
                    p.kill()
                except OSError:
                    pass
                try:
                    p.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
            # Closing a pipe whose writer is stuck can itself block: join first,
            # retain uncertain threads/process as pending rather than reuse it.
        deadline = time.monotonic() + 1
        for thread in self.threads:
            if thread is not threading.current_thread():
                thread.join(timeout=max(0, deadline - time.monotonic()))
        # A cancelled startup can finish while stop joins its launch thread.
        p = self.process
        if p is not None and p.poll() is not None and not any(t.is_alive() for t in self.threads):
            for stream in (p.stdin, p.stdout, p.stderr):
                stream.close()

    def fail(self, reason):
        self.reason = reason
        self.failed.set()
        if self.process is not None:
            try:
                self.process.kill()
            except OSError:
                pass
        try:
            self.response.put_nowait(None)
        except queue.Full:
            pass

    def start(self, node, helper, deadline):
        ready = threading.Event()

        def launch():
            try:
                env = {
                    name: value
                    for name in ("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "TEMP", "TMP")
                    if (value := os.environ.get(name)) is not None
                }
                self.process = subprocess.Popen(
                    [node, str(helper)],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                    env=env,
                    bufsize=0,
                )
                if self.cancelled.is_set():
                    self.process.kill()
                    self.process.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                self.failed.set()
            finally:
                ready.set()

        thread = threading.Thread(target=launch, daemon=True)
        self.threads.append(thread)
        thread.start()
        if not ready.wait(_remaining(deadline)):
            self.cancelled.set()
            raise VersionRuntimeError("version_runtime_startup_pending")
        if self.failed.is_set() or self.process is None:
            raise VersionRuntimeError("version_runtime_unavailable")

        def stdout():
            buffered = bytearray()
            try:
                while chunk := self.process.stdout.read(16384):
                    parts = chunk.split(b"\n")
                    for index, part in enumerate(parts):
                        buffered.extend(part)
                        if len(buffered) > MAX_ENVELOPE:
                            self.fail("version_runtime_output_limit")
                            return
                        if index < len(parts) - 1:
                            if not self.active or self.response.full():
                                self.fail("version_runtime_extra_frame")
                                return
                            if any(parts[index + 1 :]):
                                self.fail("version_runtime_extra_frame")
                                return
                            self.response.put_nowait(bytes(buffered))
                            buffered.clear()
                if not self.cancelled.is_set():
                    self.fail("version_runtime_unexpected_eof")
            except (OSError, ValueError, queue.Full):
                if not self.cancelled.is_set():
                    self.fail("version_runtime_stream_error")

        def stderr():
            count = 0
            try:
                while chunk := self.process.stderr.read(1024):
                    count += len(chunk)
                    if count > 8192:
                        self.fail("version_runtime_stderr_limit")
                        return
            except (OSError, ValueError):
                if not self.cancelled.is_set():
                    self.fail("version_runtime_stream_error")

        for target in (stdout, stderr):
            thread = threading.Thread(target=target, daemon=True)
            self.threads.append(thread)
            thread.start()
        self.timer = threading.Timer(
            max(0, 120 - (time.monotonic() - self.started)),
            self.fail,
            args=("version_runtime_lifetime",),
        )
        self.timer.daemon = True
        self.threads.append(self.timer)
        self.timer.start()

    def exchange(self, payload, deadline):
        if self.failed.is_set() or not self.response.empty():
            raise VersionRuntimeError(self.reason)
        self.active = True
        self.requests += 1

        def write():
            remaining = memoryview(payload + b"\n")
            try:
                while remaining:
                    _remaining(deadline)
                    written = self.process.stdin.write(remaining)
                    if not written:
                        raise OSError("short protocol write")
                    remaining = remaining[written:]
            except (OSError, ValueError, VersionRuntimeError):
                self.fail("version_runtime_write_error")

        thread = threading.Thread(target=write, daemon=True)
        # Finished writers do not accumulate across up to1000 operations.
        self.threads = [t for t in self.threads if t.is_alive()]
        self.threads.append(thread)
        thread.start()
        try:
            raw = self.response.get(timeout=_remaining(deadline))
            thread.join(timeout=_remaining(deadline))
            if thread.is_alive():
                raise VersionRuntimeError("version_runtime_timeout")
            if raw is None or self.failed.is_set():
                raise VersionRuntimeError(self.reason)
            _remaining(deadline)
            return 0, raw
        except queue.Empty:
            raise VersionRuntimeError("version_runtime_timeout") from None
        finally:
            self.active = False


class NodeSemver:
    def __init__(self):
        self._transport = self._exchange
        self.pending_pids: set[int] = set()
        self._worker = None
        self._fingerprint = None
        self._closed = False
        self._lock = threading.Lock()
        self._local = threading.local()

    def _abort(self):
        if self._worker is not None:
            self._worker.stop()
            if self._worker.pending:
                if self._worker.process is not None and self._worker.process.poll() is None:
                    self.pending_pids.add(self._worker.process.pid)
            else:
                if self._worker.process is not None:
                    self.pending_pids.discard(self._worker.process.pid)
                self._worker = None

    def close(self):
        if not self._lock.acquire(timeout=5):
            raise VersionRuntimeError("version_runtime_close_pending")
        try:
            self._closed = True
            self._abort()
            if self._worker is not None:
                raise VersionRuntimeError("version_runtime_cleanup_pending")
        finally:
            self._lock.release()

    def __enter__(self):
        if self._closed:
            raise VersionRuntimeError("version_runtime_closed")
        return self

    def __exit__(self, *args):
        self.close()

    def _exchange(self, node, helper, payload):
        deadline = self._local.deadline
        identity = _identity(helper)
        _remaining(deadline)
        if self._fingerprint is None:
            self._fingerprint = identity
        if identity != self._fingerprint:
            raise VersionRuntimeError("version_runtime_dependency_changed")
        if self._worker is not None:
            if self._worker.cancelled.is_set():
                raise VersionRuntimeError("version_runtime_cleanup_pending")
            if self._worker.requests >= 1000 or time.monotonic() - self._worker.started >= 120:
                self._abort()
                _remaining(deadline)
                if self._worker is not None:
                    raise VersionRuntimeError("version_runtime_cleanup_pending")
        if self._worker is None:
            self._worker = _Worker()
            self._worker.start(node, helper, deadline)
        return self._worker.exchange(payload, deadline)

    def _request(self, operation: str, args: dict):
        if self._closed:
            raise VersionRuntimeError("version_runtime_closed")
        if self.pending_pids:
            raise VersionRuntimeError("version_runtime_cleanup_pending")
        identifier = uuid.uuid4().hex
        payload = json.dumps(
            {"protocol_version": 1, "request_id": identifier, "operation": operation, "args": args},
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(payload) > MAX_ENVELOPE:
            raise VersionRuntimeError("version_runtime_request_limit")
        # Windows PATH may put node.CMD Python/network shims ahead of native Node.
        # A batch wrapper is not our fixed shell=False runtime executable.
        node = shutil.which("node.exe" if os.name == "nt" else "node")
        if node is None:
            raise VersionRuntimeError("version_runtime_unavailable")
        helper = Path(__file__).with_name("semver.mjs")
        try:
            code, raw = self._transport(node, helper, payload)
            if len(raw) > MAX_ENVELOPE:
                raise VersionRuntimeError("version_runtime_output_limit")
            response = _json(raw)
        except VersionRuntimeError as error:
            if error.pending_pid is not None:
                self.pending_pids.add(error.pending_pid)
            raise
        except subprocess.TimeoutExpired:
            raise VersionRuntimeError("version_runtime_timeout") from None
        except (OSError, ValueError, TypeError):
            raise VersionRuntimeError("version_runtime_malformed") from None
        if (
            type(response) is not dict
            or type(response.get("protocol_version")) is not int
            or response["protocol_version"] != 1
            or response.get("request_id") != identifier
            or type(response.get("ok")) is not bool
        ):
            raise VersionRuntimeError("version_runtime_protocol_error")
        if not response["ok"]:
            raise VersionRuntimeError("version_runtime_rejected")
        if code != 0 or set(response) != {"protocol_version", "request_id", "ok", "result"}:
            raise VersionRuntimeError("version_runtime_protocol_error")
        return response["result"]

    @staticmethod
    def _strings(values, limit=10000):
        if (
            type(values) is not list
            or len(values) > limit
            or any(type(value) is not str or len(value) > 256 for value in values)
        ):
            raise VersionRuntimeError("version_runtime_input_invalid")

    @_operation
    def validate_many(self, versions: list[str]) -> list[dict]:
        self._strings(versions)
        result = self._request("validate_many", {"versions": versions})
        if type(result) is not list or len(result) != len(versions):
            raise VersionRuntimeError("version_runtime_protocol_error")
        for value, item in zip(versions, result, strict=True):
            if (
                type(item) is not dict
                or set(item) != {"input", "valid", "canonical", "base", "prerelease"}
                or item["input"] != value
                or type(item["valid"]) is not bool
                or (
                    item["valid"]
                    and (
                        type(item["canonical"]) is not str
                        or type(item["base"]) is not str
                        or type(item["prerelease"]) is not list
                    )
                )
                or (
                    not item["valid"]
                    and any(item[key] is not None for key in ("canonical", "base", "prerelease"))
                )
            ):
                raise VersionRuntimeError("version_runtime_protocol_error")
        return result

    @_operation
    def compare_pairs(self, pairs: list[tuple[str, str]]) -> list[int]:
        if type(pairs) is not list or len(pairs) > 1000:
            raise VersionRuntimeError("version_runtime_input_invalid")
        for pair in pairs:
            if type(pair) not in (tuple, list) or len(pair) != 2:
                raise VersionRuntimeError("version_runtime_input_invalid")
            self._strings(list(pair), 2)
        result = self._request("compare_pairs", {"pairs": pairs})
        if (
            type(result) is not list
            or len(result) != len(pairs)
            or any(type(value) is not int or value not in (-1, 0, 1) for value in result)
        ):
            raise VersionRuntimeError("version_runtime_protocol_error")
        return result

    @_operation
    def satisfies_many(self, pairs: list[tuple[str, str]]) -> list[dict]:
        if type(pairs) is not list or len(pairs) > 1000:
            raise VersionRuntimeError("version_runtime_input_invalid")
        for pair in pairs:
            if type(pair) not in (tuple, list) or len(pair) != 2:
                raise VersionRuntimeError("version_runtime_input_invalid")
            self._strings(list(pair), 2)
        result = self._request(
            "satisfies_many", {"pairs": [{"version": v, "range": r} for v, r in pairs]}
        )
        if type(result) is not list or len(result) != len(pairs):
            raise VersionRuntimeError("version_runtime_protocol_error")
        for item in result:
            if (
                type(item) is not dict
                or set(item) != {"valid_version", "valid_range", "satisfies"}
                or type(item["valid_version"]) is not bool
                or type(item["valid_range"]) is not bool
                or (
                    item["valid_version"]
                    and item["valid_range"]
                    and type(item["satisfies"]) is not bool
                )
                or (
                    not (item["valid_version"] and item["valid_range"])
                    and item["satisfies"] is not None
                )
            ):
                raise VersionRuntimeError("version_runtime_protocol_error")
        return result

    @_operation
    def sort(self, versions: list[str]) -> list[str]:
        self._strings(versions)
        result = self._request("sort", {"versions": versions})
        if (
            type(result) is not list
            or any(type(value) is not str for value in result)
            or sorted(result) != sorted(versions)
        ):
            raise VersionRuntimeError("version_runtime_protocol_error")
        return result

    @_operation
    def between(self, versions: list[str], pin: str, target: str, prerelease="default") -> dict:
        self._strings(versions)
        self._strings([pin, target], 2)
        if prerelease not in ("default", "all", "none"):
            raise VersionRuntimeError("version_runtime_input_invalid")
        result = self._request(
            "between", {"versions": versions, "from": pin, "to": target, "prerelease": prerelease}
        )
        if (
            type(result) is not dict
            or set(result) != {"selected", "selected_total", "excluded_prereleases", "complete"}
            or type(result["selected"]) is not list
            or len(result["selected"]) > 500
            or any(type(value) is not str or value not in versions for value in result["selected"])
            or type(result["selected_total"]) is not int
            or result["selected_total"] < len(result["selected"])
            or result["selected_total"] > len(versions)
            or len(result["selected"]) != min(result["selected_total"], 500)
            or type(result["excluded_prereleases"]) is not int
            or result["excluded_prereleases"] < 0
            or result["excluded_prereleases"] + result["selected_total"] > len(versions)
            or type(result["complete"]) is not bool
            or result["complete"] != (result["selected_total"] <= 500)
        ):
            raise VersionRuntimeError("version_runtime_protocol_error")
        return result
