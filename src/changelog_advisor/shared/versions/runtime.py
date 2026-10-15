"""Bounded fixed-helper IPC; imports never start Node. No Python version comparator."""

import json
import os
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
            process.stdin.write(payload)
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


class NodeSemver:
    def __init__(self):
        self._transport = _transport
        self.pending_pids: set[int] = set()

    def _request(self, operation: str, args: dict):
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
