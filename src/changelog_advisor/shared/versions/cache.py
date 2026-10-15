"""Supplied content-addressed response cache. No implicit filesystem, recency or network."""

import base64
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime

from .advisories import timestamp
from .manifest import decode_json
from .network import FetchError, Request, Response


@dataclass(frozen=True, slots=True)
class CacheEntry:
    request: Request
    response: Response | None
    error: str | None
    http_status: int | None = None

    @property
    def digest(self):
        return hashlib.sha256(_encode(self)).hexdigest()


def _encode(entry):
    p = {
        "request": asdict(entry.request),
        "error": entry.error,
        "response": None,
        "http_status": entry.http_status,
    }
    if entry.response is not None:
        p["response"] = asdict(entry.response)
        p["response"]["body"] = base64.b64encode(entry.response.body).decode("ascii")
    return json.dumps(
        p, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf8")


class ResponseCache:
    def __init__(self):
        self._entries: dict[str, CacheEntry] = {}

    def put(self, entry: CacheEntry):
        req = entry.request
        Request(req.endpoint, req.name, req.version, req.cursor)
        if (entry.response is None) == (entry.error is None):
            raise ValueError("cache entry requires success OR explicit failure")
        if entry.http_status is not None and (
            type(entry.http_status) is not int or not 100 <= entry.http_status <= 599
        ):
            raise ValueError("invalid cached HTTP status")
        if entry.error == "fetch_http_error" and entry.http_status in (None, 200):
            raise ValueError("HTTP failure requires actual non200 status")
        if entry.response is not None and entry.http_status is not None:
            raise ValueError("successful response already carries HTTP status")
        if entry.response is not None:
            response = entry.response
            if (
                type(response) is not Response
                or type(response.status) is not int
                or response.status != 200
                or type(response.body) is not bytes
                or len(response.body) > req.byte_limit
                or type(response.headers) is not tuple
                or len(response.headers) > 64
                or any(
                    type(h) is not tuple
                    or len(h) != 2
                    or any(type(v) is not str or len(v) > 8192 for v in h)
                    for h in response.headers
                )
            ):
                raise ValueError("cache success must be bounded200 response")
            if response.origin not in ("synthetic", "saved_response"):
                raise ValueError("cache origin required")
            timestamp(response.fetched_at)
        elif entry.error not in {
            "network_backend_unavailable",
            "fetch_private_destination",
            "fetch_address_invalid",
            "fetch_dns_invalid",
            "fetch_timeout",
            "fetch_peer_or_redirect_mismatch",
            "fetch_redirect_denied",
            "fetch_response_invalid",
            "fetch_time_limit",
            "fetch_request_limit",
            "fetch_byte_limit",
            "fetch_response_limit",
            "fetch_transport_error",
            "fetch_retry_limit",
            "fetch_http_error",
        }:
            raise ValueError("closed cache error identity required")
        if len(self._entries) >= 120 and req.key not in self._entries:
            raise ValueError("cache entry limit")
        old = self._entries.get(req.key)
        if old is not None and old.digest != entry.digest:
            raise ValueError("explicit new cache snapshot required for changed response")
        self._entries[req.key] = entry

    def get(self, request: Request):
        return self._entries.get(request.key)

    def to_bytes(self):
        rows = [
            {"request_key": key, "entry_sha256": entry.digest, "entry": json.loads(_encode(entry))}
            for key, entry in sorted(self._entries.items())
        ]
        raw = json.dumps(
            {"schema_version": 1, "entries": rows},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
        if len(raw) > 64 * 1024 * 1024:
            raise ValueError("complete cache archive limit; no partial serialization")
        return raw

    @classmethod
    def from_bytes(cls, raw: bytes):
        try:
            p = decode_json(raw, 64 * 1024 * 1024)
        except RecursionError:
            raise ValueError("cache structure limit") from None
        pending = [(p, 0)]
        while pending:
            value, depth = pending.pop()
            if depth > 32:
                raise ValueError("cache structure limit")
            if type(value) is dict:
                pending.extend((v, depth + 1) for v in value.values())
            elif type(value) is list:
                pending.extend((v, depth + 1) for v in value)
        if set(p) != {"schema_version", "entries"} or type(p["schema_version"]) is not int:
            raise ValueError("invalid cache envelope")
        if p["schema_version"] != 1 or type(p["entries"]) is not list or len(p["entries"]) > 120:
            raise ValueError("invalid cache version/table")
        cache = cls()
        for row in p["entries"]:
            if type(row) is not dict or set(row) != {"request_key", "entry_sha256", "entry"}:
                raise ValueError("invalid cache row")
            item = row["entry"]
            if type(item) is not dict or set(item) != {
                "request",
                "error",
                "response",
                "http_status",
            }:
                raise ValueError("invalid cache entry")
            if type(item["request"]) is not dict or set(item["request"]) != {
                "endpoint",
                "name",
                "version",
                "cursor",
            }:
                raise ValueError("closed cached request required")
            req = Request(**item["request"])
            response = None
            if item["response"] is not None:
                if type(item["response"]) is not dict or set(item["response"]) != {
                    "status",
                    "body",
                    "headers",
                    "origin",
                    "fetched_at",
                    "peer_ip",
                    "effective_url",
                }:
                    raise ValueError("closed cached response required")
                values = dict(item["response"])
                headers = values["headers"]
                if type(headers) is not list or any(
                    type(h) is not list or len(h) != 2 for h in headers
                ):
                    raise ValueError("invalid cached header structure")
                values["body"] = base64.b64decode(values["body"], validate=True)
                values["headers"] = tuple(tuple(h) for h in values["headers"])
                response = Response(**values)
            entry = CacheEntry(req, response, item["error"], item["http_status"])
            if req.key != row["request_key"] or entry.digest != row["entry_sha256"]:
                raise ValueError("cache request/content identity mismatch")
            if cache.get(req) is not None:
                raise ValueError("duplicate cache request")
            cache.put(entry)
        return cache


def freshness(entry: CacheEntry, as_of: str | None, *, max_age_seconds=86400):
    if entry.response is None:
        return "error"
    if as_of is None:
        return "unknown"
    timestamp(as_of)
    seconds = (
        datetime.fromisoformat(as_of) - datetime.fromisoformat(entry.response.fetched_at)
    ).total_seconds()
    if seconds < 0:
        return "future_timestamp"
    return "fresh" if seconds <= max_age_seconds else "stale"


def read_response(request, cache, transport, budget, *, mode="offline", as_of=None):
    if mode not in ("offline", "injected"):
        raise ValueError("unsupported client mode; actual live backend not installed")
    entry = cache.get(request)
    if entry is None and mode == "injected":
        from .network import fetch

        try:
            response = fetch(request, transport, budget)
            entry = (
                CacheEntry(request, response, None)
                if response.status == 200
                else CacheEntry(request, None, "fetch_http_error", response.status)
            )
        except FetchError as error:
            entry = CacheEntry(request, None, error.reason)
        cache.put(entry)
    if entry is None:
        return None, "not_fetched"
    return entry, freshness(entry, as_of)
