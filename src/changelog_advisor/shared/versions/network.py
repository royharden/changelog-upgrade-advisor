"""Fixed request constructors and injected transport guards. No installed live backend."""

import hashlib
import ipaddress
import json
import re
import threading
import time
from dataclasses import dataclass
from urllib.parse import quote, urlencode

from .advisories import identifier, timestamp
from .models import package_name


class FetchError(RuntimeError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class Request:
    endpoint: str
    name: str
    version: str | None = None
    cursor: str | None = None

    def __post_init__(self):
        if self.endpoint not in ("registry", "osv_query", "osv_get", "ghsa_list", "ghsa_get"):
            raise ValueError("unsupported request endpoint")
        if self.endpoint.endswith("get"):
            identifier(self.name)
            if self.version is not None or self.cursor is not None:
                raise ValueError("record request cannot include version/cursor")
            if (
                self.endpoint == "ghsa_get"
                and re.fullmatch(r"GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}", self.name)
                is None
            ):
                raise ValueError("invalid GHSA request identity")
        else:
            package_name(self.name)
        if self.endpoint == "registry" and (self.version is not None or self.cursor is not None):
            raise ValueError("registry request cannot include version/cursor")
        if self.endpoint == "osv_query" and self.version is None:
            raise ValueError("OSV query requires explicit pinned version")
        if self.version is not None and (
            type(self.version) is not str or not self.version or len(self.version) > 256
        ):
            raise ValueError("invalid request version")
        if self.cursor is not None and (
            type(self.cursor) is not str
            or not self.cursor
            or len(self.cursor) > 4096
            or any(ord(c) < 32 for c in self.cursor)
        ):
            raise ValueError("invalid request cursor")

    @property
    def host(self):
        if self.endpoint == "registry":
            return "registry.npmjs.org"
        return "api.osv.dev" if self.endpoint.startswith("osv") else "api.github.com"

    @property
    def url(self):
        if self.endpoint == "registry":
            path = "/" + quote(self.name, safe="")
        elif self.endpoint == "osv_query":
            path = "/v1/query"
        elif self.endpoint == "osv_get":
            path = "/v1/vulns/" + quote(self.name, safe="")
        elif self.endpoint == "ghsa_get":
            path = "/advisories/" + quote(self.name, safe="")
        else:
            query = {
                "ecosystem": "npm",
                "affects": self.name + ("@" + self.version if self.version is not None else ""),
                "type": "reviewed",
                "per_page": "100",
            }
            if self.cursor is not None:
                query["after"] = self.cursor
            path = "/advisories?" + urlencode(query)
        return "https://" + self.host + path

    @property
    def method(self):
        return "POST" if self.endpoint == "osv_query" else "GET"

    @property
    def body(self):
        if self.endpoint != "osv_query":
            return b""
        p = {"package": {"name": self.name, "ecosystem": "npm"}, "version": self.version}
        if self.cursor is not None:
            p["page_token"] = self.cursor
        return json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

    @property
    def key(self):
        return hashlib.sha256(
            self.method.encode() + b"\0" + self.url.encode() + b"\0" + self.body
        ).hexdigest()

    @property
    def byte_limit(self):
        return (32 if self.endpoint == "registry" else 2) * 1024 * 1024


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: bytes
    headers: tuple[tuple[str, str], ...]
    origin: str
    fetched_at: str
    peer_ip: str | None = None
    effective_url: str | None = None


class Budget:
    """HTTP read budget, separate from owner S3 model billing/callledger."""

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.started = clock()
        self.attempts = 0
        self.bytes = 0
        self.held_bytes = 0
        self.lock = threading.Lock()

    def check_time(self):
        if self.clock() - self.started >= 120:
            raise FetchError("fetch_time_limit")

    def reserve(self, limit: int):
        with self.lock:
            self.check_time()
            if self.attempts >= 120:
                raise FetchError("fetch_request_limit")
            remaining = 256 * 1024 * 1024 - self.bytes - self.held_bytes
            if remaining <= 0:
                raise FetchError("fetch_byte_limit")
            self.attempts += 1
            allowance = min(limit, remaining)
            self.held_bytes += allowance
            return allowance, min(self.started + 120, self.clock() + 10)

    def observe(self, byte_count: int, allowance: int):
        with self.lock:
            self.held_bytes -= allowance
            self.bytes += byte_count
            self.check_time()
            if self.bytes > 256 * 1024 * 1024:
                raise FetchError("fetch_byte_limit")


def public_ip(value: str):
    if type(value) is not str or "%" in value:
        raise FetchError("fetch_address_invalid")
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        raise FetchError("fetch_address_invalid") from None
    if not addr.is_global or addr.is_multicast or addr.is_unspecified:
        raise FetchError("fetch_private_destination")
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return public_ip(str(addr.ipv4_mapped))
    return str(addr)


class DeniedTransport:
    def send(self, request: Request, *, limit: int, deadline: float):
        raise FetchError("network_backend_unavailable")


class GuardedTransport:
    """Trusted injected resolver/dialer must honor deadline, TLS hostname and streaming cap.

    Tests inject synthetic peers. Their metadata is not real TLS/SSRF assurance. No DNS,
    socket, HTTP client or SDK backend is installed by this module.
    """

    def __init__(self, resolve, dial, *, clock=time.monotonic):
        self.resolve, self.dial, self.clock = resolve, dial, clock

    def send(self, request: Request, *, limit: int, deadline: float):
        # Reconstruct to reject unchecked dataclass mutations before any injected call.
        Request(request.endpoint, request.name, request.version, request.cursor)
        addresses = self.resolve(request.host, deadline)
        if type(addresses) is not tuple or not addresses or len(addresses) > 32:
            raise FetchError("fetch_dns_invalid")
        public = tuple(public_ip(a) for a in addresses)
        if self.clock() >= deadline:
            raise FetchError("fetch_timeout")
        response = self.dial(request, public[0], limit, deadline)
        if self.clock() >= deadline:
            raise FetchError("fetch_timeout")
        if not isinstance(response, Response):
            raise FetchError("fetch_response_invalid")
        if response.peer_ip != public[0] or response.effective_url != request.url:
            raise FetchError("fetch_peer_or_redirect_mismatch")
        if 300 <= response.status < 400:
            raise FetchError("fetch_redirect_denied")
        return response


def fetch(request: Request, transport, budget: Budget) -> Response:
    request = Request(request.endpoint, request.name, request.version, request.cursor)
    for attempt in range(2):
        limit, deadline = budget.reserve(request.byte_limit)
        try:
            response = transport.send(request, limit=limit, deadline=deadline)
            if (
                not isinstance(response, Response)
                or type(response.status) is not int
                or not 100 <= response.status <= 599
                or type(response.body) is not bytes
                or response.origin not in ("synthetic", "saved_response")
                or type(response.headers) is not tuple
                or len(response.headers) > 64
                or any(
                    type(h) is not tuple
                    or len(h) != 2
                    or any(type(v) is not str or len(v) > 8192 for v in h)
                    for h in response.headers
                )
            ):
                raise FetchError("fetch_response_invalid")
            timestamp(response.fetched_at)
            budget.observe(len(response.body), limit)
            if len(response.body) > limit:
                raise FetchError("fetch_response_limit")
            if budget.clock() >= deadline:
                raise FetchError("fetch_timeout")
            if 300 <= response.status < 400:
                raise FetchError("fetch_redirect_denied")
            if response.status in (429, 502, 503, 504) and attempt == 0:
                # No unbounded sleep or Retry-After from untrusted text. Retry only absent/0.
                wait = [v for k, v in response.headers if k.lower() == "retry-after"]
                if not wait or wait == ["0"]:
                    continue
            return response
        except FetchError:
            raise
        except (OSError, ValueError, TypeError, AttributeError):
            raise FetchError("fetch_transport_error") from None
    raise FetchError("fetch_retry_limit")
