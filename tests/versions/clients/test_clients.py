"""Synthetic HTTP/cache protocol controls; no real DNS/HTTP/backend/Gold/quality claims."""

import hashlib
import json
import socket
from dataclasses import replace

import pytest

from changelog_advisor.shared.versions.cache import CacheEntry, ResponseCache, freshness
from changelog_advisor.shared.versions.clients import Clients
from changelog_advisor.shared.versions.network import (
    Budget,
    FetchError,
    GuardedTransport,
    Request,
    Response,
    fetch,
    public_ip,
)

DATE = "2026-10-14T12:00:00Z"


@pytest.fixture(autouse=True)
def deny_actual_network(monkeypatch):
    def denied(*a, **kw):
        raise AssertionError("HTTP protocol test dispatched actual network")

    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket, "getaddrinfo", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)


def response(body, *, status=200, headers=()):
    raw = body if type(body) is bytes else json.dumps(body).encode()
    return Response(status, raw, headers, "synthetic", DATE)


def osv(ident="x_CONTROL-1", name="demo"):
    return {
        "id": ident,
        "modified": DATE,
        "affected": [{"package": {"name": name, "ecosystem": "npm"}, "versions": ["1.0.0"]}],
    }


def ghsa(name="demo"):
    return {
        "ghsa_id": "GHSA-abcd-1234-efgh",
        "updated_at": DATE,
        "vulnerabilities": [
            {"package": {"name": name, "ecosystem": "npm"}, "vulnerable_version_range": "<2.0.0"}
        ],
    }


class Simulation:
    def __init__(self, replies):
        self.replies = list(replies)
        self.requests = []

    def send(self, req, *, limit, deadline):
        self.requests.append((req, limit, deadline))
        return self.replies.pop(0)


def test_fixed_request_shapes():
    r = Request("registry", "@scope/demo")
    assert r.url == "https://registry.npmjs.org/%40scope%2Fdemo" and r.method == "GET"
    q = Request("osv_query", "demo", "1.0.0", "a+/=")
    assert json.loads(q.body) == {
        "package": {"name": "demo", "ecosystem": "npm"},
        "version": "1.0.0",
        "page_token": "a+/=",
    }
    assert Request("osv_get", "x_CONTROL-1").url == "https://api.osv.dev/v1/vulns/x_CONTROL-1"
    assert Request("ghsa_get", "GHSA-abcd-1234-efgh").url.endswith("/GHSA-abcd-1234-efgh")
    assert "affects=%40scope%2Fdemo%401.0.0" in Request("ghsa_list", "@scope/demo", "1.0.0").url
    assert q.key != Request("osv_query", "demo", "1.0.1", "a+/=").key


@pytest.mark.parametrize(
    "args",
    [
        ("other", "demo"),
        ("registry", "https://evil.example/x"),
        ("registry", "../.creds"),
        ("registry", "demo", "1.0.0"),
        ("osv_get", "a/b"),
        ("ghsa_get", "x_CONTROL-1"),
        ("osv_query", "demo"),
        ("osv_query", "demo", True),
        ("ghsa_list", "demo", None, "\r\n"),
    ],
)
def test_untrusted_endpoint_construction_rejected(args):
    with pytest.raises(ValueError):
        Request(*args)


def test_offline_missing_and_error_not_empty_success():
    spy = Simulation([])
    cache = ResponseCache()
    clients = Clients(cache, transport=spy)
    q = clients.query("osv", "demo", "1.0.0")
    assert q.status == "not_fetched" and not q.complete and spy.requests == []
    cache.put(CacheEntry(Request("osv_query", "demo", "1.0.0"), None, "fetch_http_error", 404))
    q = clients.query("osv", "demo", "1.0.0")
    assert q.status == "error" and not q.complete and q.records == ()
    assert spy.requests == []


def test_injected_default_denies_network_and_retains_error():
    clients = Clients(ResponseCache(), mode="injected")
    q = clients.query("osv", "demo", "1.0.0")
    assert q.reason == "network_backend_unavailable" and clients.budget.attempts == 1
    assert clients.query("osv", "demo", "1.0.0") == q
    assert clients.budget.attempts == 1
    with pytest.raises(ValueError):
        Clients(ResponseCache(), mode="live")


def test_osv_empty_first_page_with_cursor_then_records():
    spy = Simulation([response({"next_page_token": "next"}), response({"vulns": [osv()]})])
    clients = Clients(ResponseCache(), transport=spy, mode="injected", as_of=DATE)
    q = clients.query("osv", "demo", "1.0.0")
    assert q.complete and q.status == "ready" and len(q.records) == 1
    assert len(q.page_hashes) == 2 and q.records[0].origin == "synthetic"
    assert json.loads(spy.requests[1][0].body)["page_token"] == "next"
    before = len(spy.requests)
    assert clients.query("osv", "demo", "1.0.0") == q
    assert len(spy.requests) == before


def test_complete_empty_success_is_distinct():
    for source, body in (("osv", {}), ("ghsa", [])):
        clients = Clients(
            ResponseCache(), transport=Simulation([response(body)]), mode="injected", as_of=DATE
        )
        q = clients.query(source, "demo", "1.0.0")
        assert q.complete and q.status == "ready" and not q.records


def test_ghsa_scope_bound_link_cursor_and_projection_hash():
    next_req = Request("ghsa_list", "demo", "1.0.0", "next")
    page = response([ghsa()], headers=(("Link", "<" + next_req.url + '>; rel="next"'),))
    spy = Simulation([page, response([])])
    clients = Clients(ResponseCache(), transport=spy, mode="injected", as_of=DATE)
    q = clients.query("ghsa", "demo", "1.0.0")
    assert q.complete and len(q.records) == 1 and spy.requests[1][0] == next_req
    assert q.page_hashes[0] == hashlib.sha256(page.body).hexdigest()
    assert q.records[0].sha256 != q.page_hashes[0]


@pytest.mark.parametrize(
    "link",
    [
        '<http://api.github.com/advisories>; rel="next"',
        '<https://127.0.0.1/advisories>; rel="next"',
        '<https://api.github.com@evil.test/advisories>; rel="next"',
        '<https://api.github.com/advisories?after=x>; rel="next"',
        "<https://api.github.com/advisories?ecosystem=PyPI&affects=demo"
        '&per_page=100&type=reviewed&after=x>; rel="next"',
        "garbage",
    ],
)
def test_bad_ghsa_links_never_fetch(link):
    spy = Simulation([response([ghsa()], headers=(("Link", link),))])
    q = Clients(ResponseCache(), transport=spy, mode="injected").query("ghsa", "demo", "1.0.0")
    assert not q.complete and q.status == "error" and len(spy.requests) == 1


def test_pagination_cycle_and_cap():
    q = Clients(
        ResponseCache(),
        mode="injected",
        transport=Simulation(
            [
                response({"vulns": [], "next_page_token": "x"}),
                response({"vulns": [], "next_page_token": "x"}),
            ]
        ),
    ).query("osv", "demo", "1.0.0")
    assert q.reason == "pagination_cycle" and not q.complete
    spy = Simulation([response({"vulns": [], "next_page_token": str(i)}) for i in range(5)])
    q = Clients(ResponseCache(), mode="injected", transport=spy).query("osv", "demo", "1.0.0")
    assert q.reason == "query_page_limit" and not q.complete and len(spy.requests) == 5


@pytest.mark.parametrize(
    "body",
    [
        {"vulns": [osv(name="wrong")]},
        {"vulns": False},
        {"vulns": [False]},
        {"vulns": [], "next_page_token": True},
        {"vulns": [osv()] * 1001},
        b'{"vulns":[],"vulns":[]}',
    ],
)
def test_bad_query_data_visible_unknown(body):
    q = Clients(ResponseCache(), mode="injected", transport=Simulation([response(body)])).query(
        "osv", "demo", "1.0.0"
    )
    assert not q.complete and q.status in ("error", "incomplete")


def test_record_gets_and_registry_identity():
    spy = Simulation(
        [
            response(osv()),
            response(ghsa()),
            response({"name": "demo", "versions": {"1.0.0": {}}, "dist-tags": {"latest": "1.0.0"}}),
        ]
    )
    clients = Clients(ResponseCache(), mode="injected", transport=spy, as_of=DATE)
    assert clients.advisory("osv", "x_CONTROL-1")[0].id == "x_CONTROL-1"
    assert clients.advisory("ghsa", "GHSA-abcd-1234-efgh")[0].source == "ghsa"
    assert clients.registry("demo")[0].fetched_at == DATE
    bad = Clients(ResponseCache(), mode="injected", transport=Simulation([response(osv())]))
    assert bad.advisory("osv", "x_CONTROL-2")[1] == "advisory_response_identity_mismatch"


def test_cache_roundtrip_hashes_tampering_duplicates_and_no_overwrite():
    cache = ResponseCache()
    req = Request("osv_query", "demo", "1.0.0")
    entry = CacheEntry(req, response({"vulns": [osv()]}), None)
    cache.put(entry)
    raw = cache.to_bytes()
    restored = ResponseCache.from_bytes(raw)
    assert restored.to_bytes() == raw and restored.get(req).digest == entry.digest
    with pytest.raises(ValueError):
        cache.put(replace(entry, response=response({})))
    p = json.loads(raw)
    p["entries"][0]["entry"]["request"]["version"] = "2.0.0"
    with pytest.raises(ValueError):
        ResponseCache.from_bytes(json.dumps(p).encode())
    p = json.loads(raw)
    p["entries"].append(p["entries"][0])
    with pytest.raises(ValueError):
        ResponseCache.from_bytes(json.dumps(p).encode())
    with pytest.raises(ValueError):
        ResponseCache.from_bytes(b'{"entries":[],"entries":[]}')
    with pytest.raises(ValueError):
        cache.put(CacheEntry(req, None, "private exception text"))


def test_stale_future_and_unknown_freshness_are_visible():
    entry = CacheEntry(Request("osv_query", "demo", "1.0.0"), response({}), None)
    assert freshness(entry, None) == "unknown"
    assert freshness(entry, "2026-10-16T12:00:00Z") == "stale"
    assert freshness(entry, "2026-10-13T12:00:00Z") == "future_timestamp"
    cache = ResponseCache()
    cache.put(entry)
    q = Clients(cache, as_of="2026-10-16T12:00:00Z").query("osv", "demo", "1.0.0")
    assert q.complete and q.status == "freshness_unverified" and q.freshness == ("stale",)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "224.0.0.1",
        "100.64.0.1",
        "garbage",
        "2606::1%eth0",
    ],
)
def test_private_destinations_are_observed_and_denied_before_dial(address):
    seen, dialed = [], []

    def resolve(host, deadline):
        seen.append(host)
        return (address,)

    def dial(*a):
        dialed.append(a)
        raise AssertionError("private destination dialed")

    transport = GuardedTransport(resolve, dial)
    with pytest.raises(FetchError):
        fetch(Request("osv_query", "demo", "1.0.0"), transport, Budget())
    assert seen == ["api.osv.dev"] and not dialed


def test_public_pinned_peer_and_rebinding_redirect_rejection():
    req = Request("registry", "demo")

    def resolve(*a):
        return ("8.8.8.8",)

    def dial(r, ip, cap, deadline):
        assert ip == "8.8.8.8" and cap == 32 * 1024 * 1024
        return replace(response({}), peer_ip=ip, effective_url=r.url)

    assert fetch(req, GuardedTransport(resolve, dial), Budget()).status == 200
    for bad in [
        replace(response({}), peer_ip="127.0.0.1", effective_url=req.url),
        replace(response({}), peer_ip="8.8.8.8", effective_url="https://evil.test"),
        replace(response({}, status=302), peer_ip="8.8.8.8", effective_url=req.url),
    ]:
        with pytest.raises(FetchError):
            fetch(req, GuardedTransport(resolve, lambda *a, reply=bad: reply), Budget())
    assert public_ip("8.8.8.8") == "8.8.8.8"


def test_request_byte_time_budgets_and_retry():
    req = Request("osv_query", "demo", "1.0.0")
    b = Budget()
    b.attempts = 120
    spy = Simulation([])
    with pytest.raises(FetchError, match="request_limit"):
        fetch(req, spy, b)
    assert not spy.requests
    b = Budget()
    b.bytes = 256 * 1024 * 1024
    with pytest.raises(FetchError, match="byte_limit"):
        fetch(req, spy, b)
    clock = [0.0]
    b = Budget(clock=lambda: clock[0])
    clock[0] = 120.0
    with pytest.raises(FetchError, match="time_limit"):
        fetch(req, spy, b)
    spy = Simulation([response({}, status=503), response({})])
    b = Budget()
    assert fetch(req, spy, b).status == 200 and b.attempts == 2 and b.held_bytes == 0
    spy = Simulation([response({}, status=429, headers=(("Retry-After", "999999"),))])
    assert fetch(req, spy, Budget()).status == 429 and len(spy.requests) == 1
    spy = Simulation([response(b" " * (2 * 1024 * 1024 + 1))])
    with pytest.raises(FetchError, match="response_limit"):
        fetch(req, spy, Budget())


def test_concurrent_reservations_hold_unknown_bytes():
    b = Budget()
    for _ in range(8):
        b.reserve(32 * 1024 * 1024)
    assert b.held_bytes == 256 * 1024 * 1024 and b.bytes == 0
    with pytest.raises(FetchError, match="byte_limit"):
        b.reserve(1)


def test_deadline_after_injected_dispatch_is_failure():
    clock = [0.0]
    b = Budget(clock=lambda: clock[0])

    class Slow:
        def send(self, *a, **kw):
            clock[0] = 11
            return response({})

    with pytest.raises(FetchError, match="timeout"):
        fetch(Request("osv_query", "demo", "1.0.0"), Slow(), b)


@pytest.mark.parametrize("field,value", [("headers", ["ab"]), ("status", True)])
def test_cached_response_coercions_rejected(field, value):
    cache = ResponseCache()
    cache.put(CacheEntry(Request("osv_query", "demo", "1.0.0"), response({}), None))
    p = json.loads(cache.to_bytes())
    p["entries"][0]["entry"]["response"][field] = value
    with pytest.raises(ValueError):
        ResponseCache.from_bytes(json.dumps(p).encode())


def test_http_error_retains_status_without_server_body():
    cache = ResponseCache()
    clients = Clients(
        cache,
        mode="injected",
        transport=Simulation([response(b"private server error or instructions", status=404)]),
    )
    query = clients.query("osv", "demo", "1.0.0")
    assert query.status == "error" and not query.complete
    entry = cache.get(Request("osv_query", "demo", "1.0.0"))
    assert entry.http_status == 404 and entry.response is None
    assert b"private server error" not in cache.to_bytes()
    assert ResponseCache.from_bytes(cache.to_bytes()).get(entry.request).http_status == 404


def test_deep_cache_envelope_rejected():
    with pytest.raises(ValueError):
        ResponseCache.from_bytes(b'{"unused":' + b"[" * 100 + b"0" + b"]" * 100 + b"}")
