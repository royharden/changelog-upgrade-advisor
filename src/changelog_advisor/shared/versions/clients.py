"""Required registry/OSV/GHSA cache/read paths with explicitly injected HTTP simulation."""

import hashlib
import json
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

from .advisories import Advisory, decode_record
from .cache import ResponseCache, read_response
from .ghsa import normalize_ghsa
from .manifest import decode_json
from .network import Budget, DeniedTransport, Request
from .osv import normalize_osv
from .window import read_registry_snapshot


@dataclass(frozen=True, slots=True)
class QueryResult:
    status: str
    reason: str
    records: tuple[Advisory, ...]
    complete: bool
    page_hashes: tuple[str, ...]
    retrieval_times: tuple[str, ...]
    freshness: tuple[str, ...]


def _canonical(row):
    return json.dumps(
        row, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf8")


def next_ghsa_cursor(headers, request: Request):
    links = [v for k, v in headers if k.lower() == "link"]
    if not links:
        return None
    if len(links) != 1:
        raise ValueError("ambiguous GHSA Link")
    matches = re.findall(r'<([^<>]+)>;\s*rel="([a-z]+)"', links[0])
    if not matches:
        raise ValueError("malformed GHSA Link")
    nexts = [url for url, rel in matches if rel == "next"]
    if not nexts:
        return None
    if len(nexts) != 1:
        raise ValueError("ambiguous GHSA next link")
    parsed = urlsplit(nexts[0])
    if (
        parsed.scheme != "https"
        or parsed.netloc != "api.github.com"
        or parsed.path != "/advisories"
        or parsed.fragment
    ):
        raise ValueError("GHSA next URL outside fixed source")
    query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
    if "after" not in query or len(query["after"]) != 1:
        raise ValueError("GHSA next cursor missing")
    cursor = query.pop("after")[0]
    base = parse_qs(urlsplit(Request("ghsa_list", request.name, request.version).url).query)
    if query != base:
        raise ValueError("GHSA pagination scope changed")
    Request("ghsa_list", request.name, request.version, cursor)
    return cursor


class Clients:
    def __init__(
        self, cache: ResponseCache, *, transport=None, budget=None, mode="offline", as_of=None
    ):
        if mode not in ("offline", "injected"):
            raise ValueError("actual live backend unavailable")
        self.cache = cache
        self.transport = transport if transport is not None else DeniedTransport()
        self.budget = budget if budget is not None else Budget()
        self.mode, self.as_of = mode, as_of

    def _read(self, request):
        return read_response(
            request, self.cache, self.transport, self.budget, mode=self.mode, as_of=self.as_of
        )

    def registry(self, name):
        entry, state = self._read(Request("registry", name))
        if entry is None:
            return None, "not_fetched"
        if entry.error is not None:
            return None, entry.error
        try:
            record = read_registry_snapshot(
                entry.response.body,
                name,
                origin=entry.response.origin,
                fetched_at=entry.response.fetched_at,
            )
        except (ValueError, TypeError, RecursionError):
            return None, "registry_response_invalid"
        return record, state

    def advisory(self, source, ident):
        if source not in ("osv", "ghsa"):
            raise ValueError("unsupported advisory source")
        entry, state = self._read(Request(source + "_get", ident))
        if entry is None:
            return None, "not_fetched"
        if entry.error is not None:
            return None, entry.error
        try:
            normalize = normalize_osv if source == "osv" else normalize_ghsa
            record = normalize(entry.response.body, origin=entry.response.origin)
            if record.id != ident:
                return None, "advisory_response_identity_mismatch"
        except (ValueError, TypeError):
            return None, "advisory_response_invalid"
        return record, state

    def query(self, source: str, name: str, version: str | None = None):
        if source not in ("osv", "ghsa"):
            raise ValueError("unsupported advisory source")
        records, hashes, times, freshness = [], [], [], []
        seen_cursors = set()
        cursor = None

        def result(status, reason, complete=False):
            return QueryResult(
                status,
                reason,
                tuple(records),
                complete,
                tuple(hashes),
                tuple(times),
                tuple(freshness),
            )

        for _page in range(5):
            request = Request(
                "osv_query" if source == "osv" else "ghsa_list", name, version, cursor
            )
            entry, state = self._read(request)
            if entry is None:
                return result("not_fetched" if not hashes else "incomplete", "cache_page_missing")
            if entry.error is not None:
                return result("error", entry.error)
            response = entry.response
            hashes.append(hashlib.sha256(response.body).hexdigest())
            times.append(response.fetched_at)
            freshness.append(state)
            try:
                if source == "osv":
                    p = decode_record(response.body)
                    rows = p.get("vulns", [])
                    cursor = p.get("next_page_token")
                    normalize = normalize_osv
                else:
                    # Exact HTTP page hash remains distinct from canonical parsed record bytes.
                    p = decode_json(b'{"items":' + response.body + b"}", 2 * 1024 * 1024 + 10)
                    rows = p["items"]
                    cursor = next_ghsa_cursor(response.headers, request)
                    normalize = normalize_ghsa
                if type(rows) is not list or len(rows) + len(records) > 1000:
                    return result("incomplete", "advisory_record_limit_or_table_invalid")
                parsed = [normalize(_canonical(row), origin=response.origin) for row in rows]
                if any(
                    not any(r.package == name and r.ecosystem == "npm" for r in record.affected)
                    for record in parsed
                ):
                    return result("error", "query_package_or_ecosystem_mismatch")
                records.extend(parsed)
                if cursor is not None and (
                    type(cursor) is not str or not cursor or len(cursor) > 4096
                ):
                    return result("error", "pagination_cursor_invalid")
                if cursor is None:
                    status = "ready" if set(freshness) == {"fresh"} else "freshness_unverified"
                    return result(status, "all_query_pages_retained", complete=True)
                if cursor in seen_cursors:
                    return result("incomplete", "pagination_cycle")
                seen_cursors.add(cursor)
            except (ValueError, TypeError, RecursionError):
                return result("error", "query_response_invalid")
        return result("incomplete", "query_page_limit")
