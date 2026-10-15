"""Bounded local bundle -> cited checklist. No acquisition, installation or model dispatch."""

import hashlib
from collections import Counter
from dataclasses import asdict
from typing import Annotated, Literal

from pydantic import BeforeValidator, Field, model_validator

from .judges import JudgeInput, decode_prepared, keyword_judgment, prepare_judgment
from .judges.models import DEFAULT_POLICY
from .shared.callledger.models import canonical_digest, decode_wire_json
from .shared.cited import ArtifactRef, Finding, Registry, ResolutionContext
from .shared.cited.assessment import assess_required_evidence
from .shared.cited.memory import MemoryTextResolver, install_supplied_text
from .shared.cited.models import (
    AdvisoryLocator,
    AdvisoryPointer,
    MethodRef,
    Resolution,
    SourceArtifact,
    WireModel,
)
from .shared.versions.advisories import Membership, deduplicate, group_membership
from .shared.versions.changelog import parse_changelog, select_spans
from .shared.versions.ghsa import normalize_ghsa
from .shared.versions.lockfile import Lockfile
from .shared.versions.manifest import read_manifest, select_declarations
from .shared.versions.models import package_name
from .shared.versions.osv import normalize_osv
from .shared.versions.pins import resolve_pin
from .shared.versions.runtime import NodeSemver, VersionRuntimeError
from .shared.versions.sources import make_span_source, span_pointer
from .shared.versions.window import read_registry_snapshot, release_window


def _array(value):
    return tuple(value) if type(value) is list else value


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def reference(name, value):
    return ArtifactRef(
        artifact_id=name,
        profile_id="local-explicit-bundle/1",
        artifact_sha256=canonical_digest(value),
    )


class AdvisoryInput(WireModel):
    osv: Annotated[tuple[str, ...], BeforeValidator(_array), Field(max_length=1000)] | None = None
    ghsa: Annotated[tuple[str, ...], BeforeValidator(_array), Field(max_length=1000)] | None = None


class PackageInput(WireModel):
    name: str
    target: Annotated[str, Field(min_length=1, max_length=256)] = "latest"
    pin: Annotated[str, Field(min_length=1, max_length=256)] | None = None
    registry_json: str | None = None
    notes: str | None = None
    usage_snippet: str | None = None
    advisories: AdvisoryInput = AdvisoryInput()

    @model_validator(mode="after")
    def bounded(self):
        package_name(self.name)
        if self.usage_snippet is not None and len(self.usage_snippet.encode("utf8")) > 8192:
            raise ValueError("usage snippet exceeds 8KiB")
        return self


class Bundle(WireModel):
    edition: Literal["s5-supplied-bundle/1"]
    origin: Literal["synthetic", "supplied"]
    manifest_json: str
    lock_json: str | None = None
    selected: Annotated[tuple[str, ...], BeforeValidator(_array), Field(max_length=20)] | None = (
        None
    )
    packages: Annotated[tuple[PackageInput, ...], BeforeValidator(_array), Field(max_length=20)]
    prerelease: Literal["default", "all", "none"] = "default"

    @model_validator(mode="after")
    def unique(self):
        if len({p.name for p in self.packages}) != len(self.packages):
            raise ValueError("duplicate supplied package input")
        if (
            sum(
                len(getattr(p.advisories, source) or ())
                for p in self.packages
                for source in ("osv", "ghsa")
            )
            > 1000
        ):
            raise ValueError("explicit advisory run cap1000; split selected packages")
        return self


def read_bundle(raw: bytes) -> Bundle:
    if type(raw) is not bytes or len(raw) > 64 * 1024 * 1024:
        raise ValueError(
            "bundle exceeds64MiB; split explicit selected packages into smaller bundles"
        )
    payload = decode_wire_json(raw.decode("utf8"), max_bytes=64 * 1024 * 1024)
    pending = [(payload, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > 32 or nodes > 100000:
            raise ValueError("bundle structure cap")
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
    return Bundle.model_validate(payload)


class LocalSourcePolicy:
    """The CLI caller explicitly supplied these immutable sources for this one local analysis."""

    def __init__(self, namespace, sources):
        self.namespace = namespace
        self.sources = {s.source_id: s for s in sources}
        identities = {key: value.model_dump(mode="json") for key, value in self.sources.items()}
        self.reference = reference(
            "bundle-source-policy", {"namespace": namespace, "sources": identities}
        )

    def decision(self, namespace_id, source_id):
        return "allow" if namespace_id == self.namespace and source_id in self.sources else "deny"

    def current(self, namespace_id, source_id):
        return self.sources.get(source_id) if namespace_id == self.namespace else None


def source_context(namespace, metadata):
    policy = LocalSourcePolicy(namespace, metadata)
    context = ResolutionContext(
        namespace_id=namespace,
        access_policy_ref=policy.reference,
        generation_policy_ref=policy.reference,
        required_scope="text",
    )
    return policy, context


def _record_projection(record):
    return {
        "profile": "advisory-summary-details/1",
        "source": record.source,
        "id": record.id,
        "raw_sha256": record.sha256,
        "text": record.summary + "\n" + record.details,
    }


def _advisory_id(record):
    return "advisory-" + record.source + "-" + record.sha256


class SuppliedAdvisoryResolver:
    """App-only retained record-ID/text projection; no fetching or authenticity claim."""

    def __init__(self, records, policy):
        self.records = {_advisory_id(r): r for r in records}
        self.policy = policy

    def resolve(self, pointer, context):
        if (
            context.access_policy_ref != self.policy.reference
            or context.generation_policy_ref != self.policy.reference
            or self.policy.decision(context.namespace_id, pointer.source_id) != "allow"
        ):
            return Resolution(status="unsupported", reason="access_not_allowed")
        record = self.records.get(pointer.source_id)
        metadata = self.policy.current(context.namespace_id, pointer.source_id)
        if record is None or metadata is None:
            return Resolution(status="missing", reason="source_not_retained")
        projection = _record_projection(record)
        if (
            sha(record.raw) != record.sha256
            or record.sha256 != pointer.source_sha256
            or pointer.source_revision != metadata.source_revision
            or pointer.evidence_artifact_sha256 != canonical_digest(projection)
        ):
            return Resolution(status="stale", reason="source_identity_changed")
        quote = pointer.locator.quote
        if (
            pointer.locator.advisory_id != record.id
            or not quote
            or quote not in projection["text"]
            or pointer.locator.excerpt_sha256 != sha(quote.encode("utf8"))
        ):
            return Resolution(status="invalid", reason="literal_quote_mismatch")
        if self.policy.decision(context.namespace_id, pointer.source_id) != "allow":
            return Resolution(status="unsupported", reason="access_not_allowed")
        return Resolution(
            status="resolved",
            reason="literal_quote_resolved",
            scope="text",
            checked_source_sha256=record.sha256,
            checked_source_revision=metadata.source_revision,
            checked_artifact_sha256=canonical_digest(projection),
            excerpt=quote,
            excerpt_sha256=sha(quote.encode("utf8")),
        )


def advisory_evidence(records, namespace):
    metadata = tuple(
        SourceArtifact(
            source_id=_advisory_id(r),
            source_type="advisory_record",
            source_sha256=r.sha256,
            source_revision="sha256:" + r.sha256,
            evidence_artifact_sha256=canonical_digest(_record_projection(r)),
            raw_byte_length=len(r.raw),
        )
        for r in records
    )
    policy, context = source_context(namespace, metadata)
    registry = Registry()
    registry.register(
        ("advisory:id", "advisory_record", "id"), SuppliedAdvisoryResolver(records, policy)
    )
    return registry, context, {m.source_id: m for m in metadata}


def _advisories(data, package, pin, target, runtime, origin, namespace):
    rows = []
    records = []
    states = {}
    for source, normalize in (("osv", normalize_osv), ("ghsa", normalize_ghsa)):
        supplied = getattr(data.advisories, source)
        states[source] = "not_fetched" if supplied is None else "supplied_snapshot"
        for index, text in enumerate(supplied or ()):
            try:
                records.append(normalize(text.encode("utf8"), origin=origin))
            except (TypeError, ValueError, RecursionError):
                rows.append(
                    {
                        "source": source,
                        "record_index": index,
                        "status": "error",
                        "reason": "advisory_input_invalid",
                        "membership": "unknown",
                        "usage_impact": "unknown",
                    }
                )
    expected = sum(len(getattr(data.advisories, source) or ()) for source in ("osv", "ghsa"))
    invalid = len(rows)
    unique = tuple({(r.source, r.id, r.sha256): r for r in records}.values())
    if len(unique) > 1000:
        return {
            "source_status": states,
            "status": "incomplete",
            "error": "advisory_run_cap",
            "records_expected": expected,
            "records_analyzed": 0,
            "rows": rows,
        }
    registry, context, metadata = advisory_evidence(unique, namespace)
    for group in deduplicate(unique):
        current = (
            group_membership(group, package, pin, runtime)
            if pin is not None
            else Membership("unknown", "installed_pin_unresolved")
        )
        future = group_membership(group, package, target, runtime) if target else None
        usage = (
            "does_not_apply" if current.status in ("not_affected", "not_applicable") else "unknown"
        )
        reason = (
            "outside_range_or_identity"
            if usage == "does_not_apply"
            else "missing_usage_snippet"
            if data.usage_snippet is None
            else "usage_judge_unmeasured"
        )
        evidence = []
        for record in group.records:
            m = metadata[_advisory_id(record)]
            quote = record.summary or record.details
            try:
                pointer = AdvisoryPointer(
                    kind="advisory:id",
                    source_type="advisory_record",
                    locator_subtype="id",
                    source_id=m.source_id,
                    source_sha256=m.source_sha256,
                    source_revision=m.source_revision,
                    evidence_artifact_sha256=m.evidence_artifact_sha256,
                    locator=AdvisoryLocator(
                        advisory_id=record.id, quote=quote, excerpt_sha256=sha(quote.encode("utf8"))
                    ),
                )
                resolution = registry.resolve(pointer, context)
                evidence.append(
                    {
                        "pointer": pointer.model_dump(mode="json"),
                        "resolution": resolution.model_dump(mode="json"),
                    }
                )
            except (ValueError, TypeError):
                evidence.append(
                    {"resolution": {"status": "unsupported", "reason": "advisory_quote_bounds"}}
                )
        unresolved = sum(e["resolution"]["status"] != "resolved" for e in evidence)
        rows.append(
            {
                "ids": list(group.ids),
                "membership": current.status,
                "membership_reason": current.reason,
                "target_membership": future.status if future else "unknown",
                "usage_impact": usage,
                "usage_reason": reason,
                "usage_calls": 0,
                "required_evidence_count": len(evidence),
                "resolved_evidence_count": len(evidence) - unresolved,
                "status": "unsupported"
                if unresolved
                else "review"
                if current.status not in ("not_affected", "not_applicable")
                else "outside",
                "evidence": evidence,
                "source_records": [
                    {
                        "source": r.source,
                        "id": r.id,
                        "sha256": r.sha256,
                        "origin": r.origin,
                        "modified": r.modified,
                        "withdrawn": r.withdrawn,
                    }
                    for r in group.records
                ],
            }
        )
    return {
        "source_status": states,
        "rows": rows,
        "records_expected": expected,
        "invalid_records": invalid,
        "records_normalized": len(records),
        "duplicate_records": len(records) - len(unique),
        "records_analyzed": len(unique),
        "status": "supplied_only",
    }


def _entries(data, notes, selection, method, namespace):
    source = make_span_source(
        notes, selection.spans, namespace_id=namespace, source_id="notes-" + notes.sha256
    )
    policy, context = source_context(namespace, (source.metadata,))
    registry = Registry()
    install_supplied_text(registry, MemoryTextResolver((source,), access=policy, generation=policy))
    rows = []
    for span in selection.spans:
        row = {
            "span_id": span.id,
            "release": span.release,
            "lines": [span.line_start, span.line_end],
            "state": span.state,
            "status": "unknown",
            "source_sha256": notes.sha256,
        }
        try:
            pointer = span_pointer(source, span)
            original = JudgeInput(
                span_id=span.id,
                package=data.name,
                source_generation=source.metadata.source_revision,
                source_sha256=notes.sha256,
                text=span.text,
                context=span.context,
                snippet=data.usage_snippet,
            )
            judgment = (
                keyword_judgment(original)
                if method == "keyword"
                else decode_prepared(
                    prepare_judgment(original, method=method, model="unconfigured"), None
                )
            )
            row["judgment"] = judgment.model_dump(mode="json")
            row["status"] = "review" if judgment.status == "review" else judgment.status
            row["evidence"] = {
                "pointer": pointer.model_dump(mode="json"),
                "resolution": registry.resolve(pointer, context).model_dump(mode="json"),
            }
            if judgment.judgment is not None:
                claim = Finding(
                    id="finding-"
                    + canonical_digest(
                        {"span": span.id, "policy": DEFAULT_POLICY.sha256, "method": method}
                    ),
                    text=f"Potential {judgment.judgment.category} change in {data.name}.",
                    verdict="partial",
                    probability=judgment.judgment.probability,
                    evidence=(pointer,),
                    method=MethodRef(
                        method_id=method,
                        origin="deterministic"
                        if method == "keyword"
                        else method
                        if method == "typed"
                        else "generative",
                        policy_sha256=DEFAULT_POLICY.sha256,
                    ),
                )
                assessment = assess_required_evidence(claim, registry, context)
                row["finding"] = assessment.finding.model_dump(mode="json")
                row["required_evidence_count"] = assessment.required_count
                row["resolved_evidence_count"] = assessment.resolved_count
                row["status"] = (
                    "unsupported"
                    if assessment.unresolved_count
                    else "review"
                    if judgment.judgment.is_breaking
                    else "nonbreaking"
                )
        except (TypeError, ValueError, UnicodeError):
            row.update(status="unsupported", reason="entry_or_evidence_unavailable")
        rows.append(row)
    return rows, source.metadata.model_dump(mode="json")


def analyze_bundle(bundle: Bundle, *, method="keyword", runtime=None):
    if method not in ("keyword", "typed", "generative"):
        raise ValueError("unsupported method")
    bundle = Bundle.model_validate(bundle)
    manifest = read_manifest(bundle.manifest_json.encode("utf8"))
    selected = select_declarations(manifest, bundle.selected)
    direct = {d.name for d in manifest.declarations}
    if not {p.name for p in bundle.packages} <= direct:
        raise ValueError("supplied package absent from direct manifest")
    lock = Lockfile(bundle.lock_json.encode("utf8")) if bundle.lock_json is not None else None
    config = {
        "method": method,
        "prerelease": bundle.prerelease,
        "max_spans": 500,
        "policy_sha256": DEFAULT_POLICY.sha256,
        "origin": bundle.origin,
    }
    bundle_hash = canonical_digest(bundle.model_dump(mode="json"))
    namespace = "local-run-" + bundle_hash[:24]
    supplied = {p.name: p for p in bundle.packages}
    reports = []
    remaining = 500
    owned = runtime is None
    runtime = NodeSemver() if owned else runtime
    origin = "synthetic" if bundle.origin == "synthetic" else "saved_response"
    try:
        for name in dict.fromkeys(d.name for d in selected):
            data = supplied.get(name, PackageInput(name=name))
            declarations = tuple(d for d in selected if d.name == name)
            pins = tuple(
                resolve_pin(d, runtime, lock=lock, override=data.pin) for d in declarations
            )
            row = {
                "package": name,
                "declarations": [asdict(d) for d in declarations],
                "pins": [asdict(p) for p in pins],
                "status": "unknown",
                "entries": [],
                "notes_status": "not_supplied" if data.notes is None else "supplied",
                "catalog_status": "not_supplied" if data.registry_json is None else "supplied",
            }
            reports.append(row)
            if any(p.status != "resolved" for p in pins) or len({p.version for p in pins}) != 1:
                row["advisories"] = _advisories(data, name, None, None, runtime, origin, namespace)
                row.update(status="unresolved_pin", reason="direct_pin_unresolved_or_conflicting")
                continue
            pin = pins[0].version
            row["installed_pin"] = pin
            if data.registry_json is None:
                row["advisories"] = _advisories(data, name, pin, None, runtime, origin, namespace)
                row.update(status="unknown", reason="registry_snapshot_not_supplied")
                continue
            try:
                catalog = read_registry_snapshot(
                    data.registry_json.encode("utf8"), name, origin=origin
                )
                window = release_window(
                    runtime, catalog, pin, data.target, prerelease=bundle.prerelease
                )
                row["window"] = asdict(window)
                if window.status in ("ready", "incomplete", "no_upgrade"):
                    # npm supplies validated base components; this is display arithmetic only.
                    bases = runtime.validate_many([pin, window.target])
                    before, after = (tuple(map(int, value["base"].split("."))) for value in bases)
                    row["version_gap"] = {
                        "kind": next(
                            (
                                name
                                for name, a, b in zip(
                                    ("major", "minor", "patch"), before, after, strict=True
                                )
                                if a != b
                            ),
                            "same_base",
                        ),
                        "installed_components": dict(
                            zip(("major", "minor", "patch"), before, strict=True)
                        ),
                        "target_components": dict(
                            zip(("major", "minor", "patch"), after, strict=True)
                        ),
                        "major_versions_crossed": after[0] - before[0],
                        "authority": "npm-semver/7.8.5",
                    }
                row["advisories"] = _advisories(
                    data, name, pin, window.target, runtime, origin, namespace
                )
                if data.notes is None:
                    row.update(status="incomplete", reason="release_notes_not_supplied")
                    continue
                notes = parse_changelog(data.notes.encode("utf8"), name, runtime)
                selection = select_spans(notes, window, runtime, max_spans=remaining)
                remaining -= len(selection.spans)
                row["coverage"] = asdict(selection)
                row["coverage"].pop("spans")
                row["entries"], row["source"] = _entries(data, notes, selection, method, namespace)
                row["status"] = "complete" if selection.status == "ready" else "incomplete"
                if any(
                    e["status"] in ("unknown", "unavailable", "error", "unsupported")
                    for e in row["entries"]
                ):
                    row["status"] = "incomplete"
                if any(
                    s == "not_fetched" for s in row["advisories"]["source_status"].values()
                ) or any(
                    a["status"] in ("error", "unsupported") for a in row["advisories"]["rows"]
                ):
                    row["status"] = "incomplete"
                row["reason"] = "review_checklist_generated"
            except (ValueError, TypeError, UnicodeError, VersionRuntimeError, RecursionError):
                if "advisories" not in row:
                    row["advisories"] = _advisories(
                        data, name, pin, None, runtime, origin, namespace
                    )
                row.update(status="error", reason="package_input_or_runtime_unavailable")
    finally:
        if owned:
            runtime.close()
    entries = [e for p in reports for e in p["entries"]]
    return {
        "edition": "s5-checklist/1",
        "mode": "offline",
        "origin": bundle.origin,
        "input_bundle_sha256": bundle_hash,
        "manifest_sha256": manifest.sha256,
        "lock_sha256": lock.sha256 if lock else None,
        "config": config,
        "config_sha256": canonical_digest(config),
        "method": method,
        "provider_calls": 0,
        "semantic_quality": "unmeasured",
        "workflow_status": "partial"
        if any(p["status"] != "complete" for p in reports)
        else "review_required",
        "packages": reports,
        "counts": {
            "packages": len(reports),
            "selected_entries_expected": sum(
                p.get("coverage", {}).get("selected_total", 0) for p in reports
            ),
            "packages_with_unknown_entry_coverage": sum("coverage" not in p for p in reports),
            "processed_entries": len(entries),
            "judged_entries": sum(
                e.get("judgment", {}).get("judgment") is not None for e in entries
            ),
            "entry_statuses": dict(Counter(e["status"] for e in entries)),
            "span_cap_remaining": remaining,
            "advisory_records": sum(
                p.get("advisories", {}).get("records_expected", 0) for p in reports
            ),
        },
        "limitations": [
            "Keyword heuristic requires review; no measured semantic/model quality.",
            "Typed/generative requests remain unavailable offline; no fallback results.",
            "Advisory membership is separate from conditional usage and repository reachability.",
            "Supplied immutable snapshots have unverified authenticity and online currentness.",
            "No dependency changes, source execution, fetching, live SDK, deployment or campaign.",
        ],
    }
