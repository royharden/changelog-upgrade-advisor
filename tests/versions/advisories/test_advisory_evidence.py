"""what_bug_this_catches: advisory citations trust forged projections or skip current access."""

import hashlib
import json
from dataclasses import replace

import pytest

from changelog_advisor.shared.cited import ArtifactRef, Finding, Registry, ResolutionContext
from changelog_advisor.shared.cited.assessment import assess_required_evidence
from changelog_advisor.shared.cited.models import AdvisoryLocator, AdvisoryPointer
from changelog_advisor.shared.cited.registry import DuplicateResolverError
from changelog_advisor.shared.versions.evidence import (
    ADVISORY_KEY,
    AdvisoryRecordResolver,
    AdvisorySource,
    install_advisory_records,
)
from changelog_advisor.shared.versions.ghsa import normalize_ghsa
from changelog_advisor.shared.versions.osv import normalize_osv


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def source(kind="osv", **changes):
    payload = dict(
        summary="Literal é vulnerability",
        modified="2026-10-15T00:00:00Z",
        details="Untrusted <script>text</script>",
    )
    if kind == "osv":
        payload.update(id="OSV-EXAMPLE-1", affected=[])
        normalize = normalize_osv
    else:
        payload.update(
            ghsa_id="GHSA-aaaa-bbbb-cccc", updated_at=payload.pop("modified"), vulnerabilities=[]
        )
        payload["description"] = payload.pop("details")
        normalize = normalize_ghsa
    payload.update(changes)
    record = normalize(json.dumps(payload, ensure_ascii=False).encode(), origin="synthetic")
    return AdvisorySource.from_record(record, namespace_id="ns")


class Policy:
    reference = ArtifactRef(artifact_id="p", artifact_sha256="a" * 64, profile_id="p/1")

    def __init__(self, retained):
        self.retained = retained
        self.decisions = ["allow", "allow"]
        self.generations = [retained.metadata, retained.metadata]

    def decision(self, namespace, identity):
        if (namespace, identity) != (self.retained.namespace_id, self.retained.metadata.source_id):
            return "deny"
        return self.decisions.pop(0) if len(self.decisions) > 1 else self.decisions[0]

    def current(self, namespace, identity):
        if (namespace, identity) != (self.retained.namespace_id, self.retained.metadata.source_id):
            return None
        return self.generations.pop(0) if len(self.generations) > 1 else self.generations[0]


def setup(kind="osv"):
    retained = source(kind)
    policy = Policy(retained)
    context = ResolutionContext(
        namespace_id="ns",
        access_policy_ref=policy.reference,
        generation_policy_ref=policy.reference,
    )
    resolver = AdvisoryRecordResolver((retained,), access=policy, generation=policy)
    registry = Registry()
    install_advisory_records(registry, resolver)
    return retained, policy, context, resolver, registry


def pointer(retained, *, quote="Literal é vulnerability", identity=None, **changes):
    values = dict(
        kind="advisory:id",
        source_type="advisory_record",
        locator_subtype="id",
        source_id=retained.metadata.source_id,
        source_sha256=retained.metadata.source_sha256,
        source_revision=retained.metadata.source_revision,
        evidence_artifact_sha256=retained.metadata.evidence_artifact_sha256,
        locator=AdvisoryLocator(
            advisory_id=retained.record.id if identity is None else identity,
            quote=quote,
            excerpt_sha256=sha(quote.encode()) if quote is not None else None,
        ),
    )
    values.update(changes)
    return AdvisoryPointer(**values)


@pytest.mark.parametrize("kind", ["osv", "ghsa"])
@pytest.mark.parametrize("quote", ["Literal é vulnerability", "<script>text</script>"])
def test_actual_canonical_osv_and_ghsa_quote_fidelity_is_not_applicability(kind, quote):
    retained, _, context, _, registry = setup(kind)
    p = pointer(retained, quote=quote)
    result = registry.resolve(p, context)
    assert result.status == "resolved" and result.excerpt == quote
    assert result.checked_source_sha256 == sha(retained.record.raw)
    assert result.checked_source_revision == "sha256:" + sha(retained.record.raw)
    assert result.reason == "literal_quote_resolved"
    finding = Finding(id="claim", text="Potential impact", verdict="partial", evidence=(p,))
    assert assess_required_evidence(finding, registry, context).finding.verdict == "partial"
    assert Registry().resolve(p, context).reason == "domain_not_installed"


@pytest.mark.parametrize(
    "quote", [None, "absent", "literal é vulnerability", "Literal e\u0301 vulnerability"]
)
def test_missing_or_nonliteral_quote_is_retained_as_unresolved(quote):
    retained, _, context, _, registry = setup()
    p = pointer(retained, quote=quote)
    result = registry.resolve(p, context)
    assert result.status == "invalid" and result.excerpt is None
    assessment = assess_required_evidence(
        Finding(id="claim", text="Potential impact", verdict="partial", evidence=(p,)),
        registry,
        context,
    )
    assert assessment.required_count == assessment.unresolved_count == 1
    assert assessment.finding.verdict == "unsupported"


@pytest.mark.parametrize("field", ["source_revision", "source_sha256", "evidence_artifact_sha256"])
def test_stale_source_generation_or_projection_refuses(field):
    retained, _, context, _, registry = setup()
    changed = "stale-revision" if field == "source_revision" else "b" * 64
    result = registry.resolve(pointer(retained, **{field: changed}), context)
    assert result.status == "stale" and result.excerpt is None


@pytest.mark.parametrize("mutation", ["summary", "details", "id", "sha256", "raw", "origin"])
def test_forged_normalized_record_cannot_replace_canonical_raw_binding(mutation):
    retained = source()
    value = b"{}" if mutation == "raw" else "b" * 64 if mutation == "sha256" else "changed"
    forged = replace(retained.record, **{mutation: value})
    with pytest.raises((ValueError, TypeError)):
        AdvisorySource.from_record(forged, namespace_id="ns")


@pytest.mark.parametrize("change", ["record", "metadata"])
def test_runtime_retained_mutation_is_not_disclosed(change):
    retained, _, context, resolver, registry = setup()
    if change == "record":
        changed = replace(retained, record=replace(retained.record, summary="changed"))
    else:
        changed = replace(
            retained, metadata=retained.metadata.model_copy(update={"raw_byte_length": 0})
        )
    resolver._sources[("ns", retained.metadata.source_id, retained.metadata.source_revision)] = (
        changed
    )
    result = registry.resolve(pointer(retained), context)
    assert result.status == "invalid" and result.excerpt is None


@pytest.mark.parametrize("decision", ["deny", "unknown", True, None])
def test_only_literal_allow_with_current_policy_can_disclose(decision):
    retained, policy, context, _, registry = setup()
    policy.decisions = [decision]
    assert registry.resolve(pointer(retained), context).reason == "access_not_allowed"


@pytest.mark.parametrize("change", ["revoke", "generation", "unknown", "policy_ref", "wrong_type"])
def test_policy_and_current_generation_are_rechecked(change):
    retained, policy, context, _, registry = setup()
    if change == "revoke":
        policy.decisions = ["allow", "deny"]
    if change == "generation":
        policy.generations[1] = retained.metadata.model_copy(update={"source_revision": "changed"})
    if change == "unknown":
        policy.generations = [None]
    if change == "wrong_type":
        policy.generations = [retained.metadata.model_copy(update={"source_type": "saved_web"})]
    if change == "policy_ref":
        context = context.model_copy(
            update={
                "access_policy_ref": policy.reference.model_copy(
                    update={"artifact_sha256": "b" * 64}
                )
            }
        )
    result = registry.resolve(pointer(retained), context)
    assert result.status != "resolved" and result.excerpt is None


def test_primary_identity_namespace_and_text_only_current_scope_are_explicit():
    retained, policy, context, resolver, registry = setup()
    assert registry.resolve(pointer(retained, identity="OTHER-ID"), context).status == "invalid"
    assert (
        registry.resolve(
            pointer(retained), context.model_copy(update={"namespace_id": "other"})
        ).status
        == "unsupported"
    )
    policy.decision = lambda *args: "allow"
    policy.current = lambda *args: retained.metadata
    assert (
        registry.resolve(
            pointer(retained), context.model_copy(update={"namespace_id": "other"})
        ).status
        == "missing"
    )
    assert (
        AdvisoryRecordResolver((), access=policy, generation=policy)
        .resolve(pointer(retained), context)
        .status
        == "missing"
    )
    for scope in ("spatial", "text_and_spatial"):
        assert (
            registry.resolve(
                pointer(retained), context.model_copy(update={"required_scope": scope})
            ).status
            == "unsupported"
        )
    assert (
        resolver.resolve(
            pointer(retained), context.model_copy(update={"generation_mode": "retained_historical"})
        ).status
        == "unsupported"
    )


@pytest.mark.parametrize("bad", ["mutable", "duplicate", "count", "bytes", "bool_bound"])
def test_explicit_source_collection_bounds(bad):
    retained, policy, _, _, _ = setup()
    values = (
        [retained]
        if bad == "mutable"
        else (retained, retained)
        if bad in ("duplicate", "count")
        else (retained,)
    )
    kwargs = (
        {"max_sources": 1}
        if bad == "count"
        else {"max_retained_bytes": 1}
        if bad == "bytes"
        else {"max_sources": True}
        if bad == "bool_bound"
        else {}
    )
    with pytest.raises((TypeError, ValueError)):
        AdvisoryRecordResolver(values, access=policy, generation=policy, **kwargs)


def test_registration_preserves_existing_domain_owner():
    _, _, _, resolver, registry = setup()
    with pytest.raises(DuplicateResolverError):
        install_advisory_records(registry, resolver)
    assert registry.installed_domains == frozenset({ADVISORY_KEY})
