"""what_bug_this_catches: saved anchors resolve outside their snapshot, scope or access grant."""

import hashlib
from dataclasses import replace

import pytest

from changelog_advisor.shared.cited import ArtifactRef, Finding, Registry, ResolutionContext
from changelog_advisor.shared.cited.assessment import assess_required_evidence
from changelog_advisor.shared.cited.fragments import (
    FRAGMENT_KEY,
    SavedFragmentResolver,
    SavedWebSource,
    install_saved_fragments,
)
from changelog_advisor.shared.cited.memory import MemoryBounds, SectionSpan
from changelog_advisor.shared.cited.models import FragmentLocator, FragmentPointer
from changelog_advisor.shared.cited.registry import DuplicateResolverError


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def source(**changes):
    args = dict(
        namespace_id="saved-1",
        source_id="release-page",
        source_revision="capture-1",
        raw="Title\r\nLiteral é <script>x</script>\r\nOutside word\r\n".encode(),
        newline_policy="crlf-to-lf",
        fragments=(SectionSpan("alpha", 2, 2), SectionSpan("beta", 3, 3)),
    )
    args.update(changes)
    return SavedWebSource.from_bytes(**args)


class Policy:
    reference = ArtifactRef(artifact_id="policy", artifact_sha256="a" * 64, profile_id="local/1")

    def __init__(self, retained):
        self.retained = retained
        self.decisions = ["allow", "allow"]
        self.generations = [retained.metadata, retained.metadata]

    def decision(self, namespace, identity):
        if (namespace, identity) != (
            self.retained.text.namespace_id,
            self.retained.metadata.source_id,
        ):
            return "deny"
        return self.decisions.pop(0) if len(self.decisions) > 1 else self.decisions[0]

    def current(self, namespace, identity):
        if (namespace, identity) != (
            self.retained.text.namespace_id,
            self.retained.metadata.source_id,
        ):
            return None
        return self.generations.pop(0) if len(self.generations) > 1 else self.generations[0]


def pointer(retained, *, fragment="alpha", quote=None, **changes):
    values = dict(
        kind="url#fragment",
        source_type="saved_web",
        locator_subtype="fragment",
        source_id=retained.metadata.source_id,
        source_revision=retained.metadata.source_revision,
        source_sha256=retained.metadata.source_sha256,
        evidence_artifact_sha256=retained.metadata.evidence_artifact_sha256,
        locator=FragmentLocator(
            fragment_id=fragment,
            quote=quote,
            excerpt_sha256=sha(quote.encode()) if quote is not None else None,
        ),
    )
    values.update(changes)
    return FragmentPointer(**values)


def setup(retained=None):
    retained = source() if retained is None else retained
    policy = Policy(retained)
    context = ResolutionContext(
        namespace_id=retained.text.namespace_id,
        access_policy_ref=policy.reference,
        generation_policy_ref=policy.reference,
        required_scope="text",
    )
    resolver = SavedFragmentResolver((retained,), access=policy, generation=policy)
    registry = Registry()
    install_saved_fragments(registry, resolver)
    return retained, policy, context, resolver, registry


@pytest.mark.parametrize("quote", [None, "Literal é", "<script>x</script>"])
def test_actual_anchor_resolves_only_literal_retained_text_and_keeps_semantics_partial(quote):
    retained, _, context, _, registry = setup()
    p = pointer(retained, quote=quote)
    result = registry.resolve(p, context)
    assert result.status == "resolved"
    assert result.excerpt == (quote if quote is not None else "Literal é <script>x</script>\n")
    assert result.checked_source_sha256 == sha(retained.text.raw)
    assert result.checked_artifact_sha256 != retained.text.metadata.evidence_artifact_sha256
    assert result.excerpt_sha256 == sha(result.excerpt.encode())
    finding = Finding(id="claim", text="Potential change", verdict="partial", evidence=(p,))
    assert assess_required_evidence(finding, registry, context).finding.verdict == "partial"
    assert Registry().resolve(p, context).reason == "domain_not_installed"


@pytest.mark.parametrize(
    "quote", ["Outside word", "literal é", "Literal e", "Literal e\u0301", "Literal é\r\n"]
)
def test_quote_in_another_anchor_case_or_unicode_is_not_equivalent(quote):
    retained, _, context, _, registry = setup()
    p = pointer(retained, quote=quote)
    result = registry.resolve(p, context)
    assert result.status == "invalid" and result.reason == "quote_outside_fragment"
    finding = Finding(id="claim", text="Potential change", verdict="partial", evidence=(p,))
    assessment = assess_required_evidence(finding, registry, context)
    assert assessment.finding.verdict == "unsupported"
    assert assessment.required_count == assessment.unresolved_count == 1


@pytest.mark.parametrize("field", ["source_revision", "source_sha256", "evidence_artifact_sha256"])
def test_stale_pointer_never_uses_matching_text_in_another_generation(field):
    retained, _, context, _, registry = setup()
    changed = "other-generation" if field == "source_revision" else "b" * 64
    assert registry.resolve(pointer(retained, **{field: changed}), context).status == "stale"


@pytest.mark.parametrize("decision", ["deny", "unknown", True, None])
def test_missing_or_nonliteral_access_refuses_before_disclosure(decision):
    retained, policy, context, _, registry = setup()
    policy.decisions = [decision]
    result = registry.resolve(pointer(retained), context)
    assert result.status == "unsupported" and result.excerpt is None


@pytest.mark.parametrize("change", ["revoke", "generation", "unknown", "wrong_type", "policy_ref"])
def test_current_policy_and_generation_rechecked_before_disclosure(change):
    retained, policy, context, _, registry = setup()
    if change == "revoke":
        policy.decisions = ["allow", "deny"]
    if change == "generation":
        policy.generations[1] = retained.metadata.model_copy(
            update={"source_revision": "capture-2"}
        )
    if change == "unknown":
        policy.generations = [None]
    if change == "wrong_type":
        policy.generations = [retained.text.metadata]
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


def test_namespace_retained_missing_fragment_and_wrong_domain_are_not_fallbacks():
    retained, policy, context, resolver, registry = setup()
    assert (
        registry.resolve(pointer(retained, fragment="absent"), context).reason == "fragment_missing"
    )
    foreign = context.model_copy(update={"namespace_id": "foreign"})
    assert registry.resolve(pointer(retained), foreign).status == "unsupported"
    missing = SavedFragmentResolver((), access=policy, generation=policy)
    assert missing.resolve(pointer(retained), context).status == "missing"
    for mode in ("spatial", "text_and_spatial"):
        assert (
            registry.resolve(
                pointer(retained), context.model_copy(update={"required_scope": mode})
            ).status
            == "unsupported"
        )
    assert (
        resolver.resolve(
            pointer(retained), context.model_copy(update={"generation_mode": "retained_historical"})
        ).status
        == "unsupported"
    )
    wrong = pointer(retained).model_dump()
    wrong.update(kind="doc:section", source_type="supplied_text", locator_subtype="section")
    assert resolver.resolve(wrong, context).status == "invalid"


@pytest.mark.parametrize("mutation", ["raw", "canonical", "anchors", "metadata"])
def test_changed_retained_bytes_anchor_map_or_metadata_cannot_retarget_pointer(mutation):
    retained, _, context, resolver, registry = setup()
    p = pointer(retained)
    if mutation == "raw":
        text = replace(retained.text, raw=b"Changed")
    elif mutation == "canonical":
        text = replace(retained.text, canonical=b"Changed")
    elif mutation == "anchors":
        text = replace(retained.text, sections=(SectionSpan("alpha", 3, 3),))
    else:
        text = retained.text
    changed = replace(retained, text=text)
    if mutation == "metadata":
        changed = replace(
            changed, metadata=retained.metadata.model_copy(update={"raw_byte_length": 1})
        )
    resolver._sources[
        (retained.text.namespace_id, retained.metadata.source_id, retained.metadata.source_revision)
    ] = changed
    result = registry.resolve(p, context)
    assert result.status == "invalid" and result.excerpt is None


def test_profile_hash_binds_anchor_map_and_install_preserves_existing_owner():
    original = source()
    moved = source(fragments=(SectionSpan("alpha", 3, 3),))
    assert original.metadata.source_sha256 == moved.metadata.source_sha256
    assert original.metadata.evidence_artifact_sha256 != moved.metadata.evidence_artifact_sha256
    _, _, _, resolver, registry = setup(original)
    with pytest.raises(DuplicateResolverError):
        install_saved_fragments(registry, resolver)
    assert registry.installed_domains == frozenset({FRAGMENT_KEY})


@pytest.mark.parametrize(
    "bad", ["mutable", "duplicate", "source_cap", "byte_cap", "line_cap", "anchor_cap", "total_cap"]
)
def test_constructor_bounds_and_duplicate_capture_refuse(bad):
    retained = source()
    policy = Policy(retained)
    values = (retained,)
    bounds = MemoryBounds()
    if bad == "mutable":
        values = [retained]
    if bad == "duplicate":
        values = (retained, retained)
    if bad == "source_cap":
        values = (retained, source(source_id="second"))
        bounds = MemoryBounds(max_sources=1)
    if bad == "byte_cap":
        bounds = MemoryBounds(max_source_bytes=1)
    if bad == "line_cap":
        bounds = MemoryBounds(max_lines=1)
    if bad == "anchor_cap":
        bounds = MemoryBounds(max_sections=1)
    if bad == "total_cap":
        bounds = MemoryBounds(max_retained_bytes=1)
    with pytest.raises((ValueError, TypeError)):
        SavedFragmentResolver(values, access=policy, generation=policy, bounds=bounds)


def test_empty_capture_and_oversize_excerpt_do_not_invent_or_truncate_text():
    empty, _, context, _, registry = setup(source(raw=b"", fragments=()))
    assert registry.resolve(pointer(empty), context).reason == "fragment_missing"
    large, _, context, _, registry = setup(
        source(raw=b"x" * 32769, fragments=(SectionSpan("alpha", 1, 1),))
    )
    result = registry.resolve(pointer(large), context)
    assert result.reason == "excerpt_limit_exceeded" and result.excerpt is None
    assert registry.resolve(pointer(large, quote="xxx"), context).excerpt == "xxx"


def test_same_metadata_in_a_permitted_foreign_namespace_still_has_no_retained_capture():
    retained, policy, context, _, registry = setup()
    policy.decision = lambda *args: "allow"
    policy.current = lambda *args: retained.metadata
    result = registry.resolve(
        pointer(retained), context.model_copy(update={"namespace_id": "foreign"})
    )
    assert result.status == "missing" and result.excerpt is None


def test_policy_failure_is_sanitized_and_final_reference_change_is_refused():
    retained, policy, context, _, registry = setup()

    def failed(*args):
        raise ValueError("untrusted private policy details")

    policy.current = failed
    result = registry.resolve(pointer(retained), context)
    assert result.reason == "policy_unavailable" and result.excerpt is None
    assert "private" not in result.model_dump_json()

    def changed(*args):
        policy.reference = policy.reference.model_copy(update={"artifact_sha256": "c" * 64})
        return retained.metadata

    policy.current = changed
    result = registry.resolve(pointer(retained), context)
    assert result.reason == "policy_reference_mismatch" and result.excerpt is None
