"""what_bug_this_catches: portable rendering hides evidence or promotes unresolved claims."""

from dataclasses import replace

import pytest

from changelog_advisor import report
from changelog_advisor.shared.cited import ArtifactRef, Finding, Registry, ResolutionContext
from changelog_advisor.shared.cited.assessment import EvidenceAssessment, assess_required_evidence
from changelog_advisor.shared.cited.markdown import escape_markdown, render_assessment
from changelog_advisor.shared.cited.memory import (
    MemorySource,
    MemoryTextResolver,
    install_supplied_text,
)
from changelog_advisor.shared.cited.models import LineLocator, SuppliedLinePointer


def assessment(*, supported=True, verdict="partial", text="Potential <script>change</script>"):
    source = MemorySource.from_bytes(
        namespace_id="ns",
        source_id="notes",
        source_revision="r1",
        raw=b"Literal evidence\n",
        newline_policy="identity",
    )

    class Policy:
        reference = ArtifactRef(artifact_id="p", artifact_sha256="a" * 64, profile_id="p/1")

        def decision(self, namespace, identity):
            return "allow" if (namespace, identity) == ("ns", "notes") else "deny"

        def current(self, namespace, identity):
            return source.metadata if (namespace, identity) == ("ns", "notes") else None

    policy = Policy()
    context = ResolutionContext(
        namespace_id="ns",
        access_policy_ref=policy.reference,
        generation_policy_ref=policy.reference,
    )
    pointer = SuppliedLinePointer(
        kind="file:line",
        source_type="supplied_text",
        locator_subtype="line",
        source_id="notes",
        source_sha256=source.metadata.source_sha256,
        source_revision="r1",
        evidence_artifact_sha256=source.metadata.evidence_artifact_sha256,
        locator=LineLocator(
            line_start=1,
            line_end=1,
            quote="Literal evidence\n",
            excerpt_sha256=source.metadata.source_sha256,
        ),
    )
    registry = Registry()
    if supported:
        install_supplied_text(
            registry, MemoryTextResolver((source,), access=policy, generation=policy)
        )
    finding = Finding(
        id="claim-[1]", text=text, verdict=verdict, probability=1.0, evidence=(pointer,)
    )
    return assess_required_evidence(finding, registry, context)


def test_actual_assessed_finding_keeps_partial_and_all_source_locator_quote_fields():
    value = assessment()
    markdown = render_assessment(value)
    assert "Verdict: partial" in markdown and "verified" not in markdown
    assert "Evidence: required 1; resolved 1; unresolved 0" in markdown
    assert "&lt;script&gt;" in markdown and "<script>" not in markdown
    assert "> Literal evidence" in markdown
    pointer = value.finding.evidence[0]
    assert pointer.source_sha256 in markdown and pointer.evidence_artifact_sha256 in markdown
    assert "Declared excerpt SHA256: " + pointer.locator.excerpt_sha256 in markdown
    assert "Reported excerpt SHA256: " + value.resolutions[0].excerpt_sha256 in markdown
    assert "Reported resolution: resolved" in markdown and "line\\_start" in markdown
    assert "Reported probability: 1\\.0" in markdown


def test_uninstalled_evidence_is_not_hidden_and_cannot_promote_unsupported():
    value = assessment(supported=False)
    markdown = render_assessment(value)
    assert "Verdict: unsupported" in markdown
    assert "Evidence: required 1; resolved 0; unresolved 1" in markdown
    assert "domain\\_not\\_installed" in markdown and "Unresolved quoted claim:" in markdown
    # A caller-constructed partial label cannot bypass actual unresolved counts.
    forged_label = replace(value, finding=value.finding.model_copy(update={"verdict": "partial"}))
    assert "Verdict: unsupported" in render_assessment(forged_label)
    assert "Verdict: unsupported" in render_assessment(assessment(verdict="unsupported"))


def test_empty_evidence_and_false_reason_counts_do_not_invent_support():
    finding = Finding(id="claim", text="Unproven", verdict="partial", evidence=())
    value = EvidenceAssessment(finding, (), (("synthetic_count", 100),))
    markdown = render_assessment(value)
    assert "Verdict: unsupported" in markdown and "No required evidence supplied." in markdown
    assert "Evidence: required 0; resolved 0; unresolved 0" in markdown
    assert "100" not in markdown


def test_unresolved_pointer_keeps_declared_digest_separate_from_reported_result():
    """what_bug_this_catches: S5-RV2-001 drops an unresolved quote's unique digest."""
    import hashlib

    value = assessment(supported=False)
    quote = "Unique unresolved quotation, distinct from the source's complete text.\n"
    digest = hashlib.sha256(quote.encode("utf8")).hexdigest()
    pointer = value.finding.evidence[0].model_copy(
        update={
            "locator": LineLocator(line_start=1, line_end=1, quote=quote, excerpt_sha256=digest)
        }
    )
    assert digest not in (pointer.source_sha256, pointer.evidence_artifact_sha256)
    ref = ArtifactRef(artifact_id="p", artifact_sha256="a" * 64, profile_id="p/1")
    context = ResolutionContext(namespace_id="ns", access_policy_ref=ref, generation_policy_ref=ref)
    actual = assess_required_evidence(
        value.finding.model_copy(update={"evidence": (pointer,)}), Registry(), context
    )
    assert actual.resolutions[0].excerpt_sha256 is None
    markdown = render_assessment(actual)
    assert "Declared excerpt SHA256: " + digest in markdown
    assert "Reported excerpt SHA256:" not in markdown
    assert "Unresolved quoted claim:" in markdown and escape_markdown(quote.rstrip()) in markdown
    assert "domain\\_not\\_installed" in markdown and "Verdict: unsupported" in markdown


@pytest.mark.parametrize(
    "field", ["checked_source_sha256", "checked_source_revision", "checked_artifact_sha256"]
)
def test_misbound_reported_resolution_refuses_before_render(field):
    value = assessment()
    changed = "other" if field == "checked_source_revision" else "b" * 64
    result = value.resolutions[0].model_copy(update={field: changed})
    with pytest.raises(ValueError):
        render_assessment(replace(value, resolutions=(result,)))


def test_wrong_literal_or_missing_ordered_resolution_refuses():
    value = assessment()
    # A valid excerpt/digest belongs to a different literal, despite matching source identity.
    import hashlib

    result = value.resolutions[0].model_copy(
        update={"excerpt": "other", "excerpt_sha256": hashlib.sha256(b"other").hexdigest()}
    )
    with pytest.raises(ValueError):
        render_assessment(replace(value, resolutions=(result,)))
    with pytest.raises(ValueError):
        render_assessment(replace(value, resolutions=()))
    with pytest.raises(ValueError):
        render_assessment(replace(value, resolutions=[value.resolutions[0]]))
    with pytest.raises(ValueError):
        render_assessment(replace(value, resolutions=value.resolutions * 129))


@pytest.mark.parametrize("bound", [0, -1, True, 1048577, 10])
def test_output_is_bounded_without_returning_truncated_evidence(bound):
    with pytest.raises(ValueError):
        render_assessment(assessment(), max_output_bytes=bound)


def test_exact_utf8_output_bound_and_existing_app_escaping_are_shared():
    value = assessment(text="é <image src='remote'> [label](javascript:action)")
    markdown = render_assessment(value)
    length = len(markdown.encode("utf8"))
    assert render_assessment(value, max_output_bytes=length) == markdown
    with pytest.raises(ValueError):
        render_assessment(value, max_output_bytes=length - 1)
    assert report.md is escape_markdown
    assert (
        escape_markdown("<script>[x](url)</script>")
        == "&lt;script&gt;\\[x\\]\\(url\\)&lt;/script&gt;"
    )


def test_reported_method_and_provenance_are_metadata_not_semantic_promotion():
    from changelog_advisor.shared.cited.models import MethodRef, ResolutionProvenance

    value = assessment()
    ref = ArtifactRef(artifact_id="trace", artifact_sha256="c" * 64, profile_id="trace/1")
    pointer = value.finding.evidence[0].model_copy(update={"provenance_ref": ref})
    finding = value.finding.model_copy(
        update={
            "confidence": 0.5,
            "evidence": (pointer,),
            "method": MethodRef(
                method_id="rules",
                origin="deterministic",
                policy_sha256="d" * 64,
                model_requested="unmeasured",
                model_reported="unmeasured",
            ),
        }
    )
    resolution = value.resolutions[0].model_copy(
        update={"provenance": ResolutionProvenance(profile_ref=ref)}
    )
    markdown = render_assessment(replace(value, finding=finding, resolutions=(resolution,)))
    assert "Verdict: partial" in markdown and "Reported confidence: 0\\.5" in markdown
    assert "Method policy SHA256: " + "d" * 64 in markdown
    assert "Reported requested model: unmeasured" in markdown
    assert "Reported returned model: unmeasured" in markdown
    assert "Pointer provenance ref:" in markdown and "Reported provenance:" in markdown
    assert "c" * 64 in markdown
