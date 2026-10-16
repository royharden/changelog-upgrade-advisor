"""Bounded literal Markdown from reported assessed evidence; no source or model execution."""

import html
import json
import re

from .assessment import EvidenceAssessment
from .models import Finding, Resolution

MAX_OUTPUT_BYTES = 1024 * 1024


def escape_markdown(value: object) -> str:
    """Shared literal escaping for generic findings and the application checklist."""
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~\-])", r"\\\1", html.escape(str(value)))


def _validated(assessment: EvidenceAssessment) -> tuple[Finding, tuple[Resolution, ...]]:
    if type(assessment) is not EvidenceAssessment or type(assessment.resolutions) is not tuple:
        raise ValueError("explicit immutable evidence assessment required")
    if len(assessment.resolutions) > 128:
        raise ValueError("assessment resolution bound exceeded")
    try:
        finding = Finding.model_validate(assessment.finding)
        resolutions = tuple(Resolution.model_validate(item) for item in assessment.resolutions)
    except Exception:
        raise ValueError("invalid assessed evidence") from None
    if len(resolutions) != len(finding.evidence):
        raise ValueError("every required pointer needs its ordered resolution")
    for pointer, result in zip(finding.evidence, resolutions, strict=True):
        if result.status != "resolved":
            continue
        if (
            result.checked_source_sha256 != pointer.source_sha256
            or result.checked_source_revision != pointer.source_revision
            or result.checked_artifact_sha256 != pointer.evidence_artifact_sha256
        ):
            raise ValueError("resolution does not match pointer identity")
        locator = pointer.locator
        if locator is not None and (
            (getattr(locator, "quote", None) is not None and result.excerpt != locator.quote)
            or (
                getattr(locator, "excerpt_sha256", None) is not None
                and result.excerpt is not None
                and result.excerpt_sha256 != locator.excerpt_sha256
            )
        ):
            raise ValueError("resolution does not match declared literal excerpt")
    return finding, resolutions


def render_assessment(
    assessment: EvidenceAssessment, *, max_output_bytes: int = MAX_OUTPUT_BYTES
) -> str:
    """Render reported results, preserving all required evidence and conservative verdicts.

    Caller must obtain the assessment through its actual source/policy resolver.
    Structural rendering cannot authenticate source access, execution or semantic truth.
    """
    if type(max_output_bytes) is not int or not 1 <= max_output_bytes <= MAX_OUTPUT_BYTES:
        raise ValueError("output bound must be a positive integer within 1MiB")
    finding, resolutions = _validated(assessment)
    resolved = sum(result.status == "resolved" for result in resolutions)
    required = len(finding.evidence)
    verdict = "unsupported" if not required or resolved != required else finding.verdict
    lines: list[str] = []
    size = 0

    def add(value: str = "") -> None:
        nonlocal size
        size += len(value.encode("utf8")) + 1
        if size > max_output_bytes:
            raise ValueError("complete assessment exceeds output bound")
        lines.append(value)

    literal = escape_markdown
    add("## Finding " + literal(finding.id))
    add()
    add(literal(finding.text))
    add()
    add("Verdict: " + verdict)
    add(f"Evidence: required {required}; resolved {resolved}; unresolved {required - resolved}")
    if finding.probability is not None:
        add("Reported probability: " + literal(finding.probability))
    if finding.confidence is not None:
        add("Reported confidence: " + literal(finding.confidence))
    if finding.method is not None:
        add(
            "Method: "
            + literal(finding.method.method_id)
            + "; origin "
            + literal(finding.method.origin)
        )
        add("Method policy SHA256: " + finding.method.policy_sha256)
        if finding.method.model_requested is not None:
            add("Reported requested model: " + literal(finding.method.model_requested))
        if finding.method.model_reported is not None:
            add("Reported returned model: " + literal(finding.method.model_reported))
    add()
    if not required:
        add("No required evidence supplied.")
    for index, (pointer, result) in enumerate(zip(finding.evidence, resolutions, strict=True), 1):
        add(f"### Evidence {index}")
        add()
        add(
            "Pointer: "
            + literal(" / ".join((pointer.kind, pointer.source_type, pointer.locator_subtype)))
        )
        add("Source: " + literal(pointer.source_id))
        add("Source SHA256: " + pointer.source_sha256)
        add("Source revision: " + literal(pointer.source_revision))
        add("Evidence artifact SHA256: " + pointer.evidence_artifact_sha256)
        if pointer.provenance_ref is not None:
            add(
                "Pointer provenance ref: "
                + literal(
                    json.dumps(pointer.provenance_ref.model_dump(mode="json"), sort_keys=True)
                )
            )
        locator = pointer.locator
        if locator is not None:
            coordinates = locator.model_dump(mode="json", exclude={"quote", "excerpt_sha256"})
            add("Locator: " + literal(json.dumps(coordinates, ensure_ascii=False, sort_keys=True)))
        add("Reported resolution: " + result.status + "; reason " + literal(result.reason))
        if result.scope is not None:
            add("Reported scope: " + literal(result.scope))
        if result.provenance is not None:
            add(
                "Reported provenance: "
                + literal(json.dumps(result.provenance.model_dump(mode="json"), sort_keys=True))
            )
        if result.excerpt_sha256 is not None:
            add("Reported excerpt SHA256: " + result.excerpt_sha256)
        quote = result.excerpt if result.status == "resolved" else getattr(locator, "quote", None)
        add()
        if quote is not None:
            if result.status != "resolved":
                add("Unresolved quoted claim:")
                add()
            for line in quote.splitlines():
                add("> " + literal(line))
        else:
            add("No text excerpt supplied.")
        add()
    add("Literal resolution is not semantic verification or source authentication.")
    return "\n".join(lines) + "\n"
