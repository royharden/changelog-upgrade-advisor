"""Closed domain values. Probabilities and literal evidence never certify semantics."""

import json
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from ..shared.callledger.models import NormalizedUsage, canonical_digest
from ..shared.cited.models import Digest, LogicalID, Probability, Revision, WireModel
from ..shared.providers.models import SourceCaptureRef
from ..shared.screen.models import ScreenPolicy, UntrustedText
from ..shared.versions.models import package_name

Category = Literal[
    "removed", "renamed", "changed_default", "behaviour_change", "pure_deprecation", "none"
]
CATEGORIES = (
    "removed",
    "renamed",
    "changed_default",
    "behaviour_change",
    "pure_deprecation",
    "none",
)
SCREEN_POLICY = ScreenPolicy(version="s5-entry-screen/1", required_method="rules")


class JudgeInput(WireModel):
    span_id: LogicalID
    package: Annotated[str, Field(min_length=1, max_length=214)]
    source_generation: Revision
    source_sha256: Digest
    text: Annotated[str, Field(min_length=1, max_length=8192)]
    context: Annotated[tuple[str, ...], Field(max_length=32)] = ()
    snippet: Annotated[str, Field(max_length=8192)] | None = None

    @model_validator(mode="after")
    def bounds(self) -> Self:
        package_name(self.package)
        if len(self.text.encode("utf8")) > 8192:
            raise ValueError("entry byte cap")
        if sum(len(part.encode("utf8")) for part in self.context) > 8192:
            raise ValueError("context byte cap")
        if self.snippet is not None and len(self.snippet.encode("utf8")) > 8192:
            raise ValueError("snippet byte cap")
        # Encoding overhead also counts: no hidden truncation to fit the screen.
        if len(self.screen_source().text.encode("utf8")) > 32768:
            raise ValueError("combined model input byte cap")
        return self

    @property
    def sha256(self) -> str:
        return canonical_digest(self.model_dump(mode="json"))

    def screen_source(self) -> UntrustedText:
        data = {"entry": self.text, "context": self.context, "usage_snippet": self.snippet}
        return UntrustedText(
            self.span_id,
            self.source_generation,
            json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        )


class JudgePolicy(WireModel):
    version: Literal["s5-semantic/1"] = "s5-semantic/1"
    options: tuple[Category, ...] = CATEGORIES

    @model_validator(mode="after")
    def exact_options(self) -> Self:
        if len(self.options) != 6 or set(self.options) != set(CATEGORIES):
            raise ValueError("exact six category permutation required")
        return self

    @property
    def sha256(self) -> str:
        return canonical_digest(self.model_dump(mode="json"))


DEFAULT_POLICY = JudgePolicy()


class Judgment(WireModel):
    category: Category
    is_breaking: bool
    affects_public_api: bool
    requires_migration_step: bool
    usage_impact: Literal["applies", "does_not_apply", "unknown"]
    probability: Probability | None
    category_confidence: Probability | None


class GeneratedAnswer(Judgment):
    span_id: LogicalID
    free_quote: Annotated[str, Field(max_length=8192)] | None


class ExecutionMetadata(WireModel):
    origin: Literal["heuristic", "not_run", "mock", "replay", "live"]
    model_requested: str | None = None
    model_reported: str | None = None
    accounting_ref: str | None = None
    attempt_ids: tuple[str, ...] = ()
    normalized_usage: NormalizedUsage | None = None
    current_external_cost_usd: str | None = None
    source_capture: SourceCaptureRef | None = None
    latency_ms: float | None = None


class JudgeOutcome(WireModel):
    span_id: LogicalID
    input_sha256: Digest
    policy_sha256: Digest
    method: Literal["keyword", "typed", "generative"]
    status: Literal["ok", "review", "unavailable", "error"]
    reason: str
    judgment: Judgment | None = None
    literal_quote: str | None = None
    free_quote_fidelity: Literal["not_requested", "valid", "invalid"] = "not_requested"
    execution: ExecutionMetadata

    @model_validator(mode="after")
    def usable_only_when_ok(self) -> Self:
        if self.status != "ok" and (self.judgment is not None or self.literal_quote is not None):
            raise ValueError("unavailable or held judgment cannot expose a usable claim")
        if self.status == "ok" and (self.judgment is None or not self.literal_quote):
            raise ValueError("usable judgment requires literal evidence")
        if self.method == "keyword" and self.judgment is not None:
            if self.execution.origin != "heuristic" or self.judgment.probability is not None:
                raise ValueError("keyword result is an uncalibrated heuristic")
        return self


def outcome(data, policy, method, status, reason, **values) -> JudgeOutcome:
    return JudgeOutcome(
        span_id=data.span_id,
        input_sha256=data.sha256,
        policy_sha256=policy.sha256,
        method=method,
        status=status,
        reason=reason,
        execution=values.pop("execution", ExecutionMetadata(origin="not_run")),
        **values,
    )
