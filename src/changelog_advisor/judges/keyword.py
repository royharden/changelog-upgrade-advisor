"""Plain keyword baseline. No negation, semantic inference or measured quality claim."""

import re

from ..shared.screen.rules import screen_rules
from .models import (
    DEFAULT_POLICY,
    SCREEN_POLICY,
    ExecutionMetadata,
    JudgeInput,
    JudgePolicy,
    Judgment,
    outcome,
)

RULES = (
    ("removed", r"\b(?:removed?|removal|deleted?)\b"),
    ("renamed", r"\brenam(?:e|ed|ing)\b"),
    ("changed_default", r"\b(?:default.{0,40}chang|chang.{0,40}default)"),
    ("behaviour_change", r"\b(?:breaking|incompatible|behavio[u]?r.{0,30}chang)"),
    ("pure_deprecation", r"\bdeprecat(?:e|ed|ion|ing)\b"),
)


def keyword_judgment(data: JudgeInput, policy: JudgePolicy = DEFAULT_POLICY):
    data = JudgeInput.model_validate(data)
    policy = JudgePolicy.model_validate(policy)
    screen = screen_rules(data.screen_source(), SCREEN_POLICY)
    if not screen.permits_model_input(data.screen_source(), SCREEN_POLICY):
        return outcome(data, policy, "keyword", "review", "screen_hold")
    category = next((name for name, rule in RULES if re.search(rule, data.text, re.I)), "none")
    breaking = category in ("removed", "renamed", "changed_default", "behaviour_change")
    judgment = Judgment(
        category=category,
        is_breaking=breaking,
        affects_public_api=breaking,
        requires_migration_step=breaking,
        usage_impact="unknown",
        probability=None,
        category_confidence=None,
    )
    return outcome(
        data,
        policy,
        "keyword",
        "ok",
        "plain_keyword_heuristic",
        judgment=judgment,
        literal_quote=data.text,
        execution=ExecutionMetadata(origin="heuristic"),
    )
