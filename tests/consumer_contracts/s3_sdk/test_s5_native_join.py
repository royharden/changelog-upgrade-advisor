"""what_bug_this_catches: an SDK seam bypasses S5 identity, accounting or hard closure.

All prices, answers and credentials below are authored controls, never live proof.
"""

import base64
import hashlib
import importlib.util
import json
from decimal import Decimal
from pathlib import Path

import pytest

from changelog_advisor.judges import JudgeInput, execute_native_simulation, prepare_judgment
from changelog_advisor.shared.callledger.models import canonical_digest
from changelog_advisor.shared.providers import ProjectCredential, SDKTransport

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("openai") is None or importlib.util.find_spec("typesafe_sdk") is None,
    reason="install the pinned optional sdk extra for native consumer controls",
)

path = Path(__file__).resolve().parents[3] / "vendor/s3-sdk/tests/providers/test_sdk_transport.py"
spec = importlib.util.spec_from_file_location("s5_declared_s3_native_helpers", path)
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)


def consumer(factory, tmp_path, method="generative", *, usage=True, delay=0, malformed=False):
    typed = method == "typed"
    model = "jev-1.13.0" if typed else "gpt-6-luna"
    text = "Removed public lookup()."
    data = JudgeInput(
        span_id="native-span",
        package="example-lib",
        source_generation="g1",
        source_sha256=hashlib.sha256(text.encode()).hexdigest(),
        text=text,
        context=("Public API",),
    )
    prepared = prepare_judgment(data, method=method, model=model)
    rig = factory(tmp_path / "consumer.sqlite3", "typesafe" if typed else "openai_responses", typed)
    rig.authority = rig.authority.model_copy(update={"max_outbound_attempts": 2})
    rig.limits = rig.limits.model_copy(
        update={
            "max_attempts_total": 1,
            "max_content_repairs": 0,
            "max_outbound_attempts": 2,
            "attempt_timeout_s": 10.0 if delay else 20.0,
        }
    )
    rig.policy = rig.policy.model_copy(update={"output_usd_per_million": "0"})
    helpers.native_rig(rig, model)
    old_context = rig.context

    def context(*args, **kwargs):
        return old_context(*args, **kwargs).model_copy(
            update={
                "source_generation": data.source_generation,
                "span_id": data.span_id,
                "consumer_context_sha256": data.sha256,
                "policy_sha256": prepared.policy_sha256,
            }
        )

    rig.context = context
    rig.request = prepared.request
    rig.evidence = []
    rig.register(rig.request)
    body = rig.body()
    body["model"] = model
    if typed:
        body["answers"] = {
            name: {"type": "noul", "noul": 0.9}
            for name in ("is_breaking", "affects_public_api", "requires_migration_step")
        }
        body["answers"]["category"] = {
            "type": "choice",
            "choice": "removed",
            "confidence": 0.95,
            "probabilities": {
                name: 0.95 if name == "removed" else 0.01 for name in prepared.policy.options
            },
        }
    else:
        body["output"][0]["content"][0]["text"] = json.dumps(
            {
                "span_id": data.span_id,
                "category": "removed",
                "is_breaking": True,
                "affects_public_api": True,
                "requires_migration_step": True,
                "usage_impact": "unknown",
                "probability": 0.9,
                "category_confidence": 0.8,
                "free_quote": "lookup()",
            }
        )
    if usage:
        body["usage"] = {"input_tokens": 100, "output_tokens": 1}
    else:
        body.pop("usage", None)
    raw = b"{invalid-json" if malformed else json.dumps(body).encode()
    transport = SDKTransport(
        rig.config.flavor,
        mock={
            "status_code": 200,
            "body_base64": base64.b64encode(raw).decode(),
            "delay_s": delay,
        },
    )
    provider = rig.provider(transport=transport)
    native = provider.prepare(prepared.request, context=rig.context(), limits=rig.limits)
    rig.evidence = [
        rig.evidence[0].model_copy(
            update={
                "dispatched_envelope_sha256": native.dispatched_envelope_sha256,
            }
        )
    ]
    return prepared, rig, rig.provider(transport=transport), transport


def admit(rig, provider, ledger, *, conditional=False):
    plan = rig.plan(attempts=1)
    if conditional:
        plan = plan.model_copy(
            update={"children": [plan.children[0].model_copy(update={"conditional": True})]}
        )
    return provider.admit_operation(
        plan, ledger=ledger, budget=rig.authority, context=rig.context(), limits=rig.limits
    )


@pytest.mark.parametrize("method", ["generative", "typed"])
def test_s5_actual_sdk_mock_wire_keeps_same_accounting_objects_and_source(
    factory, tmp_path, monkeypatch, method
):
    prepared, rig, provider, transport = consumer(factory, tmp_path, method)
    with rig.open() as ledger:
        allocation = admit(rig, provider, ledger)
        kwargs = rig.kwargs(ledger, allocation)
        run = provider.run
        observed = []

        def checked(request, **actual):
            assert request is prepared.request
            assert actual["purpose"] == kwargs["purpose"]
            assert all(
                actual[name] is kwargs[name]
                for name in ("ledger", "budget", "context", "limits", "allocation")
            )
            observed.append(True)
            return run(request, **actual)

        monkeypatch.setattr(provider, "run", checked)
        result = execute_native_simulation(prepared, provider=provider, **kwargs)
        assert observed == [True] and result.status == "ok"
        assert result.judgment.category == "removed" and result.literal_quote == prepared.data.text
        assert (
            result.execution.origin == "mock"
            and result.execution.source_capture.origin == "synthetic"
        )
        assert result.execution.current_external_cost_usd == "0"
        assert ledger.totals()["dispatched_attempts"] == 1
        assert Decimal(ledger.totals()["known_spend_usd"]) > 0
        assert Decimal(ledger.totals()["unknown_liability_usd"]) == 0
        assert transport.last_execution["owned_tree_closed"]
        assert transport.last_execution["active_owned_processes_after"] == 0


def test_conditional_false_closes_real_allocation_without_sdk_worker(factory, tmp_path):
    _, rig, provider, transport = consumer(factory, tmp_path)
    with rig.open() as ledger:
        allocation = admit(rig, provider, ledger, conditional=True)
        proof = canonical_digest(
            {"allocation_id": allocation.allocation_id, "child_id": "child0", "undispatched": True}
        )
        ledger.finish_child(allocation, child_id="child0", outcome="skipped", proof_sha256=proof)
        assert ledger.operation_state(allocation) == "complete"
        assert ledger.totals()["dispatched_attempts"] == 0
        assert Decimal(ledger.totals()["future_holds_usd"]) == 0
        assert transport.last_execution is None


def test_wrong_s5_context_refuses_without_dispatch_and_caller_cancels_hold(factory, tmp_path):
    prepared, rig, provider, transport = consumer(factory, tmp_path)
    with rig.open() as ledger:
        allocation = admit(rig, provider, ledger)
        kwargs = rig.kwargs(ledger, allocation)
        kwargs["context"] = kwargs["context"].model_copy(
            update={"consumer_context_sha256": "f" * 64}
        )
        result = execute_native_simulation(prepared, provider=provider, **kwargs)
        assert result.reason == "consumer_context_mismatch" and result.judgment is None
        assert transport.last_execution is None and ledger.totals()["dispatched_attempts"] == 0
        proof = canonical_digest(
            {"allocation_id": allocation.allocation_id, "child_id": "child0", "undispatched": True}
        )
        ledger.finish_child(
            allocation, child_id="child0", outcome="cancelled_before_dispatch", proof_sha256=proof
        )
        assert Decimal(ledger.totals()["future_holds_usd"]) == 0


@pytest.mark.parametrize("mode", ["missing_usage", "malformed"])
def test_consumer_keeps_unknown_liability_without_repair(factory, tmp_path, mode):
    prepared, rig, provider, transport = consumer(
        factory, tmp_path, usage=mode != "missing_usage", malformed=mode == "malformed"
    )
    with rig.open() as ledger:
        allocation = admit(rig, provider, ledger)
        result = execute_native_simulation(
            prepared, provider=provider, **rig.kwargs(ledger, allocation)
        )
        if mode == "malformed":
            assert result.status != "ok" and result.judgment is None
        else:
            assert result.execution.normalized_usage is None
            assert result.execution.attempt_ids is None
            assert result.execution.accounting_ref == allocation.allocation_id
        assert result.execution.origin == "mock"
        assert ledger.totals()["dispatched_attempts"] == 1
        assert Decimal(ledger.totals()["unknown_liability_usd"]) > 0
        assert transport.last_execution["owned_tree_closed"]
        assert transport.last_execution["active_owned_processes_after"] == 0


def test_s5_hard_deadline_closes_native_worker_and_keeps_reservation(factory, tmp_path):
    prepared, rig, provider, transport = consumer(factory, tmp_path, delay=30)
    with rig.open() as ledger:
        allocation = admit(rig, provider, ledger)
        result = execute_native_simulation(
            prepared, provider=provider, **rig.kwargs(ledger, allocation)
        )
        assert result.status == "unavailable" and result.judgment is None
        assert result.execution.origin == "mock"
        assert (
            transport.last_execution["timed_out"]
            and transport.last_execution["physical_dispatch_observed"]
        )
        assert transport.last_execution["owned_tree_closed"]
        assert transport.last_execution["active_owned_processes_after"] == 0
        assert ledger.totals()["dispatched_attempts"] == 1
        assert Decimal(ledger.totals()["unknown_liability_usd"]) > 0


def test_simulated_entry_never_runs_explicit_live_provider(factory, tmp_path):
    prepared, rig, provider, _ = consumer(factory, tmp_path)
    live = rig.provider(
        mode="live",
        transport=SDKTransport(
            "openai_responses",
            credential=ProjectCredential("authored-not-an-account", "dummy-offline-not-a-real-key"),
        ),
    )
    with rig.open() as ledger:
        allocation = admit(rig, provider, ledger)
        result = execute_native_simulation(
            prepared, provider=live, **rig.kwargs(ledger, allocation)
        )
        assert result.reason == "native_simulation_required"
        assert live.transport.last_execution is None and ledger.totals()["dispatched_attempts"] == 0
