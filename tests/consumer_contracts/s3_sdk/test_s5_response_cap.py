"""what_bug_this_catches: unsupported SDK configuration reserves or charges S5 work."""

import importlib.util
from pathlib import Path

import pytest

from changelog_advisor.shared.providers import ProviderError, sdk

path = Path(__file__).with_name("test_s5_native_join.py")
spec = importlib.util.spec_from_file_location("s5_cap_consumer_helpers", path)
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)


@pytest.mark.parametrize("method", ["generative", "typed"])
@pytest.mark.parametrize("phase", ["prepare", "admit", "run"])
def test_s5_unsupported_sdk_cap_leaves_accounting_unchanged(
    factory, tmp_path, monkeypatch, method, phase
):
    """Use actual S5 preparation/allocation to detect a canonical contract mismatch."""
    _, rig, provider, transport = helpers.consumer(factory, tmp_path, method)

    def forbidden(*args, **kwargs):
        pytest.fail("unsupported response limit started a native worker")

    monkeypatch.setattr(sdk, "_owned_worker", forbidden)
    rig.limits = rig.limits.model_copy(update={"max_response_bytes": 65537})
    with rig.open() as ledger:
        allocation = None
        if phase == "run":
            allocation = ledger.admit_operation(
                rig.plan(attempts=1), context=rig.context(), limits=rig.limits, mode="simulation"
            )
        before = ledger.totals()
        with pytest.raises(ProviderError, match="unsupported_sdk_response_limit"):
            if phase == "prepare":
                provider.prepare(rig.request, context=rig.context(), limits=rig.limits)
            elif phase == "admit":
                helpers.admit(rig, provider, ledger)
            else:
                provider.run(rig.request, **rig.kwargs(ledger, allocation))
        assert ledger.totals() == before
        assert ledger.totals()["dispatched_attempts"] == 0
        assert ledger.totals()["unknown_liability_usd"] == "0"
    assert transport.last_execution is None


@pytest.mark.parametrize("method", ["generative", "typed"])
@pytest.mark.parametrize("response_cap", [1, 65536])
def test_s5_supported_sdk_cap_admits_without_worker(factory, tmp_path, method, response_cap):
    """Supported endpoints remain funded pending work rather than a blanket refusal."""
    _, rig, provider, transport = helpers.consumer(factory, tmp_path, method)
    rig.limits = rig.limits.model_copy(update={"max_response_bytes": response_cap})
    provider.prepare(rig.request, context=rig.context(), limits=rig.limits)
    with rig.open() as ledger:
        allocation = helpers.admit(rig, provider, ledger)
        assert allocation.operation_id == "op1"
        assert ledger.totals()["dispatched_attempts"] == 0
        assert ledger.totals()["unknown_liability_usd"] == "0"
    assert transport.last_execution is None
