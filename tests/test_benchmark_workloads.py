"""Correctness and reproducibility tests for the optional benchmark corpus, without timing gates."""

from __future__ import annotations

import runpy
from pathlib import Path

import pytest

BENCHMARK = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "scripts" / "benchmark_policy.py")
)


def test_every_benchmark_verifies_its_timed_operation():
    cases = BENCHMARK["workloads"]()
    assert len(cases) == 20
    assert len({case.name for case in cases}) == len(cases)
    assert {case.group for case in cases} == set(BENCHMARK["GROUPS"])
    for case in cases:
        case.verify()
        assert len(case.metadata["workload_sha256"]) == 64
        assert case.metadata["corpus_version"] == "samsarix-workloads-v1"


def test_corpus_inputs_are_repeatable_and_detached():
    first = BENCHMARK["workloads"]()
    second = BENCHMARK["workloads"]()
    assert [(c.name, c.metadata) for c in first] == [(c.name, c.metadata) for c in second]
    one = BENCHMARK["gateway_policy"]()
    one["rules"].clear()
    assert len(BENCHMARK["gateway_policy"]()["rules"]) == 8
    assert BENCHMARK["fingerprint"]({"a": 1, "b": 2}) == BENCHMARK["fingerprint"]({"b": 2, "a": 1})
    assert BENCHMARK["fingerprint"]({"a": 2}) != BENCHMARK["fingerprint"]({"a": 1})
    assert len(BENCHMARK["package_fingerprint"]()) == 64
    assert BENCHMARK["fingerprint"]([(c.name, c.metadata) for c in first]) == (
        "39581f5eccfc9a3468f7cc5a66f6f8a288c7ddc314394dc394d7b044d48c5508"
    )


def test_workload_preflight_rejects_wrong_results():
    for case in BENCHMARK["workloads"]():
        with pytest.raises((AssertionError, AttributeError)):
            case.check(None)


@pytest.mark.parametrize("count", [0, 1, 513])
def test_rule_scaling_cannot_exceed_runtime_limits(count):
    with pytest.raises(ValueError):
        BENCHMARK["gateway_policy"](count)


def test_unknown_request_outcome_rejected():
    with pytest.raises(ValueError):
        BENCHMARK["gateway_request"](outcome="invalid")


def test_unsupported_worker_timeout_has_an_actionable_error(monkeypatch):
    monkeypatch.delattr(BENCHMARK["os"], "set_blocking", raising=False)
    BENCHMARK["check_timeout_support"](None)
    with pytest.raises(ValueError, match="external job timeout"):
        BENCHMARK["check_timeout_support"](30)


def test_guard_workloads_exercise_both_audited_paths(monkeypatch):
    events = []
    monkeypatch.setitem(BENCHMARK["workloads"].__globals__, "_serialize_audit", events.append)
    cases = {case.name: case for case in BENCHMARK["workloads"]()}
    cases["gateway.guard_no_audit"].verify()
    assert not events
    cases["gateway.guard_audit_json"].verify()
    cases["gateway.guard_denied_audit_json"].verify()
    assert [event.allowed for event in events] == [True, False]
    assert all(event.request_id is None for event in events)


def test_batch_json_preflight_rejects_missing_explanations():
    import json

    case = next(c for c in BENCHMARK["workloads"]() if c.name == "batch.evaluate_explain_json_100")
    result = json.loads(case.operation())
    del result["decisions"][0]["evaluations"]
    with pytest.raises(AssertionError):
        case.check(json.dumps(result))
