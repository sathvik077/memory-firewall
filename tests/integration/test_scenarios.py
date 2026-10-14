"""MF-15: every offline scenario must pass, and the dashboard must show the same results.

The Attack Lab in the dashboard calls the same ``run_scenario`` these tests call, so a green test
suite and a green lab cannot disagree.
"""

from __future__ import annotations

import pytest

from memory_firewall.scenarios import SCENARIOS, list_scenarios, run_all, run_scenario

pytestmark = pytest.mark.integration


def test_at_least_eight_scenarios_exist() -> None:
    assert len(SCENARIOS) >= 8
    kinds = {s.kind for s in SCENARIOS}
    assert {"attack", "benign", "control"} <= kinds
    assert all(s.contract_ref for s in SCENARIOS), (
        "every scenario cites the contract clause it covers"
    )


@pytest.mark.parametrize("scenario_id", [s.id for s in SCENARIOS])
def test_scenario_passes(scenario_id: str) -> None:
    result = run_scenario(scenario_id)
    failing = [c for c in result["checks"] if not c["passed"]]
    assert result["checks"], f"{scenario_id} asserted nothing"
    assert not failing, f"{scenario_id} failed: {failing}"
    assert result["isolated"] is True
    assert result["steps"]


def test_scenarios_are_repeatable_and_isolated() -> None:
    first = run_scenario("golden-poison")
    second = run_scenario("golden-poison")
    assert first["passed"] and second["passed"]
    assert first["database"] != second["database"], "each run needs its own disposable database"


def test_run_all_reports_a_total(tmp_path) -> None:
    results = run_all()
    assert results["total"] == len(SCENARIOS)
    assert results["passed"] == results["total"]
    assert results["failed"] == []
    total_checks = sum(len(r["checks"]) for r in results["results"])
    assert total_checks >= 40


def test_listing_matches_the_registry() -> None:
    listed = list_scenarios()
    assert [s["id"] for s in listed] == [s.id for s in SCENARIOS]
    assert all(s["description"] and s["expectation"] for s in listed)


def test_attack_scenarios_carry_honest_caveats_where_relevant() -> None:
    """A scenario that demonstrates a heuristic must say so rather than imply a guarantee."""
    for scenario_id in ("stealthy-partial", "quoted-attack", "integrity-mutation", "time-machine"):
        result = run_scenario(scenario_id)
        assert result["caveat"], f"{scenario_id} should state its limitation"
