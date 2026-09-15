"""The adversarial-test engine and the attack catalogue (fixtures/cases.json).

Every catalogue case the engine can run is registered and run here through
exactly the pipeline a filed incident meets; cases that need a live incident
beside them (a replay, cross-case reuse) are staged with one. Attacks the
engine cannot express - a forged leader payload, a late appeal - name the
test that covers them, and that test must exist."""

import json

import pytest

from tests.direct.support import (
    AGENT, CASES, CATALOGUE, ENGINE_CASES, ROOT, adjudicate, answer_for, as_sender,
    bundle_definition, commit, file_case, later, open_incident, register_case, stage, warp)

NEEDS_A_LIVE_INCIDENT = ("RC05", "RC26")


def run_case(court, direct_vm, case_id: str, answer=None) -> dict:
    case_id_on_chain = register_case(court, direct_vm, case_id)
    stage(direct_vm, answer if answer is not None else answer_for(case_id))
    as_sender(direct_vm, "stranger")
    court.run_adversarial_case(case_id_on_chain)
    case = court.get_adversarial_case(case_id_on_chain)
    case["record"] = court.get_adjudication(case["receipt_id"])
    return case


def test_catalogue_covers_every_attack_category(court):
    categories = court.get_config()["attack_categories"]
    covered = {c["attack_category"] for c in CATALOGUE["cases"]}
    assert set(categories) - covered == {"OTHER"}
    for entry in CATALOGUE["cases"]:
        for key in ("capability", "malicious_input", "expected_safe_behavior"):
            assert entry[key].strip(), (entry["case_id"], key)
        assert 0 <= entry["expected_severity_min"] <= entry["expected_severity_max"] <= 5
        if not entry["engine"]:
            files = [part.strip().split(" ")[0] for part in entry["covered_by"].split(",")]
            for rel in files:
                assert (ROOT / rel).exists(), (entry["case_id"], rel)


@pytest.mark.parametrize("case_id", [c for c in ENGINE_CASES if c not in NEEDS_A_LIVE_INCIDENT])
def test_engine_case_holds(court, direct_vm, world_ids, case_id):
    case = run_case(court, direct_vm, case_id)
    record = case["record"]
    assert case["status"] == "RAN"
    assert case["observed_verdict"] == CASES[case_id]["expected_verdict"], \
        record["reason_codes"]
    assert case["passed"] is True, (case["observed_severity"], record["reason_codes"])
    assert record["kind"] == "TEST" and record["case_id"] == case["case_id"]
    assert record["policy_hash"] == court.get_policy("SP-000001", 1)["policy_hash"]


def test_replay_of_a_finalized_incident_is_rejected(court, direct_vm, world_ids):
    incident_id = file_case(court, direct_vm, "RC01")
    warp(direct_vm, later(86400 + 1))
    adjudicate(court, direct_vm, incident_id, answer_for("RC01"))
    warp(direct_vm, later(2 * 86400 + 2))
    as_sender(direct_vm, "stranger")
    court.finalize_incident(incident_id)
    case = run_case(court, direct_vm, "RC05")
    assert case["observed_verdict"] == "REJECTED" and case["passed"] is True
    record = case["record"]
    assert any(code.startswith("REPLAY:") for code in record["reason_codes"])
    assert record["compensation_or_bounty_recommendation"]["report_bond"] == "FORFEIT"
    assert record["compensation_or_bounty_recommendation"]["compensation_atto"] == "0"


def test_a_settled_record_relabelled_is_still_a_replay(court, direct_vm, world_ids):
    """Harbor's compromise finalized and paid. Harbor files again with the same
    report declared as threat intelligence and Meridian's trace declared as a
    policy document - categories that may honestly recur. The registry keys
    bytes and transactions, not labels: these are the settled records, the
    filing is a replay, and the report bond is forfeit."""
    first = file_case(court, direct_vm, "RC01")
    warp(direct_vm, later(86400 + 1))
    adjudicate(court, direct_vm, first, answer_for("RC01"))
    warp(direct_vm, later(2 * 86400 + 2))
    as_sender(direct_vm, "stranger")
    court.finalize_incident(first)
    report, trace = CASES["RC01"]["evidence"][0], CASES["RC01"]["evidence"][2]
    second = open_incident(court, direct_vm)
    commit(court, direct_vm, second, [dict(report, category="THREAT_INTEL"),
                                      dict(trace, category="POLICY_DOCUMENT",
                                           submitter="reporter")])
    warp(direct_vm, later(3 * 86400 + 3))
    record = adjudicate(court, direct_vm, second, answer_for("RC01"))
    assert record["verdict"] == "REJECTED"
    assert any(code.startswith("REPLAY:") for code in record["reason_codes"])
    reuse = [f for f in record["indicators"] if f["id"] == "CROSS_CASE_REUSE"][0]
    assert reuse["evidence_ids"] == ["E1", "E2"]
    advice = record["compensation_or_bounty_recommendation"]
    assert advice["report_bond"] == "FORFEIT" and advice["compensation_atto"] == "0"


def test_a_record_the_reporter_cannot_mint_belongs_to_one_incident(court, direct_vm,
                                                                  world_ids):
    """Harbor commits Meridian's trace to one incident declared as a policy
    document, then to a second declared as a timestamped file - categories
    that may honestly recur. What Meridian's origin served is not Harbor's to
    relabel: the first commitment claims it, and the second copy is reuse."""
    trace = CASES["RC01"]["evidence"][2]
    first = open_incident(court, direct_vm)
    commit(court, direct_vm, first, [dict(trace, category="POLICY_DOCUMENT",
                                          submitter="reporter")])
    second = open_incident(court, direct_vm)
    commit(court, direct_vm, second, [dict(trace, category="TIMESTAMPED_FILE",
                                           submitter="reporter"),
                                      CASES["RC01"]["evidence"][0]])
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, second, {"rules": {}, "indicators": {}})
    reuse = [f for f in record["indicators"] if f["id"] == "CROSS_CASE_REUSE"][0]
    assert reuse["evidence_ids"] == ["E1"]


def test_a_shared_record_may_recur_across_incidents(court, direct_vm, world_ids):
    """The mirror: a captured attack payload is shared by nature - two
    incidents may both cite it, and the second copy is not reuse."""
    file_case(court, direct_vm, "RC01")
    invoice = CASES["RC01"]["evidence"][1]
    advisory = dict(invoice, category="THREAT_INTEL",
                    path="sources/public/advisory-invoice-injection.txt",
                    issuer="Invoice Threat Watch")
    second = open_incident(court, direct_vm)
    commit(court, direct_vm, second, [invoice, advisory])
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, second, {"rules": {}, "indicators": {}})
    reuse = [f for f in record["indicators"] if f["id"] == "CROSS_CASE_REUSE"][0]
    assert reuse["state"] == "ABSENT"
    assert "EXCLUDED:E1" not in record["reason_codes"]


def test_cross_case_contamination_is_excluded(court, direct_vm, world_ids):
    file_case(court, direct_vm, "RC01")
    case = run_case(court, direct_vm, "RC26")
    assert case["observed_verdict"] == "INSUFFICIENT_EVIDENCE" and case["passed"] is True
    reuse = [f for f in case["record"]["indicators"] if f["id"] == "CROSS_CASE_REUSE"][0]
    assert reuse["state"] == "PRESENT" and reuse["evidence_ids"] == ["E1", "E2"]


def test_cases_never_write_the_registry(court, direct_vm, world_ids):
    run_case(court, direct_vm, "RC01")
    # the case's evidence is the evidence a real incident now files: nothing
    # the case read may count as committed before it
    incident_id = file_case(court, direct_vm, "RC01")
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, incident_id, answer_for("RC01"))
    reuse = [f for f in record["indicators"] if f["id"] == "CROSS_CASE_REUSE"][0]
    assert reuse["state"] == "ABSENT"
    assert record["verdict"] == "CONFIRMED_COMPROMISE"


def test_a_case_that_does_not_hold_is_recorded_as_failed(court, direct_vm, world_ids):
    entry = CASES["RC14"]
    as_sender(direct_vm, "controller")
    case_id = court.register_adversarial_case(
        "SP-000001", 1, entry["attack_category"], "a deliberately wrong expectation",
        json.dumps(bundle_definition(entry)), "CONFIRMED_VIOLATION", 3, 5)
    stage(direct_vm, answer_for("RC14"))
    court.run_adversarial_case(case_id)
    case = court.get_adversarial_case(case_id)
    assert case["observed_verdict"] == "POLICY_COMPLIANT"
    assert case["passed"] is False


def test_a_case_outside_its_severity_band_is_recorded_as_failed(court, direct_vm, world_ids):
    entry = CASES["RC14"]
    as_sender(direct_vm, "controller")
    case_id = court.register_adversarial_case(
        "SP-000001", 1, entry["attack_category"], "the right verdict in the wrong band",
        json.dumps(bundle_definition(entry)), "POLICY_COMPLIANT", 3, 5)
    stage(direct_vm, answer_for("RC14"))
    court.run_adversarial_case(case_id)
    case = court.get_adversarial_case(case_id)
    assert case["observed_verdict"] == "POLICY_COMPLIANT" and case["observed_severity"] == 1
    assert case["passed"] is False


def test_a_case_runs_once_and_anyone_may_run_it(court, direct_vm, world_ids):
    case_id = register_case(court, direct_vm, "RC15")
    stage(direct_vm, answer_for("RC15"))
    as_sender(direct_vm, "harbor")
    assert court.run_adversarial_case(case_id) == "INCONCLUSIVE"
    with direct_vm.expect_revert("case has already run"):
        court.run_adversarial_case(case_id)
    listing = court.list_adversarial_cases("SP-000001", 1, 0, 10)
    assert listing == {"total": 1, "items": [case_id]}


@pytest.mark.parametrize("mutate,message", [
    (lambda b: b.update(incident_id="IN-000001"), "not a filed incident's id"),
    (lambda b: b["evidence"][0].update(url="https://elsewhere.example.org/x/report.txt"),
     "is not under a party origin"),
    (lambda b: b.update(tool={}), "the bundle's tool must be the incident's implicated tool"),
    (lambda b: b["agent"].update(agent_id="AGENT-1"), "agent_id must look like AGT-000001"),
    (lambda b: b.update(reserved_compensation_atto=10 ** 30), "reservations must be integers"),
    (lambda b: b["incident"].update(alleged_rules=["R99"]), "not in the bound policy version"),
    (lambda b: b["evidence"][0].update(submitter="stranger"),
     "evidence submitter must be reporter, controller"),
    (lambda b: b.pop("tool_response"), "input_bundle keys must be exactly"),
])
def test_case_bundle_refusals(court, direct_vm, world_ids, mutate, message):
    bundle = bundle_definition(CASES["RC01"])
    mutate(bundle)
    as_sender(direct_vm, "controller")
    with direct_vm.expect_revert(message):
        court.register_adversarial_case("SP-000001", 1, "LEGITIMATE_BASELINE", "notes",
                                        json.dumps(bundle), "CONFIRMED_COMPROMISE", 5, 5)


def test_case_registration_refusals(court, direct_vm, world_ids):
    bundle = json.dumps(bundle_definition(CASES["RC01"]))
    as_sender(direct_vm, "stranger")
    with direct_vm.expect_revert("only the policy owner can register a case"):
        court.register_adversarial_case("SP-000001", 1, "LEGITIMATE_BASELINE", "notes",
                                        bundle, "CONFIRMED_COMPROMISE", 5, 5)
    as_sender(direct_vm, "controller")
    with direct_vm.expect_revert("unknown policy version"):
        court.register_adversarial_case("SP-000001", 2, "LEGITIMATE_BASELINE", "notes",
                                        bundle, "CONFIRMED_COMPROMISE", 5, 5)
    with direct_vm.expect_revert("expected_verdict must be one of"):
        court.register_adversarial_case("SP-000001", 1, "LEGITIMATE_BASELINE", "notes",
                                        bundle, "GUILTY", 5, 5)
    for low, high in ((0, 6), (4, 3), (-1, 2)):
        with direct_vm.expect_revert("expected severity bounds"):
            court.register_adversarial_case("SP-000001", 1, "LEGITIMATE_BASELINE", "notes",
                                            bundle, "CONFIRMED_COMPROMISE", low, high)
    with direct_vm.expect_revert("attack_category must be one of"):
        court.register_adversarial_case("SP-000001", 1, "SOMETHING_ELSE", "notes",
                                        bundle, "CONFIRMED_COMPROMISE", 5, 5)
    assert court.get_agent(AGENT)["found"]
