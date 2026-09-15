"""Smoke: the public surface end to end - the policy, the parties, the funds,
an incident adjudicated, finalized and paid through the ledger, and a
disclosure paid from the bounty pool."""

import json

from tests.direct.support import (
    AGENT, BOND, CASES, CLAIM, NOW, POOL, REPORT_BOND, TOOL, adjudicate, answer_for,
    as_sender, assert_conserved, claimable, file_case, finding, later, policy_definition,
    present, profile, receipt, setup_world, stage, wallet, warp)


def test_config_and_health(court):
    config = court.get_config()
    assert config["contract_version"] == "0.1.0"
    assert len(config["attack_categories"]) == 32
    assert len(config["verdicts"]) == 13
    assert set(config["holding_verdicts"]) <= set(config["verdicts"])
    assert config["spheres"] == {"reporter": ["REPORTER"],
                                 "controller": ["CONTROLLER", "TOOL", "PUBLIC"]}
    health = court.health_check()
    assert health["ok"] is True and health["held_atto"] == "0"


def test_world_registration(court, direct_vm):
    ids = setup_world(court, direct_vm)
    assert ids == {"policy_id": "SP-000001", "tool_id": TOOL, "agent_id": AGENT}
    policy = court.get_policy("SP-000001", 0)
    assert policy["found"] and policy["policy_version"] == 1
    assert policy["policy"] == policy_definition()
    assert policy["effective_from"] == NOW and policy["owner"] == wallet("controller")
    agent = court.get_agent(AGENT)
    assert agent["owner_or_controller"] == wallet("controller")
    assert agent["wallet_confirmed"] is True
    assert agent["security_bond_atto"] == str(BOND)
    assert agent["bounty_pool_atto"] == str(POOL)
    assert court.get_tool(TOOL)["provider"] == wallet("docfetch")
    assert court.get_reporter(wallet("harbor"))["name"] == "Harbor Supplies"
    status = court.agent_security_status(AGENT, NOW)
    assert status["standing"] == "IN_GOOD_STANDING"
    assert_conserved(court, BOND + POOL)


def test_compromise_incident_end_to_end(court, direct_vm, world_ids):
    incident_id = file_case(court, direct_vm, "RC01")
    assert incident_id == "IN-000001"
    view = court.get_incident(incident_id)
    assert view["status"] == "OPEN" and view["report_bond_atto"] == str(REPORT_BOND)
    assert view["reserved_compensation_atto"] == str(CLAIM)
    assert len(view["evidence_ids"]) == 6
    assert court.agent_security_status(AGENT, NOW)["standing"] == "UNDER_INVESTIGATION"

    # respondents have a day; the controller answers at once
    as_sender(direct_vm, "controller")
    assert court.submit_counterreport(incident_id, "We are investigating.") == "OPEN"
    as_sender(direct_vm, "docfetch")
    assert court.submit_counterreport(incident_id, "Docfetch did what the token allowed.") \
        == "RESPONDED"

    record = adjudicate(court, direct_vm, incident_id, answer_for("RC01"))
    assert record["verdict"] == "CONFIRMED_COMPROMISE", record["reason_codes"]
    assert record["severity"] == 5
    assert record["confidence"] == "HIGH"
    assert record["corroboration"] == "CHAIN_RECORD"
    assert record["responsibility_allocation"] == [{"party": "CONTROLLER", "bps": 5000},
                                                   {"party": "ATTACKER", "bps": 5000}]
    assert record["required_remediation"] == ["ROTATE_CREDENTIALS", "ISOLATE_AGENT",
                                              "RETEST_BEFORE_RESTORE"]
    assert record["impact_classification"] == ["UNAUTHORIZED_ACTION", "FINANCIAL_LOSS",
                                               "AGENT_COMPROMISE"]
    advice = record["compensation_or_bounty_recommendation"]
    assert advice["compensation_eligible"] is True
    assert advice["compensation_atto"] == str(CLAIM // 2)
    assert advice["report_bond"] == "RETURN"
    assert finding(record, "R4")["state"] == "VIOLATED" and finding(record, "R4")["by"] == "CODE"
    assert finding(record, "R5")["state"] == "VIOLATED"
    assert set(present(record)) >= {"AGENT_UNDER_EXTERNAL_CONTROL", "MATERIAL_HARM"}
    assert receipt(record, "E6")["relevance_status"] == "SENT_BY_AGENT_WALLET"
    assert receipt(record, "E2")["authenticity_status"] == "ACCEPTED"
    assert record["finalized"] is False
    assert len(record["record_digest"]) == 64

    # nothing moves inside the appeal window
    with direct_vm.expect_revert("the appeal window is open"):
        court.finalize_incident(incident_id)
    warp(direct_vm, later(86400 + 1))
    as_sender(direct_vm, "stranger")
    assert court.finalize_incident(incident_id) == "CONFIRMED_COMPROMISE"
    view = court.get_incident(incident_id)
    assert view["status"] == "FINALIZED" and view["remediation_status"] == "REQUIRED"
    assert view["compensation_paid_atto"] == str(CLAIM // 2)
    assert claimable(court, "harbor") == CLAIM // 2 + REPORT_BOND
    assert court.get_adjudication(record["adjudication_id"])["finalized"] is True
    agent = court.get_agent(AGENT)
    assert agent["security_bond_atto"] == str(BOND - CLAIM // 2)
    assert agent["security_bond_reserved_atto"] == "0"
    status = court.agent_security_status(AGENT, later(86400 + 2))
    assert status["standing"] == "CONTAINMENT_REQUIRED"
    assert status["max_open_severity"] == 5
    assert_conserved(court, BOND + POOL + REPORT_BOND)

    as_sender(direct_vm, "harbor")
    assert court.withdraw() == str(CLAIM // 2 + REPORT_BOND)
    assert claimable(court, "harbor") == 0
    with direct_vm.expect_revert("nothing to withdraw"):
        court.withdraw()
    assert_conserved(court, BOND + POOL + REPORT_BOND, CLAIM // 2 + REPORT_BOND)


def test_disclosure_pays_the_severity_bounty(court, direct_vm, world_ids):
    incident_id = file_case(court, direct_vm, "RC32")
    view = court.get_incident(incident_id)
    assert view["kind"] == "DISCLOSURE"
    assert view["reserved_bounty_atto"] == str(200 * 10 ** 15)
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, incident_id, answer_for("RC32"))
    assert record["verdict"] == "CONFIRMED_VULNERABILITY", record["reason_codes"]
    assert record["severity"] == 4
    advice = record["compensation_or_bounty_recommendation"]
    assert advice["bounty_eligible"] is True and advice["bounty_atto"] == str(100 * 10 ** 15)
    assert record["required_remediation"] == ["RETRAIN_OR_RECONFIGURE",
                                              "DISCLOSE_VULNERABILITY",
                                              "RETEST_BEFORE_RESTORE"]
    warp(direct_vm, later(2 * 86400 + 2))
    as_sender(direct_vm, "stranger")
    court.finalize_incident(incident_id)
    assert claimable(court, "northwind") == 100 * 10 ** 15 + REPORT_BOND
    agent = court.get_agent(AGENT)
    assert agent["bounty_pool_atto"] == str(POOL - 100 * 10 ** 15)
    assert agent["bounty_pool_reserved_atto"] == "0"
    assert_conserved(court, BOND + POOL + REPORT_BOND)


def test_profiles_and_ids_are_the_signers(court, direct_vm):
    as_sender(direct_vm, "controller")
    policy_id = court.register_policy(json.dumps(policy_definition()))
    as_sender(direct_vm, "stranger")
    with direct_vm.expect_revert("owns its policy"):
        court.register_agent(json.dumps(profile("agent")))
    as_sender(direct_vm, "harbor")
    court.register_reporter(json.dumps(profile("harbor")))
    with direct_vm.expect_revert("already a registered reporter"):
        court.register_reporter(json.dumps(profile("harbor")))
    assert policy_id == "SP-000001"
    stage(direct_vm)
    assert CASES["RC01"]["expected_verdict"] == "CONFIRMED_COMPROMISE"
