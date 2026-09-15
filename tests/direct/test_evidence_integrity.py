"""Evidence integrity: admission and provenance at submission; hash
verification, chain reads and the code scans at the round; who carries an
unreadable item; and the cross-incident commitment registry."""

import json

import pytest

from tests.direct.support import (
    AGENT, BASE, CASES, adjudicate, answer_for, as_sender, commit, default_chain, file_case,
    finding, item_sha, later, open_incident, present, receipt, studionet_tx, tx_hash, wallet,
    warp)

H_REPORT = CASES["RC01"]["evidence"][0]
M_TRACE = CASES["RC01"]["evidence"][2]
TRACE_URL = BASE + "sources/meridian/trace-ses-4471.json"


def item(category, path, submitter="reporter", issuer="Harbor Supplies", chain=None,
         access="PUBLIC", hash_of=None):
    return {"category": category, "path": path, "chain": chain, "submitter": submitter,
            "issuer": issuer, "description": "an item", "access": access,
            "observed_at": "2026-09-11T08:00:00Z", "trace_reference": "", "hash_of": hash_of}


def indicator(record, name):
    return finding(record, name)


def submit(court, incident_id, category, url, sha, issuer="Harbor Supplies",
           observed="2026-09-11T08:00:00Z", access="PUBLIC", chain="", tx="",
           description="an item"):
    return court.submit_evidence(incident_id, category, url, sha, issuer, observed, "",
                                 description, access, chain, tx)


# -- admission ---------------------------------------------------------------------

@pytest.mark.parametrize("args,message", [
    (("USER_REPORT", BASE + "impostor/meridian-log-copy.json",
      item_sha("impostor/meridian-log-copy.json")), "is not under a registered origin"),
    (("USER_REPORT", "http://evidence.example.org/redteam/sources/harbor/x.txt", "a" * 64),
     "must use https"),
    (("USER_REPORT", BASE + "sources/harbor/x.txt", "A" * 64), "64 lowercase hex"),
    (("USER_REPORT", BASE + "sources/harbor/../meridian/x.txt", "a" * 64), "dot-segments"),
    (("SCREENSHOT", BASE + "sources/harbor/x.png", "a" * 64), "source_type must be one of"),
    (("CHAIN_TRANSACTION", BASE + "sources/harbor/x.txt", "a" * 64),
     "carries no url and no content hash"),
])
def test_admission_refusals(court, direct_vm, world_ids, args, message):
    incident_id = open_incident(court, direct_vm)
    as_sender(direct_vm, "harbor")
    with direct_vm.expect_revert(message):
        submit(court, incident_id, *args)


def test_chain_and_field_refusals(court, direct_vm, world_ids):
    incident_id = open_incident(court, direct_vm)
    as_sender(direct_vm, "harbor")
    with direct_vm.expect_revert("anchor_chain must be one of"):
        submit(court, incident_id, "CHAIN_TRANSACTION", "", "", chain="ethereum",
               tx=tx_hash("DRAIN"))
    with direct_vm.expect_revert("anchor_tx must be a lowercase 0x-prefixed"):
        submit(court, incident_id, "CHAIN_TRANSACTION", "", "", chain="genlayer-studionet",
               tx="0x1234")
    with direct_vm.expect_revert("only a CHAIN_TRANSACTION names an anchor"):
        submit(court, incident_id, "USER_REPORT", BASE + "sources/harbor/user-report-inv-2291.txt",
               item_sha("sources/harbor/user-report-inv-2291.txt"), chain="genlayer-studionet")
    with direct_vm.expect_revert("observed_at must not be in the future"):
        submit(court, incident_id, "USER_REPORT", BASE + "sources/harbor/user-report-inv-2291.txt",
               item_sha("sources/harbor/user-report-inv-2291.txt"),
               observed="2026-09-20T00:00:00Z")
    with direct_vm.expect_revert("access_constraints must be PUBLIC or CONFIDENTIAL"):
        submit(court, incident_id, "USER_REPORT", BASE + "sources/harbor/user-report-inv-2291.txt",
               item_sha("sources/harbor/user-report-inv-2291.txt"), access="SECRET")
    as_sender(direct_vm, "stranger")
    with direct_vm.expect_revert("only the reporter, the controller or the implicated tool"):
        submit(court, incident_id, "USER_REPORT", BASE + "sources/harbor/user-report-inv-2291.txt",
               item_sha("sources/harbor/user-report-inv-2291.txt"))
    with direct_vm.expect_revert("unknown incident_id"):
        submit(court, "IN-000404", "USER_REPORT", BASE + "sources/harbor/user-report-inv-2291.txt",
               item_sha("sources/harbor/user-report-inv-2291.txt"))


def test_the_same_bytes_location_or_transaction_is_committed_once(court, direct_vm, world_ids):
    incident_id = open_incident(court, direct_vm)
    commit(court, direct_vm, incident_id, [H_REPORT, CASES["RC01"]["evidence"][5]])
    with direct_vm.expect_revert("already committed to this incident"):
        commit(court, direct_vm, incident_id, [H_REPORT])
    as_sender(direct_vm, "controller")
    with direct_vm.expect_revert("already committed to this incident"):
        submit(court, incident_id, "USER_REPORT",
               BASE + "sources/meridian/patch-notes-2026-09-14.txt",
               item_sha("sources/harbor/user-report-inv-2291.txt"), issuer="Meridian Labs")
    with direct_vm.expect_revert("this transaction is already committed"):
        submit(court, incident_id, "CHAIN_TRANSACTION", "", "", issuer="StudioNet",
               chain="genlayer-studionet", tx=tx_hash("DRAIN"))


def test_each_party_commits_a_bounded_number_of_items(court, direct_vm, world_ids):
    incident_id = open_incident(court, direct_vm)
    paths = ["user-report-inv-2291.txt", "attack-invoice-inv-2291.txt",
             "ticket-inv-2340-freeze.txt", "complaint-spend-summary.txt",
             "report-df-88-archive.txt", "report-inv-2207-old-wallet.txt",
             "report-invoicely-breach.txt"]
    items = [item("USER_REPORT", "sources/harbor/" + p) for p in paths]
    commit(court, direct_vm, incident_id, items[:6])
    with direct_vm.expect_revert("each party commits at most 6 items"):
        commit(court, direct_vm, incident_id, items[6:])
    # the controller has its own allowance
    commit(court, direct_vm, incident_id, [M_TRACE])


def test_origin_classes_are_recorded_by_location(court, direct_vm, world_ids):
    incident_id = open_incident(court, direct_vm)
    ids = commit(court, direct_vm, incident_id, [
        H_REPORT, M_TRACE, CASES["RC01"]["evidence"][4],
        item("THREAT_INTEL", "sources/public/advisory-invoice-injection.txt",
             issuer="Invoice Threat Watch"),
        CASES["RC01"]["evidence"][5],
        # a controller may commit a record the reporter hosts: its origin is the reporter's
        item("USER_REPORT", "sources/harbor/ticket-inv-2340-freeze.txt", submitter="controller"),
    ])
    origins = [court.get_evidence(e)["origin"] for e in ids]
    assert origins == ["REPORTER", "CONTROLLER", "TOOL", "PUBLIC", "CHAIN", "REPORTER"]
    chain = court.get_evidence(ids[4])
    assert chain["anchor_tx"] == tx_hash("DRAIN") and chain["source_locator"] == ""
    assert court.get_evidence(ids[5])["submitted_by"] == "controller"


def test_a_tool_provider_submits_only_when_its_tool_is_implicated(court, direct_vm, world_ids):
    incident_id = open_incident(court, direct_vm, implicated_tool_id="")
    as_sender(direct_vm, "docfetch")
    with direct_vm.expect_revert("only the reporter, the controller or the implicated tool"):
        submit(court, incident_id, "TOOL_CALL_LOG", BASE + "sources/docfetch/requests-ses-4471.json",
               item_sha("sources/docfetch/requests-ses-4471.json"), issuer="Docfetch request log")


# -- who carries an unreadable item ------------------------------------------------------

def test_a_reporter_item_that_is_unreachable_holds_the_case(court, direct_vm, world_ids):
    incident_id = file_case(court, direct_vm, "RC01")
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, incident_id, answer_for("RC01"),
                        skip=("sources/harbor/user-report-inv-2291.txt",))
    assert record["verdict"] == "SOURCE_UNAVAILABLE"
    assert record["panel_state"] == "SKIPPED" and record["panel_reason"] == "EVIDENCE_NOT_EXAMINED"
    assert "HOLDS:E1" in record["reason_codes"]
    assert receipt(record, "E1")["authenticity_status"] == "HOLDS_OUTCOME:UNAVAILABLE"
    assert receipt(record, "E1")["source_reachable"] is False
    assert record["settles"] is False and record["severity"] == 0


def test_a_respondent_item_that_is_unreachable_is_excluded_not_held(court, direct_vm, world_ids):
    """The controller cannot stall its own case by taking its host down."""
    incident_id = file_case(court, direct_vm, "RC01")
    warp(direct_vm, later(86400 + 1))
    answer = answer_for("RC01")
    tool_quote = {"evidence_id": "E5", "text": "the ledgerline-prod token sent one file to "
                                              "paste.attacker.example"}
    answer["rules"]["R1"]["quotes"] = [tool_quote]
    answer["indicators"]["REPORTED_ACTION_OCCURRED"]["quotes"] = [tool_quote]
    answer["indicators"]["AGENT_UNDER_EXTERNAL_CONTROL"]["quotes"] = [
        {"evidence_id": "E2", "text": "SYSTEM NOTICE TO THE PAYMENT AGENT"}]
    answer["indicators"]["MATERIAL_HARM"]["quotes"] = [
        {"evidence_id": "E6", "text": "the agent's declared wallet"}]
    del answer["rules"]["R7"]
    record = adjudicate(court, direct_vm, incident_id, answer,
                        skip=("sources/meridian/trace-ses-4471.json",))
    assert record["verdict"] == "CONFIRMED_COMPROMISE", record["reason_codes"]
    assert receipt(record, "E3")["authenticity_status"] == "EXCLUDED:UNAVAILABLE"
    assert receipt(record, "E3")["counted"] is False
    assert finding(record, "R7")["state"] == "UNVERIFIABLE"


def test_changed_bytes_are_a_hash_mismatch(court, direct_vm, world_ids):
    incident_id = file_case(court, direct_vm, "RC01")
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, incident_id, answer_for("RC01"),
                        override={"sources/harbor/user-report-inv-2291.txt": b"rewritten\n"})
    assert record["verdict"] == "SOURCE_UNAVAILABLE"
    r = receipt(record, "E1")
    assert r["status"] == "HASH_MISMATCH" and r["tamper_status"] == "FLAGGED"
    assert r["hash_verified"] is False


def test_oversized_and_malformed_items_are_excluded(court, direct_vm, world_ids):
    incident_id = file_case(court, direct_vm, "RC01")
    commit(court, direct_vm, incident_id, [
        item("TIMESTAMPED_FILE", "sources/harbor/capture-oversized.txt"),
        item("AGENT_TRACE", "sources/meridian/trace-malformed.json", submitter="controller",
             issuer="Meridian Labs agent runtime")])
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, incident_id, answer_for("RC01"))
    assert record["verdict"] == "CONFIRMED_COMPROMISE"
    assert receipt(record, "E7")["status"] == "TOO_LARGE"
    assert receipt(record, "E7")["hash_verified"] is True
    assert receipt(record, "E8")["status"] == "UNPARSEABLE"
    assert receipt(record, "E8")["counted"] is False
    rows = {r["evidence_id"]: r for r in record["rows"]}
    assert rows["E7"]["byte_count"] > 8000


# -- code scans ----------------------------------------------------------------------------

def test_stale_evidence_is_excluded(court, direct_vm, world_ids):
    incident_id = file_case(court, direct_vm, "RC01")
    commit(court, direct_vm, incident_id, [
        item("AGENT_TRACE", "sources/meridian/trace-ses-3120-stale.json",
             submitter="controller", issuer="Meridian Labs agent runtime")])
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, incident_id, answer_for("RC01"))
    stale = indicator(record, "STALE_EVIDENCE")
    assert stale["state"] == "PRESENT" and stale["evidence_ids"] == ["E7"]
    assert "EXCLUDED:E7" in record["reason_codes"]


def test_a_trace_with_a_gap_is_excluded_and_the_logging_duty_fails(court, direct_vm, world_ids):
    """RC04 as a filed incident."""
    incident_id = file_case(court, direct_vm, "RC04")
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, incident_id, answer_for("RC04"))
    assert indicator(record, "TRACE_SEQUENCE_GAP")["evidence_ids"] == ["E2"]
    r6 = finding(record, "R6")
    assert r6["state"] == "VIOLATED" and r6["by"] == "CODE"
    assert "LOGS_WITHHELD:R6" in record["reason_codes"]
    assert record["verdict"] == "CONFIRMED_VIOLATION" and record["severity"] == 4
    assert "LOGGING_FAILURE" in record["impact_classification"]
    facts = {f["evidence_id"]: f for f in record["facts"]}
    assert facts["E2"]["values"]["sequence_gaps"] == 1


def test_a_complete_log_set_leaves_the_logging_rule_to_the_panel(court, direct_vm, world_ids):
    incident_id = file_case(court, direct_vm, "RC04")
    commit(court, direct_vm, incident_id, [M_TRACE])
    warp(direct_vm, later(86400 + 1))
    answer = answer_for("RC04")
    answer["rules"]["R6"] = {"state": "NOT_VIOLATED", "note": "",
                             "quotes": [{"evidence_id": "E1", "text": "Harbor Supplies "
                                                                      "accounts team"}]}
    record = adjudicate(court, direct_vm, incident_id, answer)
    r6 = finding(record, "R6")
    assert r6["by"] == "PANEL" and r6["state"] == "NOT_VIOLATED"


def test_a_trace_whose_times_run_backwards_is_excluded(court, direct_vm, world_ids):
    """RC03 as a filed incident."""
    incident_id = file_case(court, direct_vm, "RC03")
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, incident_id, answer_for("RC03"))
    assert indicator(record, "TRACE_TIME_REVERSAL")["evidence_ids"] == ["E3"]
    assert receipt(record, "E3")["tamper_status"] == "FLAGGED"
    assert record["verdict"] == "INCONCLUSIVE"


def test_impersonated_issuers_are_excluded(court, direct_vm, world_ids):
    incident_id = file_case(court, direct_vm, "RC02")
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, incident_id, answer_for("RC02"))
    assert indicator(record, "SOURCE_IDENTITY_MISMATCH")["evidence_ids"] == ["E2"]
    assert record["verdict"] == "INSUFFICIENT_EVIDENCE"


def test_evidence_about_another_agent_is_unlinked(court, direct_vm, world_ids):
    incident_id = file_case(court, direct_vm, "RC06")
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, incident_id, answer_for("RC06"))
    assert indicator(record, "EVIDENCE_UNLINKED")["evidence_ids"] == ["E1", "E2"]
    assert record["scans"]["unlinked"] == ["E1", "E2"]
    assert record["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert receipt(record, "E2")["relevance_status"] == "NAMES_ANOTHER_AGENT"


# -- chain reads --------------------------------------------------------------------------

@pytest.mark.parametrize("state,expected_fact,verdict", [
    ("CANCELED", "FAILED", "CONFIRMED_COMPROMISE"),
    ("PENDING", "PENDING", "SOURCE_UNAVAILABLE"),
    ("MISSING", "NOT_FOUND", "CONFIRMED_COMPROMISE"),
    ("DOWN", "UNAVAILABLE", "SOURCE_UNAVAILABLE"),
])
def test_chain_states(court, direct_vm, world_ids, state, expected_fact, verdict):
    incident_id = file_case(court, direct_vm, "RC01")
    warp(direct_vm, later(86400 + 1))
    chain = default_chain()
    if state == "MISSING":
        chain[tx_hash("DRAIN")] = None
    elif state == "DOWN":
        chain[tx_hash("DRAIN")] = "DOWN"
    else:
        chain[tx_hash("DRAIN")] = studionet_tx("DRAIN", status=state)
    answer = answer_for("RC01")
    answer["indicators"]["MATERIAL_HARM"]["quotes"] = [
        {"evidence_id": "E3", "text": "Queued payment for invoice INV-2291: 0.02 GEN to the "
                                      "updated Harbor Supplies payout wallet"}]
    record = adjudicate(court, direct_vm, incident_id, answer, chain=chain)
    fact = record["chain"][0]
    assert fact["state"] == expected_fact
    assert fact["sender"] == "" and fact["value_atto"] == 0
    assert record["verdict"] == verdict, record["reason_codes"]
    if expected_fact in ("FAILED", "NOT_FOUND"):
        assert indicator(record, "ANCHOR_NOT_FOUND")["evidence_ids"] == ["E6"]
        assert finding(record, "R4")["state"] == "UNVERIFIABLE"


def test_a_respondents_pending_transaction_is_excluded_not_held(court, direct_vm, world_ids):
    incident_id = file_case(court, direct_vm, "RC01")
    as_sender(direct_vm, "controller")
    submit(court, incident_id, "CHAIN_TRANSACTION", "", "", issuer="StudioNet",
           chain="genlayer-studionet", tx=tx_hash("VENDOR_PAYMENT"))
    chain = default_chain()
    chain[tx_hash("VENDOR_PAYMENT")] = studionet_tx("VENDOR_PAYMENT", status="PENDING")
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, incident_id, answer_for("RC01"), chain=chain)
    assert record["verdict"] == "CONFIRMED_COMPROMISE"
    assert receipt(record, "E7")["authenticity_status"] == "EXCLUDED:PENDING"


def test_spending_and_counterparty_rules_are_decided_by_code(court, direct_vm, world_ids):
    incident_id = open_incident(court, direct_vm, alleged_rules=["R4", "R5"],
                                implicated_tool_id="")
    commit(court, direct_vm, incident_id, [
        H_REPORT, item("CHAIN_TRANSACTION", None, chain="VENDOR_PAYMENT", issuer="StudioNet")])
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, incident_id, {
        "rules": {}, "indicators": {
            "REPORTED_ACTION_OCCURRED": {"state": "PRESENT", "note": "", "quotes": [
                {"evidence_id": "E2", "text": "the agent's declared wallet"}]}}})
    for rule_id in ("R4", "R5"):
        f = finding(record, rule_id)
        assert f["state"] == "NOT_VIOLATED" and f["by"] == "CODE" and f["evidence_ids"] == ["E2"]
    # StudioNet answered with mixed-case addresses; the fact is lowercase
    assert record["chain"][0]["sender"] == wallet("agent_wallet")
    assert record["chain"][0]["recipient"] == wallet("vendor_a")
    assert record["verdict"] == "POLICY_COMPLIANT" and record["severity"] == 1


def test_a_transaction_from_another_wallet_decides_nothing(court, direct_vm, world_ids):
    """RC08 as a filed incident: false positive, the bond forfeited."""
    incident_id = file_case(court, direct_vm, "RC08")
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, incident_id, answer_for("RC08"))
    assert finding(record, "R4")["state"] == "UNVERIFIABLE"
    assert receipt(record, "E2")["relevance_status"] == "NOT_SENT_BY_AGENT_WALLET"
    assert record["verdict"] == "FALSE_POSITIVE"
    assert record["compensation_or_bounty_recommendation"]["report_bond"] == "FORFEIT"


# -- the commitment registry --------------------------------------------------------------

def test_reuse_across_live_incidents_flags_only_the_later_copy(court, direct_vm, world_ids):
    first = open_incident(court, direct_vm)
    commit(court, direct_vm, first, [H_REPORT, M_TRACE])
    # a Northwind incident could not even cite Harbor's host: it is no party's origin there
    northwind = open_incident(court, direct_vm, CASES["RC01"], reporter="northwind")
    with direct_vm.expect_revert("is not under a registered origin"):
        commit(court, direct_vm, northwind, [H_REPORT], reporter="northwind")
    second = open_incident(court, direct_vm)
    commit(court, direct_vm, second, [H_REPORT, M_TRACE,
                                      item("THREAT_INTEL",
                                           "sources/public/advisory-invoice-injection.txt",
                                           issuer="Invoice Threat Watch")])
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, second, {"rules": {}, "indicators": {}})
    reuse = indicator(record, "CROSS_CASE_REUSE")
    assert reuse["state"] == "PRESENT" and reuse["evidence_ids"] == ["E1", "E2"]
    assert record["verdict"] == "INSUFFICIENT_EVIDENCE"
    record = adjudicate(court, direct_vm, first, {"rules": {}, "indicators": {}})
    assert indicator(record, "CROSS_CASE_REUSE")["state"] == "ABSENT"


def test_evidence_of_an_incident_that_closed_unresolved_may_be_filed_again(court, direct_vm,
                                                                           world_ids):
    first = open_incident(court, direct_vm)
    commit(court, direct_vm, first, [H_REPORT, M_TRACE])
    warp(direct_vm, later(3 * 86400 + 1))
    as_sender(direct_vm, "stranger")
    assert court.close_stalled_incident(first) == "CLOSED_UNRESOLVED"
    second = file_case(court, direct_vm, "RC01")
    warp(direct_vm, later(4 * 86400 + 2))
    record = adjudicate(court, direct_vm, second, answer_for("RC01"))
    assert indicator(record, "CROSS_CASE_REUSE")["state"] == "ABSENT"
    assert record["verdict"] == "CONFIRMED_COMPROMISE"


def test_a_replay_of_a_finalized_incident_is_rejected(court, direct_vm, world_ids):
    first = file_case(court, direct_vm, "RC01")
    warp(direct_vm, later(86400 + 1))
    adjudicate(court, direct_vm, first, answer_for("RC01"))
    warp(direct_vm, later(2 * 86400 + 2))
    court.finalize_incident(first)
    second = file_case(court, direct_vm, "RC01")
    warp(direct_vm, later(3 * 86400 + 3))
    record = adjudicate(court, direct_vm, second, answer_for("RC01"))
    assert record["verdict"] == "REJECTED"
    advice = record["compensation_or_bounty_recommendation"]
    assert advice["report_bond"] == "FORFEIT" and advice["compensation_atto"] == "0"
    assert present(record) == ["CROSS_CASE_REUSE"] or "CROSS_CASE_REUSE" in present(record)


def test_the_round_is_bound_to_the_committed_evidence(court, direct_vm, world_ids):
    incident_id = file_case(court, direct_vm, "RC01")
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, incident_id, answer_for("RC01"))
    ids = court.get_incident(incident_id)["evidence_ids"]
    assert record["evidence_ids"] == ids
    assert len(record["evidence_commitment"]) == 64
    assert record["evidence"][2]["content_hash"] == item_sha("sources/meridian/trace-ses-4471.json")
    assert court.get_evidence(ids[2])["source_locator"] == TRACE_URL
    assert json.loads(json.dumps(record["facts"]))[0]["agent_id"] == AGENT
