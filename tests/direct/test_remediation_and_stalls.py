"""Remediation reviews and the wall-clock exits: a fix is verified only by test
results supported from outside the controller's sphere; every held state has
a permissionless exit; and nobody closes or finalizes anything early."""

from tests.direct.support import (
    AGENT, CASES, CLAIM, REPORT_BOND, adjudicate, answer_for, as_sender, claimable, commit,
    file_case, later, open_incident, stage, warp)

NW_RETEST = {"category": "REMEDIATION_TEST", "path": "sources/northwind/retest-nw-2026-014.json",
             "chain": None, "submitter": "controller", "issuer": "Northwind Security retest",
             "description": "Northwind's retest", "access": "PUBLIC",
             "observed_at": "2026-09-14T16:30:00Z", "trace_reference": "", "hash_of": None}
M_RETEST = dict(NW_RETEST, path="sources/meridian/retest-meridian-5102.json",
                issuer="Meridian Labs QA", description="Meridian's own regression run")
PATCH_NOTES = dict(NW_RETEST, category="TIMESTAMPED_FILE",
                   path="sources/meridian/patch-notes-2026-09-14.txt", issuer="Meridian Labs",
                   description="patch notes")
VERIFIED = {"indicators": {
    "REMEDIATION_VERIFIED": {"state": "PRESENT", "note": "", "quotes": [
        {"evidence_id": "E1", "text": "Ledgerline made no docfetch.post call and refused every "
                                      "notice"}]},
    "EVIDENCE_TAMPERING": {"state": "ABSENT", "quotes": [], "note": ""},
    "ADJUDICATOR_INJECTION": {"state": "ABSENT", "quotes": [], "note": ""}}}


def finalized_disclosure(court, direct_vm):
    incident_id = file_case(court, direct_vm, "RC32")
    warp(direct_vm, later(86400 + 1))
    adjudicate(court, direct_vm, incident_id, answer_for("RC32"))
    warp(direct_vm, later(2 * 86400 + 2))
    court.finalize_incident(incident_id)
    return incident_id


def report(court, direct_vm, incident_id, items, statement="Fixed and retested."):
    ids = commit(court, direct_vm, incident_id, items, "northwind")
    as_sender(direct_vm, "controller")
    court.submit_remediation_report(incident_id, statement, ids)
    return ids


def review(court, direct_vm, incident_id, answer):
    stage(direct_vm, answer)
    as_sender(direct_vm, "stranger")
    return court.get_adjudication(court.request_remediation_review(incident_id))


def test_a_remediation_supported_by_the_researchers_retest_is_verified(court, direct_vm,
                                                                      world_ids):
    incident_id = finalized_disclosure(court, direct_vm)
    status = court.agent_security_status(AGENT, later(2 * 86400 + 3))
    assert status["standing"] == "REMEDIATION_REQUIRED"
    assert status["required_remediation"] == ["RETRAIN_OR_RECONFIGURE", "DISCLOSE_VULNERABILITY",
                                              "RETEST_BEFORE_RESTORE"]
    ids = report(court, direct_vm, incident_id, [NW_RETEST, M_RETEST])
    assert [court.get_evidence(e)["phase"] for e in ids] == ["REMEDIATION", "REMEDIATION"]
    assert court.get_evidence(ids[0])["origin"] == "REPORTER"
    assert court.get_incident(incident_id)["remediation_status"] == "REPORTED"
    record = review(court, direct_vm, incident_id, VERIFIED)
    assert record["kind"] == "REMEDIATION_REVIEW"
    assert record["verdict"] == "VERIFIED" and record["settles"] is True
    assert record["finding_under_remediation"]["verdict"] == "CONFIRMED_VULNERABILITY"
    assert record["remediation_statement"] == "Fixed and retested."
    assert "REMEDIATION_TESTS:2" in record["reason_codes"]
    assert court.get_incident(incident_id)["remediation_status"] == "VERIFIED"
    status = court.agent_security_status(AGENT, later(2 * 86400 + 3))
    assert status["standing"] == "IN_GOOD_STANDING"
    assert status["verified_remediations"] == 1
    history = court.get_incident_history(incident_id, 0, 10)["items"]
    assert history[-1] == record["adjudication_id"] and len(history) == 2


def test_a_remediation_claim_without_test_results_is_insufficient(court, direct_vm, world_ids):
    """RC20: patch notes are a claim, not verification."""
    incident_id = finalized_disclosure(court, direct_vm)
    report(court, direct_vm, incident_id, [PATCH_NOTES])
    record = review(court, direct_vm, incident_id, VERIFIED)
    assert record["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert "REMEDIATION_TESTS:0" in record["reason_codes"]
    assert court.get_incident(incident_id)["remediation_status"] == "REQUIRED"


def test_the_controllers_own_retest_cannot_verify_its_own_fix(court, direct_vm, world_ids):
    """The mirror floor: a finding that favours the controller needs support
    from outside its sphere, and a remediation is no exception."""
    incident_id = finalized_disclosure(court, direct_vm)
    report(court, direct_vm, incident_id, [M_RETEST])
    answer = {"indicators": dict(VERIFIED["indicators"], REMEDIATION_VERIFIED={
        "state": "PRESENT", "note": "", "quotes": [
            {"evidence_id": "E1", "text": "All 12 injected invoices were refused"}]})}
    record = review(court, direct_vm, incident_id, answer)
    assert record["verdict"] == "INCONCLUSIVE"
    assert [f for f in record["indicators"] if f["id"] == "REMEDIATION_VERIFIED"][0]["state"] \
        == "UNDETERMINED"
    assert court.get_incident(incident_id)["remediation_status"] == "REQUIRED"


def test_remediation_refusals(court, direct_vm, world_ids):
    incident_id = file_case(court, direct_vm, "RC32")
    as_sender(direct_vm, "controller")
    with direct_vm.expect_revert("this incident has no open finding to remediate"):
        court.submit_remediation_report(incident_id, "early", ["EV-000001"])
    with direct_vm.expect_revert("no remediation report is waiting for review"):
        court.request_remediation_review(incident_id)
    warp(direct_vm, later(86400 + 1))
    adjudicate(court, direct_vm, incident_id, answer_for("RC32"))
    warp(direct_vm, later(2 * 86400 + 2))
    court.finalize_incident(incident_id)
    ids = commit(court, direct_vm, incident_id, [NW_RETEST], "northwind")
    as_sender(direct_vm, "northwind")
    with direct_vm.expect_revert("only the controller reports a remediation"):
        court.submit_remediation_report(incident_id, "mine", ids)
    as_sender(direct_vm, "controller")
    with direct_vm.expect_revert("names remediation evidence of this incident"):
        court.submit_remediation_report(incident_id, "old evidence", ["EV-000001"])
    with direct_vm.expect_revert("a remediation report names 1 to 4"):
        court.submit_remediation_report(incident_id, "nothing", [])
    court.submit_remediation_report(incident_id, "fixed", ids)
    record = review(court, direct_vm, incident_id, {"indicators": {}})
    assert record["verdict"] == "INCONCLUSIVE"
    as_sender(direct_vm, "controller")
    with direct_vm.expect_revert("each remediation item is reviewed once"):
        court.submit_remediation_report(incident_id, "again", ids)


def test_remediation_reviews_are_capped(court, direct_vm, world_ids):
    incident_id = finalized_disclosure(court, direct_vm)
    for n in range(3):
        report(court, direct_vm, incident_id,
               [dict(PATCH_NOTES, path="sources/northwind/vuln-report-nw-2026-02%d-%s.txt" % (
                   n, ("theoretical", "payload", "hidden")[n]))])
        review(court, direct_vm, incident_id, VERIFIED)
    ids = commit(court, direct_vm, incident_id, [NW_RETEST], "northwind")
    as_sender(direct_vm, "controller")
    with direct_vm.expect_revert("used its 3 remediation reviews"):
        court.submit_remediation_report(incident_id, "a fourth", ids)


def test_an_incident_nobody_adjudicates_closes_after_the_windows(court, direct_vm, world_ids):
    incident_id = file_case(court, direct_vm, "RC01")
    as_sender(direct_vm, "controller")
    with direct_vm.expect_revert("an adjudication can still be requested until"):
        court.close_stalled_incident(incident_id)
    warp(direct_vm, later(3 * 86400))
    with direct_vm.expect_revert("an adjudication can still be requested until"):
        court.close_stalled_incident(incident_id)
    warp(direct_vm, later(3 * 86400 + 1))
    as_sender(direct_vm, "stranger")
    assert court.incident_status(incident_id, later(3 * 86400 + 1))["can_close_stalled"] is True
    assert court.close_stalled_incident(incident_id) == "CLOSED_UNRESOLVED"
    view = court.get_incident(incident_id)
    assert view["route"] == "NO_ADJUDICATION" and view["reserved_compensation_atto"] == "0"
    assert claimable(court, "harbor") == REPORT_BOND
    agent = court.get_agent(AGENT)
    assert agent["security_bond_reserved_atto"] == "0" and agent["open_incidents"] == 0
    with direct_vm.expect_revert("is CLOSED_UNRESOLVED and not stalled"):
        court.close_stalled_incident(incident_id)
    with direct_vm.expect_revert("this incident takes no evidence while CLOSED_UNRESOLVED"):
        commit(court, direct_vm, incident_id, [CASES["RC01"]["evidence"][0]])


def test_a_holding_verdict_closes_after_the_appeal_and_stall_windows(court, direct_vm,
                                                                    world_ids):
    incident_id = file_case(court, direct_vm, "RC03")
    warp(direct_vm, later(86400 + 1))
    adjudicate(court, direct_vm, incident_id, answer_for("RC03"))
    warp(direct_vm, later(4 * 86400 + 1))
    with direct_vm.expect_revert("the appeal and stall windows run until"):
        court.close_stalled_incident(incident_id)
    warp(direct_vm, later(4 * 86400 + 2))
    assert court.close_stalled_incident(incident_id) == "CLOSED_UNRESOLVED"
    assert court.get_incident(incident_id)["route"] == "HELD_VERDICT"


def test_a_settling_verdict_is_finalized_never_closed(court, direct_vm, world_ids):
    """RC28: the controller cannot close its way out of a finding."""
    incident_id = file_case(court, direct_vm, "RC01")
    warp(direct_vm, later(86400 + 1))
    adjudicate(court, direct_vm, incident_id, answer_for("RC01"))
    as_sender(direct_vm, "controller")
    with direct_vm.expect_revert("the appeal window is open until"):
        court.finalize_incident(incident_id)
    warp(direct_vm, later(5 * 86400))
    with direct_vm.expect_revert("this adjudication settles; finalize_incident is its exit"):
        court.close_stalled_incident(incident_id)
    assert court.finalize_incident(incident_id) == "CONFIRMED_COMPROMISE"
    with direct_vm.expect_revert("only an adjudicated incident can be finalized"):
        court.finalize_incident(incident_id)
    assert claimable(court, "harbor") == CLAIM // 2 + REPORT_BOND


def test_adjudication_timing_and_counter_reports(court, direct_vm, world_ids):
    incident_id = open_incident(court, direct_vm)
    as_sender(direct_vm, "stranger")
    with direct_vm.expect_revert("respondents may still answer until"):
        court.request_adjudication(incident_id)
    warp(direct_vm, later(86400 + 1))
    with direct_vm.expect_revert("no evidence has been committed to this incident"):
        court.request_adjudication(incident_id)
    as_sender(direct_vm, "harbor")
    with direct_vm.expect_revert("only a respondent"):
        court.submit_counterreport(incident_id, "I am the reporter")
    as_sender(direct_vm, "controller")
    court.submit_counterreport(incident_id, "Late but here.")
    with direct_vm.expect_revert("the controller has already answered"):
        court.submit_counterreport(incident_id, "again")
    commit(court, direct_vm, incident_id, CASES["RC01"]["evidence"])
    adjudicate(court, direct_vm, incident_id, answer_for("RC01"))
    as_sender(direct_vm, "docfetch")
    with direct_vm.expect_revert("counter-reports close when an adjudication is requested"):
        court.submit_counterreport(incident_id, "too late")
    with direct_vm.expect_revert("is ADJUDICATED; it is adjudicated once"):
        court.request_adjudication(incident_id)


def test_a_review_with_tampered_items_verifies_nothing(court, direct_vm, world_ids):
    """Northwind's retest supports the fix, but the panel finds Meridian's patch
    notes tampered with. A review whose record was manipulated cannot clear the
    finding, however well the rest of it reads."""
    incident_id = finalized_disclosure(court, direct_vm)
    report(court, direct_vm, incident_id, [NW_RETEST, M_RETEST, PATCH_NOTES])
    answer = {"indicators": dict(VERIFIED["indicators"], EVIDENCE_TAMPERING={
        "state": "PRESENT", "note": "", "quotes": [
            {"evidence_id": "E3", "text": "We consider NW-2026-014 fixed."}]})}
    record = review(court, direct_vm, incident_id, answer)
    assert "MANIPULATION:controller:E3" in record["reason_codes"]
    assert record["verdict"] == "CONFLICTING_EVIDENCE"
    assert court.get_incident(incident_id)["remediation_status"] != "VERIFIED"
