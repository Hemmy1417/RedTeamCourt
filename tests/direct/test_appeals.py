"""Appeals and readjudication: a party appeals the standing record, by id,
inside its window, with evidence it committed afterwards; the record appealed
never changes; a readjudication names what changed; an appeal nobody hears
lapses and the appealed record stands."""

from tests.direct.support import (
    CASES, adjudicate, answer_for, as_sender, commit, finding, later, open_incident, stage, warp)

GRANTS_PATH = "sources/meridian/access-ledgerline-grants.json"

H_REPORT, H_INVOICE = CASES["RC01"]["evidence"][0], CASES["RC01"]["evidence"][1]
DRAIN = CASES["RC01"]["evidence"][5]
M_CALLS = CASES["RC04"]["evidence"][2]


def state(value, *quotes):
    return {"state": value, "note": "", "quotes": [{"evidence_id": e, "text": t}
                                                   for e, t in quotes]}


# the reporter's own two items cannot convict: nothing outside its sphere
FIRST_ANSWER = {
    "rules": {"R1": state("UNVERIFIABLE"), "R7": state("UNVERIFIABLE")},
    "indicators": {"REPORTED_ACTION_OCCURRED": state("UNDETERMINED"),
                   "AGENT_UNDER_EXTERNAL_CONTROL": state("UNDETERMINED"),
                   "CONTROLLER_MISCONFIGURATION": state("UNDETERMINED"),
                   "TOOL_FAULT": state("ABSENT"), "EXTERNAL_DEPENDENCY_FAILURE": state("ABSENT"),
                   "MATERIAL_HARM": state("UNDETERMINED"), "ONGOING_EXPOSURE": state("ABSENT"),
                   "EVIDENCE_TAMPERING": state("ABSENT"), "ADJUDICATOR_INJECTION": state("ABSENT")}}
# with the chain record of the payment added on appeal
APPEAL_ANSWER = {
    "rules": {"R1": state("UNVERIFIABLE"), "R7": state("UNVERIFIABLE")},
    "indicators": {"REPORTED_ACTION_OCCURRED": state("PRESENT",
                                                     ("E3", "the agent's declared wallet")),
                   "AGENT_UNDER_EXTERNAL_CONTROL": state(
                       "PRESENT", ("E2", "SYSTEM NOTICE TO THE PAYMENT AGENT")),
                   "CONTROLLER_MISCONFIGURATION": state("ABSENT"),
                   "TOOL_FAULT": state("ABSENT"), "EXTERNAL_DEPENDENCY_FAILURE": state("ABSENT"),
                   "MATERIAL_HARM": state("PRESENT", ("E3", "the agent's declared wallet")),
                   "ONGOING_EXPOSURE": state("ABSENT"),
                   "EVIDENCE_TAMPERING": state("ABSENT"), "ADJUDICATOR_INJECTION": state("ABSENT")}}


def first_round(court, direct_vm):
    incident_id = open_incident(court, direct_vm)
    commit(court, direct_vm, incident_id, [H_REPORT, H_INVOICE])
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, incident_id, FIRST_ANSWER)
    return incident_id, record


def appeal_with_the_payment(court, direct_vm, incident_id, record):
    [drain_id] = commit(court, direct_vm, incident_id, [DRAIN])
    as_sender(direct_vm, "harbor")
    appeal_id = court.submit_appeal(incident_id, record["adjudication_id"],
                                    "The chain shows the agent's wallet paid the attacker.",
                                    [drain_id])
    return appeal_id, drain_id


def test_a_valid_appeal_with_new_evidence_changes_the_outcome(court, direct_vm, world_ids):
    incident_id, first = first_round(court, direct_vm)
    assert first["verdict"] == "INCONCLUSIVE"
    appeal_id, drain_id = appeal_with_the_payment(court, direct_vm, incident_id, first)
    assert appeal_id == "AP-000001"
    appeal = court.get_appeal(appeal_id)
    assert appeal["original_adjudication_id"] == first["adjudication_id"]
    assert appeal["additional_evidence_ids"] == [drain_id]
    assert appeal["policy_version"] == 1 and appeal["appellant_role"] == "reporter"
    assert appeal["status"] == "OPEN"
    assert court.get_evidence(drain_id)["phase"] == "APPEAL"

    as_sender(direct_vm, "stranger")
    stage(direct_vm, APPEAL_ANSWER)
    second_id = court.request_readjudication(appeal_id)
    second = court.get_adjudication(second_id)
    assert second["kind"] == "READJUDICATION"
    assert second["verdict"] == "CONFIRMED_COMPROMISE" and second["severity"] == 5
    assert second["appeal_of"] == first["adjudication_id"] and second["appeal_id"] == appeal_id
    changes = second["changes"]
    assert changes["verdict"] == ["INCONCLUSIVE", "CONFIRMED_COMPROMISE"]
    assert changes["severity"] == [0, 5]
    assert changes["added_evidence"] == [drain_id]
    assert "VERDICT:CONFIRMED_COMPROMISE" in changes["reason_codes_added"]
    assert "VERDICT:INCONCLUSIVE" in changes["reason_codes_removed"]
    assert finding(second, "R4")["state"] == "VIOLATED"
    # history is immutable: the appealed record reads exactly as it did
    assert court.get_adjudication(first["adjudication_id"]) == first
    assert court.get_appeal(appeal_id)["status"] == "HEARD"
    assert court.get_incident_history(incident_id, 0, 10)["items"] == [
        first["adjudication_id"], second_id]
    assert court.get_latest_adjudication(incident_id)["adjudication_id"] == second_id


def test_an_expired_appeal_is_refused(court, direct_vm, world_ids):
    """RC27: one second past the window."""
    incident_id, first = first_round(court, direct_vm)
    [drain_id] = commit(court, direct_vm, incident_id, [DRAIN])
    warp(direct_vm, later(2 * 86400 + 2))
    as_sender(direct_vm, "harbor")
    with direct_vm.expect_revert("expired appeal: the appeal window closed at"):
        court.submit_appeal(incident_id, first["adjudication_id"], "late", [drain_id])


def test_an_appeal_names_the_standing_record_and_its_own_new_evidence(court, direct_vm,
                                                                     world_ids):
    incident_id, first = first_round(court, direct_vm)
    judged = court.get_incident(incident_id)["evidence_ids"]
    as_sender(direct_vm, "harbor")
    with direct_vm.expect_revert("an appeal names the standing adjudication"):
        court.submit_appeal(incident_id, "AD-000999", "wrong record", [judged[0]])
    with direct_vm.expect_revert("an appeal names 1 to 3 new evidence items"):
        court.submit_appeal(incident_id, first["adjudication_id"], "no evidence", [])
    with direct_vm.expect_revert("an appellant names evidence it committed after"):
        court.submit_appeal(incident_id, first["adjudication_id"], "old evidence", [judged[0]])
    [calls_id] = commit(court, direct_vm, incident_id, [M_CALLS])
    as_sender(direct_vm, "harbor")
    with direct_vm.expect_revert("an appellant names evidence it committed after"):
        court.submit_appeal(incident_id, first["adjudication_id"], "their evidence", [calls_id])
    with direct_vm.expect_revert("new evidence must belong to this incident"):
        court.submit_appeal(incident_id, first["adjudication_id"], "nothing", ["EV-000999"])
    [drain_id] = commit(court, direct_vm, incident_id, [DRAIN])
    as_sender(direct_vm, "harbor")
    with direct_vm.expect_revert("new evidence must be evidence no round has read"):
        court.submit_appeal(incident_id, first["adjudication_id"], "twice",
                            [drain_id, drain_id])
    with direct_vm.expect_revert("reason is required"):
        court.submit_appeal(incident_id, first["adjudication_id"], "", [drain_id])
    as_sender(direct_vm, "stranger")
    with direct_vm.expect_revert("only a party to this incident can appeal"):
        court.submit_appeal(incident_id, first["adjudication_id"], "me too", [drain_id])


def test_the_controller_may_appeal_with_its_own_evidence(court, direct_vm, world_ids):
    incident_id, first = first_round(court, direct_vm)
    [calls_id] = commit(court, direct_vm, incident_id, [M_CALLS])
    as_sender(direct_vm, "controller")
    appeal_id = court.submit_appeal(incident_id, first["adjudication_id"],
                                    "Our tool-call log shows what happened.", [calls_id])
    assert court.get_appeal(appeal_id)["appellant_role"] == "controller"


def test_one_open_appeal_at_a_time_and_no_finalizing_under_it(court, direct_vm, world_ids):
    incident_id, first = first_round(court, direct_vm)
    appeal_id, _ = appeal_with_the_payment(court, direct_vm, incident_id, first)
    [calls_id] = commit(court, direct_vm, incident_id, [M_CALLS])
    as_sender(direct_vm, "controller")
    with direct_vm.expect_revert("an appeal is already waiting to be heard"):
        court.submit_appeal(incident_id, first["adjudication_id"], "mine", [calls_id])
    warp(direct_vm, later(2 * 86400 + 2))
    with direct_vm.expect_revert("an appeal is waiting to be heard"):
        court.finalize_incident(incident_id)
    status = court.incident_status(incident_id, later(2 * 86400 + 2))
    assert status["appeal_pending"] is True and status["open_appeal_id"] == appeal_id
    assert status["can_finalize"] is False


def test_appeals_are_capped(court, direct_vm, world_ids):
    incident_id, first = first_round(court, direct_vm)
    appeal_id, _ = appeal_with_the_payment(court, direct_vm, incident_id, first)
    stage(direct_vm, FIRST_ANSWER)
    second = court.get_adjudication(court.request_readjudication(appeal_id))
    [calls_id] = commit(court, direct_vm, incident_id, [M_CALLS])
    as_sender(direct_vm, "controller")
    third_appeal = court.submit_appeal(incident_id, second["adjudication_id"], "again",
                                       [calls_id])
    stage(direct_vm, FIRST_ANSWER)
    third = court.get_adjudication(court.request_readjudication(third_appeal))
    assert third["kind"] == "READJUDICATION"
    as_sender(direct_vm, "harbor")
    with direct_vm.expect_revert("this incident has used its appeals"):
        court.submit_appeal(incident_id, third["adjudication_id"], "once more", [calls_id])
    with direct_vm.expect_revert("this appeal is HEARD"):
        court.request_readjudication(appeal_id)


def test_a_lapsed_appeal_restores_the_appealed_record(court, direct_vm, world_ids):
    """S29: an appeal nobody asks to hear cannot hold a settling record
    forever. After the stall window it lapses, and the record it appealed
    settles exactly as if no appeal had been filed."""
    incident_id = open_incident(court, direct_vm)
    commit(court, direct_vm, incident_id, CASES["RC01"]["evidence"])
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, incident_id, answer_for("RC01"))
    assert record["verdict"] == "CONFIRMED_COMPROMISE"
    [calls_id] = commit(court, direct_vm, incident_id, [M_CALLS])
    as_sender(direct_vm, "controller")
    appeal_id = court.submit_appeal(incident_id, record["adjudication_id"], "delay", [calls_id])
    warp(direct_vm, later(86400 + 1 + 2 * 86400))
    as_sender(direct_vm, "stranger")
    with direct_vm.expect_revert("the appeal can still be heard until"):
        court.close_stalled_incident(incident_id)
    warp(direct_vm, later(86400 + 2 + 2 * 86400))
    assert court.close_stalled_incident(incident_id) == "CONFIRMED_COMPROMISE"
    view = court.get_incident(incident_id)
    assert view["status"] == "FINALIZED" and view["route"] == "APPEAL_LAPSED"
    assert view["settled_record_id"] == record["adjudication_id"]
    assert court.get_appeal(appeal_id)["status"] == "LAPSED"


def test_an_appellant_cannot_win_by_withdrawing_what_the_first_round_read(court, direct_vm,
                                                                          world_ids):
    """S14: an appeal judges what the first panel saw. Meridian's access
    record admitted that POST was enabled; Meridian appeals, then stops
    serving the record. Its bytes are hash-bound, so they cannot be changed,
    but a round without them would judge less than the record it replaces -
    so the readjudication does not run, the appeal waits, and when it lapses
    the appealed compromise settles."""
    incident_id = open_incident(court, direct_vm)
    commit(court, direct_vm, incident_id, CASES["RC01"]["evidence"])
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, incident_id, answer_for("RC01"))
    assert record["verdict"] == "CONFIRMED_COMPROMISE"
    [calls_id] = commit(court, direct_vm, incident_id, [M_CALLS])
    as_sender(direct_vm, "controller")
    appeal_id = court.submit_appeal(incident_id, record["adjudication_id"],
                                    "Our tool-call log tells the story.", [calls_id])
    grants_id = court.get_incident(incident_id)["evidence_ids"][3]
    stage(direct_vm, answer_for("RC01"), skip=(GRANTS_PATH,))
    as_sender(direct_vm, "stranger")
    with direct_vm.expect_revert("the appealed round read " + grants_id + ", which this round "
                                 "could not read again"):
        court.request_readjudication(appeal_id)
    assert court.get_appeal(appeal_id)["status"] == "OPEN"
    assert court.get_incident_history(incident_id, 0, 10)["items"] == [
        record["adjudication_id"]]
    warp(direct_vm, later(86400 + 2 + 2 * 86400))
    assert court.close_stalled_incident(incident_id) == "CONFIRMED_COMPROMISE"
    view = court.get_incident(incident_id)
    assert view["route"] == "APPEAL_LAPSED"
    assert view["settled_record_id"] == record["adjudication_id"]


def test_a_readjudication_runs_once_everything_is_served_again(court, direct_vm, world_ids):
    """The same rule for an honest outage: the reporter's host is down when
    the appeal is first heard, nothing is recorded, and the appeal is heard
    once the report is served again."""
    incident_id, first = first_round(court, direct_vm)
    appeal_id, _ = appeal_with_the_payment(court, direct_vm, incident_id, first)
    stage(direct_vm, APPEAL_ANSWER, skip=(H_REPORT["path"],))
    as_sender(direct_vm, "stranger")
    with direct_vm.expect_revert("which this round could not read again"):
        court.request_readjudication(appeal_id)
    stage(direct_vm, APPEAL_ANSWER)
    second = court.get_adjudication(court.request_readjudication(appeal_id))
    assert second["verdict"] == "CONFIRMED_COMPROMISE"


def test_a_lapsed_appeal_of_a_holding_record_releases_everything(court, direct_vm, world_ids):
    incident_id, first = first_round(court, direct_vm)
    appeal_with_the_payment(court, direct_vm, incident_id, first)
    warp(direct_vm, later(86400 + 2 + 2 * 86400))
    as_sender(direct_vm, "stranger")
    assert court.close_stalled_incident(incident_id) == "CLOSED_UNRESOLVED"
    view = court.get_incident(incident_id)
    assert view["route"] == "APPEAL_LAPSED" and view["report_bond_outcome"] == "RETURN"
    assert view["reserved_compensation_atto"] == "0"
