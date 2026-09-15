"""Funds and standing: deposits that are refused are returned, reservations
never over-commit a bond, withdrawals wait and never touch what incidents
reserved, an incident pays once, every atto is accounted for, and the one
view a downstream contract reads tells the truth."""

from tests.direct.support import (
    AGENT, BOND, CASES, CLAIM, MILLI, POOL, REPORT_BOND, adjudicate, answer_for, as_sender,
    assert_conserved, claimable, file_case, later, open_incident, warp)


def test_refused_deposits_are_returned_never_reverted(court, direct_vm, world_ids):
    as_sender(direct_vm, "stranger")
    direct_vm.value = 7 * MILLI
    assert court.post_security_bond(AGENT).startswith(
        "RETURNED: only the agent's controller funds it")
    direct_vm.value = 3 * MILLI
    assert court.fund_bounty_pool("AGT-000404") == "RETURNED: unknown agent_id"
    as_sender(direct_vm, "controller")
    direct_vm.value = 10 ** 24
    assert court.post_security_bond(AGENT).startswith("RETURNED: a fund holds at most")
    direct_vm.value = 0
    with direct_vm.expect_revert("send a positive amount"):
        court.post_security_bond(AGENT)
    returned = court.get_returned_deposits(0, 10)
    assert returned["total"] == 3
    assert [r["method"] for r in returned["items"]] == ["post_security_bond", "fund_bounty_pool",
                                                        "post_security_bond"]
    assert claimable(court, "stranger") == 10 * MILLI
    assert claimable(court, "controller") == 10 ** 24
    assert court.get_agent(AGENT)["security_bond_atto"] == str(BOND)
    assert_conserved(court, BOND + POOL + 10 * MILLI + 10 ** 24)


def test_reservations_never_over_commit_the_bond(court, direct_vm, world_ids):
    reserved = []
    for _ in range(4):
        incident_id = open_incident(court, direct_vm, claimed_compensation_atto=200 * MILLI)
        reserved.append(int(court.get_incident(incident_id)["reserved_compensation_atto"]))
    assert reserved == [200 * MILLI, 200 * MILLI, 100 * MILLI, 0]
    agent = court.get_agent(AGENT)
    assert agent["security_bond_reserved_atto"] == agent["security_bond_atto"]
    assert court.agent_security_status(AGENT, later(60))["security_bond_unreserved_atto"] == "0"


def test_withdrawals_wait_and_never_touch_reservations(court, direct_vm, world_ids):
    open_incident(court, direct_vm, claimed_compensation_atto=CLAIM)
    as_sender(direct_vm, "stranger")
    with direct_vm.expect_revert("only the agent's controller can withdraw its funds"):
        court.request_withdrawal(AGENT, "BOND", BOND)
    as_sender(direct_vm, "controller")
    with direct_vm.expect_revert("the fund holds"):
        court.request_withdrawal(AGENT, "BOND", BOND + 1)
    with direct_vm.expect_revert("fund must be BOND or BOUNTY_POOL"):
        court.request_withdrawal(AGENT, "SAVINGS", 1)
    after = court.request_withdrawal(AGENT, "BOND", BOND)
    assert after == later(2 * 86400)
    with direct_vm.expect_revert("already pending until"):
        court.request_withdrawal(AGENT, "BOND", 1)
    # the pending request does not shrink what a new incident can reserve
    second = open_incident(court, direct_vm, claimed_compensation_atto=CLAIM)
    assert court.get_incident(second)["reserved_compensation_atto"] == str(CLAIM)
    as_sender(direct_vm, "controller")
    with direct_vm.expect_revert("the withdrawal completes at"):
        court.complete_withdrawal(AGENT, "BOND")
    warp(direct_vm, later(2 * 86400))
    assert court.agent_security_status(AGENT, later(2 * 86400))["withdrawal_pending"] is True
    assert court.complete_withdrawal(AGENT, "BOND") == str(BOND - 2 * CLAIM)
    agent = court.get_agent(AGENT)
    assert agent["security_bond_atto"] == str(2 * CLAIM)
    assert agent["pending_withdrawals"]["BOND"] == {"amount_atto": "0", "after": ""}
    with direct_vm.expect_revert("no withdrawal from this fund is pending"):
        court.complete_withdrawal(AGENT, "BOND")
    assert claimable(court, "controller") == BOND - 2 * CLAIM
    assert_conserved(court, BOND + POOL + 2 * REPORT_BOND)


def test_a_fully_reserved_fund_keeps_the_request_pending(court, direct_vm, world_ids):
    as_sender(direct_vm, "controller")
    court.request_withdrawal(AGENT, "BOUNTY_POOL", POOL)
    for _ in range(2):
        open_incident(court, direct_vm, CASES["RC32"], reporter="northwind")
    warp(direct_vm, later(2 * 86400))
    as_sender(direct_vm, "controller")
    with direct_vm.expect_revert("open incidents reserve all of this fund"):
        court.complete_withdrawal(AGENT, "BOUNTY_POOL")
    assert court.get_agent(AGENT)["pending_withdrawals"]["BOUNTY_POOL"]["after"] != ""


def test_an_incident_pays_once(court, direct_vm, world_ids):
    """RC29: a second finalize is refused, and the same evidence filed again
    is a rejected replay that pays nothing."""
    incident_id = file_case(court, direct_vm, "RC01")
    warp(direct_vm, later(86400 + 1))
    adjudicate(court, direct_vm, incident_id, answer_for("RC01"))
    warp(direct_vm, later(2 * 86400 + 2))
    court.finalize_incident(incident_id)
    with direct_vm.expect_revert("only an adjudicated incident can be finalized"):
        court.finalize_incident(incident_id)
    paid = claimable(court, "harbor")
    again = file_case(court, direct_vm, "RC01")
    warp(direct_vm, later(3 * 86400 + 3))
    record = adjudicate(court, direct_vm, again, answer_for("RC01"))
    assert record["verdict"] == "REJECTED"
    warp(direct_vm, later(4 * 86400 + 4))
    court.finalize_incident(again)
    assert claimable(court, "harbor") == paid
    assert claimable(court, "controller") == REPORT_BOND
    assert court.get_reporter(court.get_incident(again)["reporter"])["rejected"] == 1
    assert_conserved(court, BOND + POOL + 2 * REPORT_BOND)


def test_a_false_positive_forfeits_the_bond_to_the_controller(court, direct_vm, world_ids):
    incident_id = file_case(court, direct_vm, "RC08")
    warp(direct_vm, later(86400 + 1))
    adjudicate(court, direct_vm, incident_id, answer_for("RC08"))
    warp(direct_vm, later(2 * 86400 + 2))
    court.finalize_incident(incident_id)
    view = court.get_incident(incident_id)
    assert view["report_bond_outcome"] == "FORFEIT" and view["remediation_status"] == "NOT_REQUIRED"
    assert claimable(court, "controller") == REPORT_BOND
    assert claimable(court, "quayside") == 0
    assert court.get_reporter(court.get_incident(incident_id)["reporter"])["false_positives"] == 1
    status = court.agent_security_status(AGENT, later(2 * 86400 + 3))
    assert status["standing"] == "IN_GOOD_STANDING" and status["open_finding_ids"] == []


def test_standing_moves_with_the_record(court, direct_vm, world_ids):
    assert court.agent_security_status(AGENT, later(0))["standing"] == "IN_GOOD_STANDING"
    incident_id = file_case(court, direct_vm, "RC01")
    status = court.agent_security_status(AGENT, later(0))
    assert status["standing"] == "UNDER_INVESTIGATION"
    assert status["open_incident_ids"] == [incident_id]
    warp(direct_vm, later(86400 + 1))
    adjudicate(court, direct_vm, incident_id, answer_for("RC01"))
    warp(direct_vm, later(2 * 86400 + 2))
    court.finalize_incident(incident_id)
    status = court.agent_security_status(AGENT, later(2 * 86400 + 2))
    assert status["standing"] == "CONTAINMENT_REQUIRED"
    assert status["containment_required"] is True
    assert status["open_finding_ids"] == [incident_id]
    assert status["max_open_severity"] == 5
    assert court.agent_security_status(AGENT, "not a time")["error"].startswith("as_of must be")
    assert court.agent_security_status("AGT-000404", later(0)) == {"found": False,
                                                                    "agent_id": "AGT-000404"}
    listing = court.list_agent_incidents(AGENT, 0, 10)
    assert listing == {"total": 1, "items": [incident_id]}


def test_incident_status_names_the_open_actions(court, direct_vm, world_ids):
    incident_id = file_case(court, direct_vm, "RC01")
    status = court.incident_status(incident_id, later(60))
    assert status["can_request_adjudication"] is False
    assert court.incident_status(incident_id, later(86401))["can_request_adjudication"] is True
    warp(direct_vm, later(86400 + 1))
    adjudicate(court, direct_vm, incident_id, answer_for("RC01"))
    status = court.incident_status(incident_id, later(86400 + 2))
    assert status["appeal_window_open"] is True and status["can_finalize"] is False
    status = court.incident_status(incident_id, later(2 * 86400 + 2))
    assert status["can_finalize"] is True and status["can_close_stalled"] is False
    assert court.incident_status("IN-000404", later(0))["found"] is False


def test_withdraw_pays_out_the_whole_claimable_balance(court, direct_vm, world_ids):
    incident_id = file_case(court, direct_vm, "RC08")
    warp(direct_vm, later(86400 + 1))
    adjudicate(court, direct_vm, incident_id, answer_for("RC08"))
    warp(direct_vm, later(2 * 86400 + 2))
    court.finalize_incident(incident_id)
    as_sender(direct_vm, "controller")
    assert court.withdraw() == str(REPORT_BOND)
    assert claimable(court, "controller") == 0
    assert court.get_stats()["claimable_atto"] == "0"
    assert_conserved(court, BOND + POOL + REPORT_BOND, REPORT_BOND)


def test_only_the_declared_wallet_confirms_itself(court, direct_vm, world_ids):
    for impostor in ("controller", "stranger"):
        as_sender(direct_vm, impostor)
        with direct_vm.expect_revert("only the declared agent wallet can confirm itself"):
            court.confirm_agent_wallet(AGENT)
    as_sender(direct_vm, "agent_wallet")
    assert court.confirm_agent_wallet(AGENT) != ""
