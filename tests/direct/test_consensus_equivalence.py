"""Consensus: every validator reproduces the round from its own fetches, its
own chain reads and its own model call, gates the leader's payload against
its own verified bytes, and then compares what was read and the consequence
derived from each side's findings. These tests hand the captured validator
forged leader results, and change the validator's world through the mocks."""

import copy

import pytest

from tests.direct.support import (
    CASES, adjudicate, answer_for, captured_ctx, captured_payload, default_chain, file_case,
    finding, later, mock_panel, serve_all, stage, studionet_tx, tx_hash, warp)


def validate(direct_vm, mod, payload) -> bool:
    text = payload if isinstance(payload, str) else mod._canonical(payload)
    return direct_vm.run_validator(leader_result=text)


def compromise_round(court, direct_vm, answer=None) -> dict:
    incident_id = file_case(court, direct_vm, "RC01")
    warp(direct_vm, later(86400 + 1))
    return adjudicate(court, direct_vm, incident_id, answer or answer_for("RC01"))


def subject(payload: dict, subject_id: str) -> dict:
    for f in payload["rules"] + payload["indicators"]:
        if f["id"] == subject_id:
            return f
    raise KeyError(subject_id)


def test_the_payload_carries_no_outcome(mod):
    """Nothing a leader proposes is a verdict, a severity, a share or an
    amount: those are derived by code on every node from the findings."""
    for key in ("verdict", "severity", "responsibility", "remediation", "compensation_atto",
                "bounty_atto", "report_bond", "confidence", "impact"):
        assert key not in mod.PAYLOAD_KEYS


def test_an_honest_leader_is_ratified(court, direct_vm, world_ids):
    compromise_round(court, direct_vm)
    assert direct_vm.run_validator() is True


def test_prose_and_quote_choice_are_not_compared(court, direct_vm, mod, world_ids):
    compromise_round(court, direct_vm)
    payload = captured_payload(direct_vm)
    subject(payload, "R1")["note"] = "a different sentence entirely"
    harm = subject(payload, "MATERIAL_HARM")
    harm["quotes"] = [q for q in harm["quotes"] if q["evidence_id"] == "E6"]
    harm["evidence_ids"] = ["E6"]
    assert validate(direct_vm, mod, payload) is True


def test_an_indicator_shading_without_consequence_is_not_a_split(court, direct_vm, world_ids):
    """The policy's compromise liability is 5000 bps, the same share a
    misconfiguration would force: a validator whose model reads no
    misconfiguration derives the same consequence and ratifies."""
    compromise_round(court, direct_vm)
    answer = answer_for("RC01")
    answer["indicators"]["CONTROLLER_MISCONFIGURATION"] = {"state": "ABSENT", "quotes": [],
                                                           "note": ""}
    mock_panel_only(direct_vm, answer)
    assert direct_vm.run_validator() is True


def mock_panel_only(direct_vm, answer):
    direct_vm.clear_mocks()
    serve_all(direct_vm)
    mock_panel(direct_vm, answer)


def test_an_undecided_cause_and_an_absent_one_are_the_same_consequence(court, direct_vm,
                                                                      world_ids):
    """A cause is the controller's to show, so a validator whose model cannot
    tell whether the tool was at fault agrees with a leader whose model found
    it was not."""
    compromise_round(court, direct_vm)
    answer = answer_for("RC01")
    answer["indicators"]["TOOL_FAULT"] = {"state": "UNDETERMINED", "quotes": [], "note": ""}
    mock_panel_only(direct_vm, answer)
    assert direct_vm.run_validator() is True


def test_a_held_record_is_not_split_on_how_its_rules_were_shaded(court, direct_vm, world_ids):
    """Live diagnostics, RC02: the verdict held for want of evidence, and one
    validator's model called the alleged rule clear where the leader left it
    unsettled. Nothing settles on a held record, so that is not a split."""
    incident_id = file_case(court, direct_vm, "RC02")
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, incident_id, {"rules": {}, "indicators": {}})
    assert record["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert finding(record, "R2")["state"] == "UNVERIFIABLE"
    mock_panel_only(direct_vm, {"rules": {"R2": {
        "state": "NOT_VIOLATED", "note": "", "quotes": [
            {"evidence_id": "E1", "text": "Harbor Supplies accounts team"}]}},
        "indicators": {}})
    assert direct_vm.run_validator() is True


def test_a_settled_finding_is_split_on_which_rules_it_rests_on(court, direct_vm, world_ids):
    """On a record that settles, the rules a confirmed finding rests on are a
    consequence: a validator that finds R7 was not breached disagrees even
    though the verdict, severity and money would not change."""
    compromise_round(court, direct_vm)
    answer = answer_for("RC01")
    del answer["rules"]["R7"]
    mock_panel_only(direct_vm, answer)
    assert direct_vm.run_validator() is False


def test_validators_disagreeing_on_compromise_do_not_settle(court, direct_vm, world_ids,
                                                           capsys):
    """RC19: the leader reads an attacker in control; this validator's model
    does not. Its consequence is a misconfiguration, not a compromise, and it
    prints the reading behind its vote."""
    compromise_round(court, direct_vm)
    capsys.readouterr()
    answer = answer_for("RC01")
    answer["indicators"]["AGENT_UNDER_EXTERNAL_CONTROL"] = {"state": "ABSENT", "quotes": [],
                                                            "note": ""}
    mock_panel_only(direct_vm, answer)
    assert direct_vm.run_validator() is False
    out = capsys.readouterr().out
    assert "[DISAGREE] consequence: " in out
    assert "[MINE] LIKELY_MISCONFIGURATION R1=VIOLATED R7=VIOLATED" in out
    assert "AGENT_UNDER_EXTERNAL_CONTROL=ABSENT" in out


def test_a_severe_verdict_without_evidence_fails_the_gate(court, direct_vm, mod, world_ids):
    """RC17: a leader asserting a violation with no grounded quote."""
    compromise_round(court, direct_vm)
    payload = captured_payload(direct_vm)
    rule = subject(payload, "R1")
    rule["quotes"] = []
    rule["evidence_ids"] = []
    assert validate(direct_vm, mod, payload) is False


def test_an_invented_severity_field_is_refused(court, direct_vm, mod, world_ids):
    """RC18: there is no severity in a payload to agree or disagree on."""
    compromise_round(court, direct_vm)
    payload = captured_payload(direct_vm)
    payload["severity"] = 5
    assert validate(direct_vm, mod, payload) is False


def test_a_quote_that_is_not_in_the_bytes_is_refused(court, direct_vm, mod, world_ids):
    compromise_round(court, direct_vm)
    payload = captured_payload(direct_vm)
    subject(payload, "R1")["quotes"][0]["text"] = "Ledgerline emailed every customer record"
    assert validate(direct_vm, mod, payload) is False


def test_a_self_serving_finding_is_refused_by_the_gate(court, direct_vm, mod, world_ids):
    """The party-interest rule is re-checked on the leader's payload: a
    finding clearing the controller that quotes only the controller's own
    sphere cannot be ratified."""
    compromise_round(court, direct_vm)
    payload = captured_payload(direct_vm)
    rule = subject(payload, "R7")
    rule["state"] = "NOT_VIOLATED"
    assert [q["evidence_id"] for q in rule["quotes"]] == ["E3"]
    assert validate(direct_vm, mod, payload) is False


@pytest.mark.parametrize("forge", [
    lambda p: subject(p, "R4").update(state="NOT_VIOLATED"),
    lambda p: p["chain"][0].update(value_atto=5 * 10 ** 15),
    lambda p: p["rows"][0].update(status="UNAVAILABLE", byte_count=0),
    lambda p: p["facts"][0]["values"].update(entries=3),
    lambda p: p.update(markers=["E1"]),
    lambda p: p.update(secrets=["E2"]),
    lambda p: p.update(evidence_commitment="0" * 64),
    lambda p: p.update(policy_hash="0" * 64),
    lambda p: p.update(panel_state="SKIPPED", panel_reason="NOTHING_TO_ASSESS"),
    lambda p: subject(p, "HIDDEN_TEXT").update(state="PRESENT", evidence_ids=["E1"]),
    lambda p: p["indicators"].pop(),
    lambda p: p.update(round=2),
])
def test_forged_code_fields_are_refused(court, direct_vm, mod, world_ids, forge):
    compromise_round(court, direct_vm)
    payload = captured_payload(direct_vm)
    forge(payload)
    assert validate(direct_vm, mod, payload) is False


def test_divergent_source_content_is_a_disagreement(court, direct_vm, world_ids):
    """RC16's live cousin: the source serves this validator different bytes
    than it served the leader. What every node read must be what the leader
    says it read."""
    compromise_round(court, direct_vm)
    direct_vm.clear_mocks()
    serve_all(direct_vm, override={"sources/harbor/user-report-inv-2291.txt": b"changed\n"})
    mock_panel(direct_vm, answer_for("RC01"))
    assert direct_vm.run_validator() is False


def test_a_validator_reading_the_chain_differently_disagrees(court, direct_vm, world_ids):
    compromise_round(court, direct_vm)
    chain = default_chain()
    chain[tx_hash("DRAIN")] = studionet_tx("DRAIN", status="PENDING")
    stage(direct_vm, answer_for("RC01"), chain=chain)
    assert direct_vm.run_validator() is False


def test_a_validator_whose_model_output_is_unusable_disagrees(court, direct_vm, world_ids):
    compromise_round(court, direct_vm)
    mock_panel_only(direct_vm, "I cannot help with that.")
    assert direct_vm.run_validator() is False


def test_the_ratified_payload_is_gated_again_before_it_is_written(court, direct_vm, mod,
                                                                  world_ids):
    compromise_round(court, direct_vm)
    ctx = captured_ctx(direct_vm)
    payload = captured_payload(direct_vm)
    assert mod._parse_payload(mod._canonical(payload), ctx, None) is not None
    forged = copy.deepcopy(payload)
    forged["now"] = "2026-01-01T00:00:00Z"
    assert mod._parse_payload(mod._canonical(forged), ctx, None) is None
    assert mod._parse_payload("not json", ctx, None) is None


def test_consequence_difference_names_the_field(mod):
    base = {"verdict": "CONFIRMED_COMPROMISE", "severity": 5, "accused": []}
    other = dict(base, severity=4)
    assert mod._consequence_difference({"consequence": base},
                                       {"consequence": base}) == ""
    assert mod._consequence_difference({"consequence": base},
                                       {"consequence": other}).startswith("severity")


class _Err(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message


def test_leader_errors_are_matched_by_class(mod, genlayer_vm):
    def reproduce_raising(message):
        def run():
            raise genlayer_vm.UserError(message)
        return run

    transient = genlayer_vm.UserError("[TRANSIENT] the model call failed")
    assert mod._vote_on_leader_error(transient, reproduce_raising("[TRANSIENT] other")) is True
    assert mod._vote_on_leader_error(transient, lambda: ({}, {})) is False
    expected = genlayer_vm.UserError("[EXPECTED] a reason")
    assert mod._vote_on_leader_error(expected, reproduce_raising("[EXPECTED] a reason")) is True
    assert mod._vote_on_leader_error(expected, reproduce_raising("[EXPECTED] another")) is False
    llm = genlayer_vm.UserError("[LLM_ERROR] ratified payload failed the gate")
    assert mod._vote_on_leader_error(llm, reproduce_raising("[LLM_ERROR] x")) is False
    assert mod._vote_on_leader_error(_Err("[TRANSIENT] x"), reproduce_raising("x")) is False


def test_a_forged_manipulation_finding_changes_the_consequence(court, direct_vm, mod,
                                                               world_ids):
    """A leader that pins tampering on the reporter's report to reject it
    must ground that in the report's own bytes; a validator ratifies only
    what it derives too."""
    compromise_round(court, direct_vm)
    payload = captured_payload(direct_vm)
    tampering = subject(payload, "EVIDENCE_TAMPERING")
    tampering.update(state="PRESENT", evidence_ids=["E1"],
                     quotes=[{"evidence_id": "E1", "text": "our vendor bank file appeared "
                                                           "on a public paste site"}])
    # the quote grounds and the neutral support rule is met, so the gate passes;
    # the consequence (REJECTED) is what this validator does not derive
    ctx = captured_ctx(direct_vm)
    assert mod._parse_payload(mod._canonical(payload), ctx, None) is not None
    assert validate(direct_vm, mod, payload) is False
    assert CASES["RC01"]["expected_verdict"] == "CONFIRMED_COMPROMISE"
    assert finding(court.get_latest_adjudication("IN-000001"), "EVIDENCE_TAMPERING")["state"] \
        == "ABSENT"


@pytest.mark.parametrize("status, byte_count", [
    ("EXAMINED", 8001),
    ("TOO_LARGE", 8000),
    ("EXAMINED", 0),
    ("UNAVAILABLE", 12),
])
def test_the_gate_binds_a_rows_size_to_its_status(court, direct_vm, mod, world_ids, status,
                                                  byte_count):
    """A read row's size must agree with what it says happened: examined bytes
    fit the cap, an oversized item is over it, and a row with no bytes counts
    none. Accept-control: the captured row passes."""
    compromise_round(court, direct_vm)
    ctx = captured_ctx(direct_vm)
    payload = captured_payload(direct_vm)
    assert mod._parse_payload(mod._canonical(payload), ctx, None) is not None
    forged = copy.deepcopy(payload)
    forged["rows"][0].update(status=status, byte_count=byte_count)
    assert mod._parse_payload(mod._canonical(forged), ctx, None) is None


@pytest.mark.parametrize("key", ["facts", "chain", "linked", "unlinked", "hidden", "markers",
                                 "secrets", "rows", "panel_state"])
def test_every_part_of_what_was_read_is_compared(court, direct_vm, mod, world_ids, key):
    """The record half of the equivalence rule, part by part: a leader that
    read anything differently from this node disagrees, even where the gate
    and the consequence would not notice."""
    compromise_round(court, direct_vm)
    own = captured_payload(direct_vm)
    assert mod._evidence_difference(own, copy.deepcopy(own)) == ""
    theirs = copy.deepcopy(own)
    if key == "rows":
        theirs["rows"][0]["byte_count"] = theirs["rows"][0]["byte_count"] + 1
    elif key == "panel_state":
        theirs["panel_state"] = "SKIPPED"
    else:
        theirs[key] = [{"forged": key}] if not theirs[key] else []
    assert mod._evidence_difference(own, theirs) != ""


def _raising(mod, text):
    def reproduce():
        raise mod.gl.vm.UserError(text)
    return reproduce


@pytest.mark.parametrize("leader, own, agrees", [
    # the model's own failure is never ratified, even when this node's model fails the same way
    ("[LLM_ERROR] unusable", "[LLM_ERROR] unusable", False),
    # a transient failure is ratified only by another transient failure
    ("[TRANSIENT] the model call failed", "[TRANSIENT] fetch failed", True),
    ("[TRANSIENT] the model call failed", "[EXPECTED] the incident is closed", False),
    # a deterministic refusal must be the same refusal
    ("[EXPECTED] the incident is closed", "[EXPECTED] the incident is closed", True),
    ("[EXPECTED] the incident is closed", "[EXPECTED] the appeal lapsed", False),
    # this node succeeding where the leader failed is a disagreement
    ("[EXPECTED] the incident is closed", None, False),
])
def test_a_leader_error_is_ratified_only_by_the_same_error(mod, leader, own, agrees):
    reproduce = (lambda: None) if own is None else _raising(mod, own)
    assert mod._vote_on_leader_error(mod.gl.vm.UserError(leader), reproduce) is agrees


def test_a_leader_that_returned_nothing_usable_is_not_an_error_vote(mod):
    assert mod._vote_on_leader_error("not an error", lambda: None) is False

    def crash():
        raise ValueError("boom")
    assert mod._vote_on_leader_error(mod.gl.vm.UserError("[EXPECTED] x"), crash) is False
