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


def test_validators_disagreeing_on_compromise_do_not_settle(court, direct_vm, world_ids):
    """RC19: the leader reads an attacker in control; this validator's model
    does not. Its consequence is a misconfiguration, not a compromise."""
    compromise_round(court, direct_vm)
    answer = answer_for("RC01")
    answer["indicators"]["AGENT_UNDER_EXTERNAL_CONTROL"] = {"state": "ABSENT", "quotes": [],
                                                            "note": ""}
    mock_panel_only(direct_vm, answer)
    assert direct_vm.run_validator() is False


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
