"""Secrets and confidentiality: credentials and personal data never enter the
contract through a party's words, evidence carrying one is excluded and its
text withheld, confidential evidence is never republished in a record or a
view, and a disclosure's text waits out its embargo.

Secret-looking test strings are assembled at run time from parts, so no
scanner mistakes this repository for a leak."""

import json

import pytest

from tests.direct.support import (
    BASE, CASES, adjudicate, answer_for, as_sender, commit, file_case, finding, later,
    open_incident, receipt, warp)

SECRETS = {
    "PRIVATE_KEY_BLOCK": "-----BEGIN " + "RSA PRIVATE KEY-----",
    "WALLET_PRIVATE_KEY": "private_key: 0x" + "ab" * 32,
    "SEED_PHRASE": "seed phrase: " + " ".join(["orbit"] * 12),
    "AWS_ACCESS_KEY": "AKIA" + "IOSFODNN7" + "EXAMPLE",
    "GITHUB_TOKEN": "gh" + "p_" + "a1B2" * 9,
    "SLACK_TOKEN": "xo" + "xb-" + "1234567890-abcdef",
    "STRIPE_SECRET": "sk_" + "live_" + "Zx9" * 8,
    "BEARER_TOKEN": "Authorization: " + "Bearer " + "tok" * 8,
    "JSON_WEB_TOKEN": "eyJ" + "hbGciOiJIUzI1" + ".eyJ" + "zdWIiOiIxMjM0" + "." + "SflKxwRJSMeK",
    "SESSION_COOKIE": "Cookie: " + "sessionid=" + "a7" * 10,
    "PASSWORD_ASSIGNMENT": "pass" + "word: " + "hunter2hunter2",
    "US_SSN": "123-" + "45-" + "6789",
    "PAYMENT_CARD": "4111 " + "1111 " + "1111 " + "1111",
}


@pytest.mark.parametrize("kind", sorted(SECRETS))
def test_each_secret_kind_is_recognised(mod, kind):
    assert kind in mod._secret_kinds("our records: " + SECRETS[kind])


@pytest.mark.parametrize("text", [
    "tx 0x" + "ab" * 32,
    "sha256 " + "cd" * 32,
    "invoice INV-2291 paid 2026-09-10 at 09:38 UTC",
    "the ledgerline-prod token scope allowed write",
    "card ending 1111",
    "4111 1111 1111 1112",
])
def test_ordinary_security_text_is_not_mistaken_for_a_secret(mod, text):
    assert mod._secret_kinds(text) == []


@pytest.mark.parametrize("kind", ["AWS_ACCESS_KEY", "PASSWORD_ASSIGNMENT", "PAYMENT_CARD",
                                  "WALLET_PRIVATE_KEY", "US_SSN"])
def test_party_writes_refuse_credentials(court, direct_vm, world_ids, kind):
    secret = SECRETS[kind]
    with direct_vm.expect_revert("looks like a credential or personal data (" + kind):
        open_incident(court, direct_vm, bond=0, summary="Evidence attached. " + secret)
    incident_id = open_incident(court, direct_vm)
    as_sender(direct_vm, "controller")
    with direct_vm.expect_revert("looks like a credential"):
        court.submit_counterreport(incident_id, "Use " + secret)
    as_sender(direct_vm, "harbor")
    with direct_vm.expect_revert("looks like a credential"):
        court.submit_evidence(incident_id, "USER_REPORT",
                              BASE + "sources/harbor/user-report-inv-2291.txt", "a" * 64,
                              "Harbor Supplies", "2026-09-11T08:00:00Z", "", "login " + secret,
                              "PUBLIC", "", "")


def test_evidence_carrying_a_secret_is_excluded_withheld_and_rotation_required(
        court, direct_vm, world_ids, mod):
    """RC30 as a filed incident: the password never reaches the panel or the
    record, and the record requires the credential rotated."""
    incident_id = file_case(court, direct_vm, "RC30")
    warp(direct_vm, later(86400 + 1))
    record = adjudicate(court, direct_vm, incident_id, answer_for("RC30"))
    assert finding(record, "SECRET_EXPOSURE")["evidence_ids"] == ["E1"]
    assert record["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert record["required_remediation"] == ["ROTATE_CREDENTIALS"]
    assert record["impact_classification"] == ["CREDENTIAL_EXPOSURE"]
    assert receipt(record, "E1")["authenticity_status"] == "EXCLUDED:SECRET_EXPOSURE"
    stored = json.dumps(record)
    assert "correct-horse-battery-staple" not in stored
    assert mod.EXCLUDED_TEXT not in stored


def test_a_secret_never_grounds_a_quote(mod):
    text = "Harbor login password: correct-horse-battery-staple-7 for the portal"
    texts = {"E1": text}
    assert mod._ground_quote("password: correct-horse-battery-staple-7", "E1", ["E1"],
                             texts) is None
    assert mod._ground_quote("Harbor login", "E1", ["E1"], texts) == {
        "evidence_id": "E1", "text": "Harbor login"}


def test_a_note_carrying_a_secret_is_dropped(mod):
    assert mod._clean_note("the file shows " + SECRETS["GITHUB_TOKEN"]) == ""
    assert mod._clean_note("  a  plain\nnote ") == "a plain note"
    assert mod._clean_note(mod._clean_note("x " * 150)) == mod._clean_note("x " * 150)


def test_confidential_evidence_is_not_republished(court, direct_vm, world_ids):
    entry = CASES["RC01"]
    incident_id = open_incident(court, direct_vm)
    confidential = dict(entry["evidence"][0], access="CONFIDENTIAL")
    ids = commit(court, direct_vm, incident_id, [confidential] + entry["evidence"][1:])
    view = court.get_evidence(ids[0])
    assert view["source_locator"] == "(confidential)"
    assert view["description"] == "(confidential)"
    assert view["access_constraints"] == "CONFIDENTIAL"
    warp(direct_vm, later(86400 + 1))
    answer = answer_for("RC01")
    answer["indicators"]["MATERIAL_HARM"] = {
        "state": "PRESENT", "note": "Harbor's bank file was posted publicly",
        "quotes": [{"evidence_id": "E1", "text": "our vendor bank file appeared on a public "
                                                  "paste site"},
                   {"evidence_id": "E6", "text": "the agent's declared wallet"}]}
    record = adjudicate(court, direct_vm, incident_id, answer)
    harm = finding(record, "MATERIAL_HARM")
    assert harm["quotes"][0]["text"].startswith("[confidential quote withheld; sha256 ")
    assert harm["quotes"][1]["text"] == "the agent's declared wallet"
    assert harm["note"] == "[note withheld: it cites confidential evidence]"
    r = receipt(record, "E1")
    assert r["source_locator"] == "(confidential)"
    assert r["summary"] == "(confidential: summary withheld)"
    assert "public paste site" not in json.dumps(record)
    assert record["verdict"] == "CONFIRMED_COMPROMISE"


def test_a_disclosure_waits_out_its_embargo(court, direct_vm, world_ids):
    entry = CASES["RC32"]
    incident_id = open_incident(court, direct_vm, entry, confidentiality_seconds=3 * 86400)
    view = court.get_incident(incident_id)
    assert view["embargo_lifted"] is False and view["embargo_until"] == later(3 * 86400)
    for key in ("incident_summary", "impact_claim", "reproducibility"):
        assert view[key] == "(withheld until the disclosure embargo is lifted)"
    with direct_vm.expect_revert("the embargo runs until"):
        court.lift_disclosure_embargo(incident_id)
    assert court.incident_status(incident_id, later(3600))["embargo_liftable"] is False
    warp(direct_vm, later(3 * 86400))
    as_sender(direct_vm, "stranger")
    court.lift_disclosure_embargo(incident_id)
    view = court.get_incident(incident_id)
    assert view["embargo_lifted"] is True
    assert view["incident_summary"] == entry["summary"]
    with direct_vm.expect_revert("carries no embargo"):
        court.lift_disclosure_embargo(incident_id)


def test_an_incident_has_no_embargo(court, direct_vm, world_ids):
    incident_id = open_incident(court, direct_vm)
    view = court.get_incident(incident_id)
    assert view["embargo_lifted"] is True and view["embargo_until"] == ""
    with direct_vm.expect_revert("carries no embargo"):
        court.lift_disclosure_embargo(incident_id)
