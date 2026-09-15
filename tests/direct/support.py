"""Shared scenario data and mock helpers for the Direct Mode suite.

The suite runs the real contract inside the official genlayer-test direct
runner (SDK resolved from the contract's own pinned runner hash). Only the
external boundaries are mocked, and narrowly:

- web fetches: every file under fixtures/ is served at BASE + its relative
  path, byte for byte; any other GET answers 404, so the contract records
  the item UNAVAILABLE;
- chain reads: a JSON-RPC POST to the StudioNet endpoint is answered from
  TRANSACTIONS, keyed by the transaction hash in the request body, in the
  shape StudioNet returns (probed live: mixed-case addresses, an integer
  value, a digit-string timestamp, and no result key for an unknown hash);
- the one panel prompt, matched on its header, answered with a JSON object.

Nothing in the contract is patched. Every verdict, severity, share and atto
in this suite is produced by the contract's own code from those inputs.
"""

import calendar
import copy
import hashlib
import json
import pathlib
import re
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONTRACT = "contracts/redteam_court.py"
MODULE = "_contract_redteam_court"
FIXTURES = ROOT / "fixtures"

BASE = "https://evidence.example.org/redteam/"
RPC = "https://studio.genlayer.com/api"
NOW = "2026-09-15T12:00:00Z"
PANEL_PATTERN = r"(?s)RedTeam Court panel"
GEN = 10 ** 18
MILLI = 10 ** 15
BOND = 500 * MILLI
POOL = 300 * MILLI
REPORT_BOND = 10 * MILLI
CLAIM = 100 * MILLI

WALLETS = json.loads((FIXTURES / "wallets.json").read_text(encoding="utf-8"))
CATALOGUE = json.loads((FIXTURES / "cases.json").read_text(encoding="utf-8"))
CASES = {c["case_id"]: c for c in CATALOGUE["cases"]}
ENGINE_CASES = [c["case_id"] for c in CATALOGUE["cases"] if c["engine"]]


def world(base: str = BASE) -> dict:
    text = (FIXTURES / "world.json").read_text(encoding="utf-8")
    return json.loads(text.replace("{BASE}", base))


WORLD = world()
AGENT = WORLD["agent_id"]
TOOL = WORLD["tool_id"]
OCCURRED = WORLD["occurred_at"]


def wallet(name: str) -> str:
    return WALLETS[name]


def addr(name: str) -> bytes:
    return bytes.fromhex(WALLETS[name][2:])


def as_sender(direct_vm, name: str):
    direct_vm.sender = addr(name)


def file_bytes(rel: str) -> bytes:
    return (FIXTURES / rel).read_bytes()


def sha256_hex(data) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def item_sha(rel: str) -> str:
    return sha256_hex(file_bytes(rel))


def epoch(iso: str) -> int:
    return calendar.timegm(time.strptime(iso, "%Y-%m-%dT%H:%M:%SZ"))


def checksum_like(address: str) -> str:
    """StudioNet returns mixed-case addresses; any mixed casing proves the
    contract lowercases what it reads."""
    return "0x" + "".join(c.upper() if i % 3 == 0 else c
                          for i, c in enumerate(address[2:]))


# -- policy, profiles, incidents ------------------------------------------------

def policy_definition(base: str = BASE, **overrides) -> dict:
    policy = copy.deepcopy(world(base)["policy"])
    policy.update(overrides)
    return policy


def policy_json(base: str = BASE, **overrides) -> str:
    return json.dumps(policy_definition(base, **overrides))


def profile(key: str, base: str = BASE, **overrides) -> dict:
    data = copy.deepcopy(world(base)["profiles"][key])
    data.update(overrides)
    return data


def incident_definition(entry: dict = None, **overrides) -> dict:
    """An incident as the reporter files it: a catalogue case's, or the honest
    compromise (RC01) by default."""
    entry = entry or CASES["RC01"]
    incident = {
        "kind": entry["kind"], "attack_category": entry["attack_category"],
        "summary": entry["summary"], "alleged_rules": list(entry["alleged_rules"]),
        "implicated_tool_id": TOOL if entry["tool"] else "",
        "claimed_compensation_atto": entry["claimed_compensation_atto"],
        "occurred_at": OCCURRED, "impact_claim": entry["impact_claim"],
        "reproducibility": entry["reproducibility"], "confidentiality_seconds": 0,
    }
    incident.update(overrides)
    return incident


# -- chain transactions ----------------------------------------------------------

def tx_hash(name: str) -> str:
    return "0x" + sha256_hex("redteam-court:" + name)


def studionet_tx(name: str, status: str = "FINALIZED") -> dict:
    spec = WORLD["transactions"][name]
    return {"hash": tx_hash(name), "from_address": checksum_like(wallet(spec["from"])),
            "to_address": checksum_like(wallet(spec["to"])), "value": spec["value_atto"],
            "status": status, "value_credited": True,
            "created_timestamp": str(epoch(spec["at"])), "type": 1}


def default_chain() -> dict:
    return {tx_hash(name): studionet_tx(name) for name in WORLD["transactions"]}


def _response(status: int, body: bytes) -> dict:
    return {"ok": {"response": {"status": status, "headers": {}, "body": body}}}


def rpc_handler(chain: dict):
    """Answers what no mock matched: a StudioNet JSON-RPC POST from `chain`
    (hash -> transaction dict, None for an unknown hash, "DOWN" for an
    endpoint that fails), and 404 for everything else."""
    def handler(data):
        if data.get("method", "GET") != "POST" or not str(data.get("url", "")).startswith(RPC):
            return _response(404, b"not found")
        body = data.get("body")
        if isinstance(body, (bytes, bytearray)):
            body = bytes(body).decode("utf-8")
        request = json.loads(body)
        if request.get("method") != "eth_getTransactionByHash":
            return _response(200, json.dumps({"jsonrpc": "2.0", "id": 1, "error": {
                "code": -32601, "message": "method not found"}}).encode("utf-8"))
        entry = chain.get(request["params"][0])
        if entry == "DOWN":
            return _response(503, b"<html>bad gateway</html>")
        envelope = {"jsonrpc": "2.0", "id": 1}
        if entry is not None:
            envelope["result"] = entry
        return _response(200, json.dumps(envelope).encode("utf-8"))
    return handler


# -- mocks ---------------------------------------------------------------------------

def serve_all(direct_vm, base: str = BASE, skip=(), override=None):
    """Serve every fixture file at base + relative path (exact bytes), with
    `override` replacing some bodies."""
    override = override or {}
    for path in sorted(FIXTURES.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(FIXTURES).as_posix()
        if rel in skip:
            continue
        body = override.get(rel, path.read_bytes())
        direct_vm.mock_web("^" + re.escape(base + rel) + "$", {
            "method": "GET", "response": {"status": 200, "headers": {}, "body": body}})


def mock_panel(direct_vm, answer):
    direct_vm.mock_llm(PANEL_PATTERN, answer if isinstance(answer, str) else json.dumps(answer))


def stage(direct_vm, answer=None, base: str = BASE, skip=(), override=None, chain=None):
    direct_vm.clear_mocks()
    serve_all(direct_vm, base, skip, override)
    direct_vm._live_web_handler = rpc_handler(default_chain() if chain is None else chain)
    if answer is not None:
        mock_panel(direct_vm, answer)


def answer_for(case_id: str) -> dict:
    return copy.deepcopy(CASES[case_id]["panel_answer"])


# -- flows ---------------------------------------------------------------------------

def setup_world(contract, direct_vm, base: str = BASE, fund: bool = True,
                **policy_overrides) -> dict:
    """The controller's policy and agent, the tool, the three reporters, the
    agent wallet's confirmation, and (by default) a funded bond and pool."""
    as_sender(direct_vm, "controller")
    policy_id = contract.register_policy(policy_json(base, **policy_overrides))
    as_sender(direct_vm, "docfetch")
    tool_id = contract.register_tool(json.dumps(profile("tool", base)))
    as_sender(direct_vm, "controller")
    agent_id = contract.register_agent(json.dumps(profile("agent", base)))
    for name in ("harbor", "northwind", "quayside"):
        as_sender(direct_vm, name)
        contract.register_reporter(json.dumps(profile(name, base)))
    as_sender(direct_vm, "agent_wallet")
    contract.confirm_agent_wallet(agent_id)
    if fund:
        as_sender(direct_vm, "controller")
        direct_vm.value = BOND
        contract.post_security_bond(agent_id)
        direct_vm.value = POOL
        contract.fund_bounty_pool(agent_id)
        direct_vm.value = 0
    return {"policy_id": policy_id, "tool_id": tool_id, "agent_id": agent_id}


def open_incident(contract, direct_vm, entry: dict = None, reporter: str = None,
                  bond: int = REPORT_BOND, version: int = 1, **overrides) -> str:
    entry = entry or CASES["RC01"]
    as_sender(direct_vm, reporter or entry["reporter"])
    direct_vm.value = bond
    incident_id = contract.open_incident(AGENT, version,
                                         json.dumps(incident_definition(entry, **overrides)))
    direct_vm.value = 0
    return incident_id


ROLE_WALLET = {"controller": "controller", "tool": "docfetch"}


def submitter_wallet(it: dict, reporter: str) -> str:
    return reporter if it["submitter"] == "reporter" else ROLE_WALLET[it["submitter"]]


def submit_item(contract, direct_vm, incident_id: str, it: dict, reporter: str,
                base: str = BASE, chain_names: dict = None) -> str:
    as_sender(direct_vm, submitter_wallet(it, reporter))
    if it["category"] == "CHAIN_TRANSACTION":
        tx = (chain_names or {}).get(it["chain"], tx_hash(it["chain"]))
        return contract.submit_evidence(incident_id, "CHAIN_TRANSACTION", "", "", it["issuer"],
                                        it["observed_at"], it["trace_reference"],
                                        it["description"], it["access"],
                                        "genlayer-studionet", tx)
    return contract.submit_evidence(incident_id, it["category"], base + it["path"],
                                    item_sha(it["hash_of"] or it["path"]), it["issuer"],
                                    it["observed_at"], it["trace_reference"],
                                    it["description"], it["access"], "", "")


def commit(contract, direct_vm, incident_id: str, items, reporter: str = "harbor",
           base: str = BASE) -> list:
    return [submit_item(contract, direct_vm, incident_id, it, reporter, base) for it in items]


def file_case(contract, direct_vm, case_id: str, **overrides) -> str:
    """Open the case's incident and commit its evidence in catalogue order,
    so evidence E1..En matches the case's panel answer."""
    entry = CASES[case_id]
    incident_id = open_incident(contract, direct_vm, entry, **overrides)
    commit(contract, direct_vm, incident_id, entry["evidence"], entry["reporter"])
    return incident_id


def adjudicate(contract, direct_vm, incident_id: str, answer=None, requester: str = "stranger",
               **stage_kwargs) -> dict:
    stage(direct_vm, answer, **stage_kwargs)
    as_sender(direct_vm, requester)
    adjudication_id = contract.request_adjudication(incident_id)
    return contract.get_adjudication(adjudication_id)


def warp(direct_vm, timestamp: str):
    """Move the transaction clock. genlayer-test 0.29.2's warp() updates the
    VM's datetime but its message refresh copies only sender/origin into the
    SDK's cached gl.message_raw, so a warp after deploy never reaches contract
    code. Set both; this touches the test clock only."""
    direct_vm.warp(timestamp)
    gl = sys.modules.get("genlayer.gl")
    if gl is not None and getattr(gl, "message_raw", None) is not None:
        gl.message_raw["datetime"] = timestamp


def later(seconds: int, start: str = NOW) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch(start) + seconds))


def finding(record: dict, subject_id: str) -> dict:
    for f in record["rules"] + record["indicators"]:
        if f["id"] == subject_id:
            return f
    raise KeyError(subject_id)


def present(record: dict) -> list:
    return [f["id"] for f in record["indicators"] if f["state"] == "PRESENT"]


def receipt(record: dict, evidence_id: str) -> dict:
    for r in record["receipts"]:
        if r["evidence_id"] == evidence_id:
            return r
    raise KeyError(evidence_id)


def claimable(contract, name: str) -> int:
    return int(contract.get_claimable(wallet(name))["claimable_atto"])


def assert_conserved(contract, deposited: int, withdrawn: int = 0):
    """Everything paid in is a bond, a pool, a held report bond or a
    claimable credit, until it is withdrawn."""
    stats = contract.get_stats()
    held = (int(stats["bonds_atto"]) + int(stats["bounty_pools_atto"])
            + int(stats["report_bonds_atto"]) + int(stats["claimable_atto"]))
    assert held == deposited - withdrawn, stats


def captured_payload(direct_vm) -> dict:
    result, _leader_fn, _validator_fn = direct_vm._captured_validators[-1]
    return json.loads(result)


def captured_ctx(direct_vm) -> dict:
    _result, leader_fn, _validator_fn = direct_vm._captured_validators[-1]
    for cell in leader_fn.__closure__ or ():
        value = cell.cell_contents
        if isinstance(value, dict) and "subject_id" in value:
            return value
    raise AssertionError("round context not found")


# -- the adversarial engine --------------------------------------------------------

def bundle_definition(entry: dict, base: str = BASE, chain_names: dict = None) -> dict:
    agent = profile("agent", base)
    tool = profile("tool", base)
    reporter = profile(entry["reporter"], base)
    evidence = []
    for it in entry["evidence"]:
        chain = it["category"] == "CHAIN_TRANSACTION"
        evidence.append({
            "category": it["category"], "url": "" if chain else base + it["path"],
            "sha256": "" if chain else item_sha(it["hash_of"] or it["path"]),
            "issuer": it["issuer"], "description": it["description"],
            "trace_reference": it["trace_reference"], "submitter": it["submitter"],
            "access": it["access"], "observed_at": it["observed_at"],
            "anchor_chain": "genlayer-studionet" if chain else "",
            "anchor_tx": ((chain_names or {}).get(it["chain"], tx_hash(it["chain"]))
                          if chain else "")})
    return {
        "incident_id": "CASE-" + entry["case_id"],
        "agent": {"agent_id": AGENT, "name": agent["name"],
                  "controller_name": agent["controller_name"],
                  "agent_wallet": agent["agent_wallet"],
                  "allowed_tools": agent["allowed_tools"], "origins": agent["origins"]},
        "reporter": {"name": reporter["name"], "origins": reporter["origins"]},
        "tool": {"tool_id": TOOL, "name": tool["name"], "origins": tool["origins"]}
        if entry["tool"] else {},
        "incident": incident_definition(entry),
        "controller_response": entry["controller_response"],
        "tool_response": entry["tool_response"],
        "evidence": evidence,
        "reserved_compensation_atto": entry["reserved_compensation_atto"],
        "reserved_bounty_atto": entry["reserved_bounty_atto"],
    }


def register_case(contract, direct_vm, case_id: str, policy_id: str = "SP-000001",
                  version: int = 1, base: str = BASE) -> str:
    entry = CASES[case_id]
    as_sender(direct_vm, "controller")
    return contract.register_adversarial_case(
        policy_id, version, entry["attack_category"], entry["notes"][:400],
        json.dumps(bundle_definition(entry, base)), entry["expected_verdict"],
        entry["expected_severity_min"], entry["expected_severity_max"])
