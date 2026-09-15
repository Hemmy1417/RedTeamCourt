#!/usr/bin/env python3
"""Disposable diagnostic deployment: do StudioNet's validators - several model
families - agree on the catalogue's cases? Not canonical: the results inform
calibration only and are kept under deploy/diagnostics/.

  python scripts/diagnostic_rounds.py <raw-base> [CASE,CASE,...] [--chain FILE]

A case is a catalogue id, or A1 / A2: the live run's phase A first round and
readjudication, rehearsed as engine cases.

Deploys the working-tree contract from a fresh throwaway account, registers
the demo policy against <raw-base>, makes the chain transfers the cases cite
from the demo wallets (keys in .data/demo_wallets.json, gitignored, funded
from the faucet; --chain reuses transfers an earlier run recorded), and runs
each case through the adversarial engine. For every round it records each
node's model, vote and the tail of its stdout - the contract prints
[DISAGREE], [DOWNGRADE] and [MODEL_OUTPUT_INVALID] lines there, so a split
names its own cause.
"""

import importlib.util
import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import studionet_transport  # noqa: E402,F401
from chain_transfer import fund, send_gen  # noqa: E402
from genlayer_py import create_account, create_client  # noqa: E402
from genlayer_py.chains import studionet  # noqa: E402
from genlayer_py.types import TransactionStatus  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
RAW = ARGS[0] if ARGS else ""
CHAIN_FILE = sys.argv[sys.argv.index("--chain") + 1] if "--chain" in sys.argv else ""
if CHAIN_FILE in ARGS:
    ARGS.remove(CHAIN_FILE)
STAMP = time.strftime("%Y%m%dT%H%M%S")
OUT = ROOT / "deploy" / "diagnostics" / ("run_" + STAMP + ".json")

spec = importlib.util.spec_from_file_location("support", ROOT / "tests/direct/support.py")
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)
CASE_IDS = ARGS[1].split(",") if len(ARGS) > 1 else [
    c for c in support.ENGINE_CASES if c not in ("RC05", "RC26")]
GEN = 10 ** 18


def _rehearsal(case_id: str, evidence: list, verdict: str, low: int, high: int,
               notes: str) -> dict:
    entry = dict(support.CASES["RC01"], case_id=case_id, evidence=evidence,
                 expected_verdict=verdict, expected_severity_min=low,
                 expected_severity_max=high, notes=notes)
    entry["controller_response"] = "Meridian Labs is investigating session ses-4471."
    entry["tool_response"] = "Docfetch executed the requests the ledgerline-prod token made."
    return entry


# The live run's phase A rounds, rehearsed as engine cases before a canonical
# deployment: the first round rests on Harbor's report and the captured invoice,
# the readjudication adds the chain record of the payment.
_RC01 = support.CASES["RC01"]["evidence"]
REHEARSALS = {
    "A1": _rehearsal("A1", _RC01[:2], "INCONCLUSIVE", 0, 0,
                     "phase A's first round: the reporter's own two items"),
    "A2": _rehearsal("A2", _RC01[:2] + [_RC01[5]], "CONFIRMED_COMPROMISE", 5, 5,
                     "phase A's readjudication: the report, the invoice and the payment"),
}

deployer = create_account()
client = create_client(chain=studionet, account=deployer)
out = {"raw_base": RAW, "cases": CASE_IDS, "rounds": []}


def wait(tx):
    return client.wait_for_transaction_receipt(transaction_hash=tx,
                                               status=TransactionStatus.FINALIZED,
                                               interval=5000, retries=360)


def leader(r):
    lr = r["consensus_data"]["leader_receipt"]
    return str((lr[0] if isinstance(lr, list) else lr)["execution_result"])


def save():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=1), encoding="utf-8", newline="\n")


def transfers() -> dict:
    """The chain transactions the cases cite, made from the demo wallets."""
    if CHAIN_FILE:
        return json.loads(pathlib.Path(CHAIN_FILE).read_text(encoding="utf-8"))
    from genlayer_py import create_account as account_from_key
    keys = json.loads((ROOT / ".data" / "demo_wallets.json").read_text(encoding="utf-8"))
    names = {}
    for name, spec_ in support.WORLD["transactions"].items():
        sender = account_from_key(keys[spec_["from"]]["private_key"])
        payer = create_client(chain=studionet, account=sender)
        if payer.get_balance(sender.address) < spec_["value_atto"] * 3:
            fund(payer, sender.address, GEN // 10)
        tx = send_gen(payer, sender, support.wallet(spec_["to"]), spec_["value_atto"])
        payer.wait_for_transaction_receipt(transaction_hash=tx,
                                           status=TransactionStatus.FINALIZED,
                                           interval=5000, retries=120)
        names[name] = tx
        print("transfer", name, tx, flush=True)
    path = ROOT / "deploy" / "diagnostics" / ("chain_" + STAMP + ".json")
    path.write_text(json.dumps(names, indent=1) + "\n", encoding="utf-8", newline="\n")
    return names


chain_names = transfers()
out["chain"] = chain_names
r = wait(client.deploy_contract(code=(ROOT / "contracts/redteam_court.py").read_text(
    encoding="utf-8"), args=[], consensus_max_rotations=3))
addr = r["data"]["contract_address"]
out["address"] = addr
print("deployed", addr, leader(r), flush=True)
save()


def W(fn, args):
    return wait(client.write_contract(address=addr, function_name=fn, args=args,
                                      consensus_max_rotations=3))


def R(fn, args):
    return client.read_contract(address=addr, function_name=fn, args=args)


print("policy", leader(W("register_policy", [json.dumps(support.policy_definition(RAW))])),
      flush=True)
for cid in CASE_IDS:
    entry = REHEARSALS.get(cid) or support.CASES[cid]
    bundle = support.bundle_definition(entry, RAW, chain_names)
    registered = W("register_adversarial_case", [
        "SP-000001", 1, entry["attack_category"], entry["notes"][:400], json.dumps(bundle),
        entry["expected_verdict"], entry["expected_severity_min"],
        entry["expected_severity_max"]])
    if leader(registered) != "SUCCESS":
        out["rounds"].append({"case": cid, "registration": leader(registered)})
        save()
        print(cid, "registration", leader(registered), flush=True)
        continue
    case_id = R("list_adversarial_cases", ["SP-000001", 1, 0, 50])["items"][-1]
    t0 = time.time()
    r = W("run_adversarial_case", [case_id])
    cd = r["consensus_data"]
    nodes = []
    for n in [cd["leader_receipt"][0]] + cd.get("validators", []):
        nc = n["node_config"]
        nodes.append({"mode": n["mode"],
                      "model": (nc.get("primary_model") or {}).get("model"),
                      "vote": cd["votes"].get(nc["address"]),
                      "stdout": ((n.get("genvm_result") or {}).get("stdout") or "")[-900:]})
    view = R("get_adversarial_case", [case_id])
    rec = R("get_adjudication", [view["receipt_id"]]) if view["receipt_id"] else {}
    row = {"case": cid, "status": r.get("status_name"), "leader": leader(r),
           "seconds": round(time.time() - t0), "expected": entry["expected_verdict"],
           "observed": view["observed_verdict"], "severity": view["observed_severity"],
           "passed": view["passed"],
           "panel": [(f["id"], f["state"]) for f in rec.get("rules", []) + rec.get(
               "indicators", []) if f.get("by") == "PANEL"],
           "reason_codes": rec.get("reason_codes", []), "nodes": nodes}
    out["rounds"].append(row)
    save()
    print(cid, row["status"], row["observed"], row["severity"], row["passed"],
          row["seconds"], "s",
          [(n["model"], n["vote"], n["stdout"].strip()[-200:]) for n in nodes], flush=True)
print("DONE", OUT.relative_to(ROOT), flush=True)
