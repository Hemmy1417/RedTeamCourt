#!/usr/bin/env python3
"""Inspect a RedTeam Court deployment on StudioNet - read-only, no stored key.

    python scripts/inspect_deployment.py                     # deploy/deployment.json
    python scripts/inspect_deployment.py 0xADDRESS
    python scripts/inspect_deployment.py 0xADDRESS IN-000001

Prints: whether the deployed source is byte-identical to
contracts/redteam_court.py, the method count from the deployed schema,
health_check and get_stats (including every fund and the claimable total),
the configured version and bounds, the demo agent's security standing as of
now, and - for the incident id given, or for every incident filed against the
demo agent - which actions are open on it as of now.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import studionet_transport  # noqa: E402,F401 - retries RPC transport failures
from deploy_studionet import deployed_source, rpc  # noqa: E402
from genlayer_py import create_account, create_client  # noqa: E402
from genlayer_py.chains import studionet  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "redteam_court.py"
RECORD = ROOT / "deploy" / "deployment.json"
AGENT = "AGT-000001"
FIELDS = ("status", "verdict", "severity", "settles", "can_request_adjudication",
          "appeal_window_open", "appeal_pending", "can_finalize", "can_close_stalled",
          "can_report_remediation", "can_request_remediation_review")


def main() -> int:
    args = sys.argv[1:]
    address = args[0] if args else json.loads(RECORD.read_text(encoding="utf-8"))[
        "contract_address"]
    # genlayer-py reads need an account object; an ephemeral one signs nothing
    client = create_client(chain=studionet, account=create_account())

    def read(fn, fn_args):
        return client.read_contract(address=address, function_name=fn, args=fn_args)

    deployed = deployed_source(address)
    local = CONTRACT.read_bytes()
    same = hashlib.sha256(deployed).hexdigest() == hashlib.sha256(local).hexdigest()
    print("contract       ", address)
    print("deployed sha256", hashlib.sha256(deployed).hexdigest())
    print("local sha256   ", hashlib.sha256(local).hexdigest())
    print("byte-identical ", same)
    schema = rpc("gen_getContractSchema", [address]).get("result") or {}
    print("schema methods ", len(schema.get("methods") or {}))
    print("health_check   ", read("health_check", []))
    print("get_stats      ", read("get_stats", []))
    config = read("get_config", [])
    print("version        ", config["contract_version"], " bounds", config["bounds"])

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    status = read("agent_security_status", [AGENT, now])
    if status.get("found"):
        print(f"\n{AGENT} as of {now}")
        for key in ("standing", "policy_version_in_effect", "open_incident_ids",
                    "open_finding_ids", "max_open_severity", "required_remediation",
                    "security_bond_atto", "security_bond_unreserved_atto",
                    "bounty_pool_atto", "wallet_confirmed", "withdrawal_pending"):
            print(f"  {key:<32}{status.get(key)}")

    incident_ids = [args[1]] if len(args) > 1 else \
        (read("list_agent_incidents", [AGENT, 0, 50]).get("items") or [])
    for incident_id in incident_ids:
        view = read("incident_status", [incident_id, now])
        if not view.get("found"):
            print(f"\n{incident_id}: not found")
            continue
        print(f"\n{incident_id}")
        for key in FIELDS:
            print(f"  {key:<32}{view.get(key)}")
    return 0 if same else 1


if __name__ == "__main__":
    sys.exit(main())
