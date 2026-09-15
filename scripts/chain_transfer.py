#!/usr/bin/env python3
"""A plain GEN transfer from one wallet to another on StudioNet, and a probe of
what the chain records for it.

A transfer is a signed transaction addressed to the recipient wallet itself,
with no calldata and the value on the envelope; contract calls, by contrast,
go to the consensus contract's addTransaction. The live run uses it to make the agent wallet's
payments that incidents cite as CHAIN_TRANSACTION evidence.

  python scripts/chain_transfer.py --probe   # fund two throwaway wallets,
                                             # transfer, record what the chain says

The probe exists because the contract reads a transaction's value only when
StudioNet marks it credited: the recorded fields - status, type, value,
value_credited, addresses, timestamp - are what that reading is checked
against, and they are written to deploy/diagnostics/transfer_probe.json.
"""

from __future__ import annotations

import json
import pathlib
import sys
import time
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import studionet_transport  # noqa: E402,F401 - retries RPC transport failures
from genlayer_py import create_account, create_client  # noqa: E402
from genlayer_py.chains import studionet  # noqa: E402
from genlayer_py.contracts.actions import _prepare_transaction  # noqa: E402
from genlayer_py.types import TransactionStatus  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
RPC = "https://studio.genlayer.com/api"
GEN = 10 ** 18


def rpc(method: str, params: list):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    last = None
    for attempt in range(6):
        try:
            request = urllib.request.Request(RPC, data=body, headers={
                "Content-Type": "application/json", "User-Agent": "redteam-court-probe"})
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read().decode())
        except Exception as err:          # noqa: BLE001 - transport errors vary
            last = err
            time.sleep(10 * (attempt + 1))
    raise last


def send_gen(client, account, to_address: str, value_atto: int) -> str:
    """Submit a transfer and return its transaction hash: a signed
    transaction addressed to the recipient itself, with no calldata."""
    transaction = _prepare_transaction(self=client, sender=account.address,
                                       recipient=client.w3.to_checksum_address(to_address),
                                       data="0x", value=value_atto)
    signed = account.sign_transaction(transaction)
    answer = client.provider.make_request("eth_sendRawTransaction",
                                          [client.w3.to_hex(signed.raw_transaction)])
    return answer["result"]


def chain_record(tx_hash: str) -> dict:
    result = rpc("eth_getTransactionByHash", [tx_hash]).get("result") or {}
    keys = ("hash", "type", "status", "from_address", "to_address", "value",
            "value_credited", "created_timestamp", "result_name")
    return {k: result.get(k) for k in keys}


def fund(client, address: str, amount: int):
    before = client.get_balance(address)
    client.fund_account(address, amount)
    for _ in range(40):
        if client.get_balance(address) > before:
            return
        time.sleep(3)
    raise SystemExit("the faucet did not fund " + address)


def probe() -> None:
    sender = create_account()
    recipient = create_account()
    client = create_client(chain=studionet, account=sender)
    fund(client, sender.address, GEN // 10)
    before = client.get_balance(recipient.address)
    tx = send_gen(client, sender, recipient.address, GEN // 100)
    print("transfer tx:", tx, flush=True)
    receipt = client.wait_for_transaction_receipt(transaction_hash=tx,
                                                  status=TransactionStatus.FINALIZED,
                                                  interval=5000, retries=120)
    time.sleep(5)
    after = client.get_balance(recipient.address)
    record = {
        "probed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sender": sender.address.lower(), "recipient": recipient.address.lower(),
        "value_atto": GEN // 100, "tx": tx,
        "receipt_status": receipt.get("status_name") or receipt.get("status"),
        "chain_record": chain_record(tx),
        "recipient_balance_before": str(before), "recipient_balance_after": str(after),
    }
    out = ROOT / "deploy" / "diagnostics" / "transfer_probe.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    if "--probe" in sys.argv:
        probe()
    else:
        print(__doc__)
