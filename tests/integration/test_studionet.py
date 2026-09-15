"""StudioNet integration: the canonical deployment in deploy/deployment.json,
checked over the network.

    python -m pytest tests/integration -v
    REDTEAM_LIVE_WRITES=1 python -m pytest tests/integration -v

Read-only by default: the deployed source is byte-identical to
contracts/redteam_court.py, the deployed schema exposes every public method in
that file, the views answer, the contract's balance is exactly what it says it
holds, and what the live run recorded reads back. With REDTEAM_LIVE_WRITES=1 one
write goes through real consensus: a fresh wallet registers as a reporter
(StudioNet is gasless).

genlayer-py is used directly: gltest's ContractFactory cannot bind a hosted
contract from its schema on this SDK generation.
"""

import base64
import hashlib
import json
import os
import pathlib
import re
import sys
import time
import urllib.request

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONTRACT = ROOT / "contracts" / "redteam_court.py"
RECORD = ROOT / "deploy" / "deployment.json"
TRANSCRIPT = ROOT / "deploy" / "live_scenarios_transcript.json"
RPC = "https://studio.genlayer.com/api"

pytestmark = pytest.mark.skipif(not RECORD.exists(), reason="no deployment recorded")
sys.path.insert(0, str(ROOT / "scripts"))


def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                       "params": params}).encode()
    last = None
    for attempt in range(6):
        try:
            request = urllib.request.Request(RPC, data=body, headers={
                "Content-Type": "application/json", "User-Agent": "redteam-court-integration"})
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read().decode())
        except Exception as err:          # noqa: BLE001 - transport errors vary
            last = err
            time.sleep(10 * (attempt + 1))
    raise last


@pytest.fixture(scope="module")
def deployment():
    return json.loads(RECORD.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def client():
    import studionet_transport  # noqa: F401
    from genlayer_py import create_account, create_client
    from genlayer_py.chains import studionet
    return create_client(chain=studionet, account=create_account())


@pytest.fixture(scope="module")
def read(deployment, client):
    return lambda fn, args: client.read_contract(
        address=deployment["contract_address"], function_name=fn, args=args)


@pytest.fixture(scope="module")
def transcript(deployment):
    if not TRANSCRIPT.exists():
        pytest.skip("no live run recorded")
    data = json.loads(TRANSCRIPT.read_text(encoding="utf-8"))
    if data.get("address") != deployment["contract_address"]:
        pytest.skip("the transcript belongs to another deployment")
    return data


def test_deployed_source_is_the_committed_file(deployment):
    result = rpc("gen_getContractCode", [deployment["contract_address"]])["result"]
    deployed = result.encode() if result.lstrip().startswith("#") else base64.b64decode(result)
    local = CONTRACT.read_bytes()
    assert hashlib.sha256(deployed).hexdigest() == hashlib.sha256(local).hexdigest() \
        == deployment["source_sha256"]


def test_deployed_schema_exposes_every_public_method(deployment):
    schema = rpc("gen_getContractSchema", [deployment["contract_address"]])["result"]
    methods = set(schema["methods"])
    declared = re.findall(r"@gl\.public\.(?:view|write(?:\.payable)?)\n    def (\w+)\(",
                          CONTRACT.read_text(encoding="utf-8"))
    assert len(declared) == 45
    assert set(declared) <= methods, sorted(set(declared) - methods)


def test_views_answer(read):
    assert read("health_check", [])["ok"] is True
    config = read("get_config", [])
    assert config["contract_version"] == "0.1.0"
    assert len(config["verdicts"]) == 13 and len(config["attack_categories"]) == 32
    assert read("get_incident", ["IN-999999"])["found"] is False
    assert read("agent_security_status", ["AGT-999999", "2026-09-15T00:00:00Z"])["found"] \
        is False


def test_the_balance_is_exactly_what_the_contract_holds(deployment, client, read):
    """Every atto the contract holds is a security bond, a bounty pool, a held
    report bond or a claimable credit: the four totals are its whole
    liability, and its native balance must be exactly their sum."""
    stats = read("get_stats", [])
    held = sum(int(stats[k]) for k in ("bonds_atto", "bounty_pools_atto",
                                       "report_bonds_atto", "claimable_atto"))
    assert int(read("health_check", [])["held_atto"]) == held
    assert client.get_balance(deployment["contract_address"]) == held


def test_the_readjudicated_incident_reads_back(read, transcript):
    recorded = transcript["A"]["readjudication"]["observed"]
    record = read("get_adjudication", [recorded["adjudication_id"]])
    assert record["verdict"] == recorded["verdict"]
    assert record["severity"] == recorded["severity"]
    assert record["record_digest"] == recorded["record_digest"]
    assert record["compensation_or_bounty_recommendation"] == \
        recorded["compensation_or_bounty_recommendation"]
    first = read("get_adjudication", [transcript["A"]["first_round"]["observed"]
                                      ["adjudication_id"]])
    assert first["record_digest"] == transcript["A"]["first_digest"]


def test_the_engine_cases_read_back(read, transcript):
    cases = transcript["B"]["cases"]
    assert cases
    for case_id, row in cases.items():
        view = read("get_adversarial_case", [row["onchain_id"]])
        assert view["passed"] == row["passed"], case_id
        if row["observed"] is not None:
            assert view["observed_verdict"] == row["observed"]["verdict"], case_id


@pytest.mark.skipif(os.environ.get("REDTEAM_LIVE_WRITES") != "1",
                    reason="writes to the canonical deployment are opt-in")
def test_a_write_through_consensus(deployment):
    import studionet_transport  # noqa: F401
    from genlayer_py import create_account, create_client
    from genlayer_py.chains import studionet
    from genlayer_py.types import TransactionStatus
    account = create_account()
    writer = create_client(chain=studionet, account=account)
    tx = writer.write_contract(address=deployment["contract_address"],
                               function_name="register_reporter",
                               args=[json.dumps({"name": "Integration test reporter",
                                                 "origins": []})],
                               consensus_max_rotations=3)
    receipt = writer.wait_for_transaction_receipt(
        transaction_hash=tx, status=TransactionStatus.FINALIZED, interval=5000, retries=240)
    leader = receipt["consensus_data"]["leader_receipt"]
    assert str((leader[0] if isinstance(leader, list) else leader)["execution_result"]) == \
        "SUCCESS"
    profile = writer.read_contract(address=deployment["contract_address"],
                                   function_name="get_reporter",
                                   args=[str(account.address).lower()])
    assert profile["found"] and profile["name"] == "Integration test reporter"
