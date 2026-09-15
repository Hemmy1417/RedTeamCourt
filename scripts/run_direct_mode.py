#!/usr/bin/env python3
"""Run one sample security incident in Direct Mode and print it readably.

    python scripts/run_direct_mode.py            # readable summary
    python scripts/run_direct_mode.py --json     # the full stored record

The sample is the honest compromise: Harbor Supplies reports that a forged
invoice took control of Meridian Labs' treasury agent Ledgerline, which
leaked the vendor bank file and queued a payment to the attacker. Six
evidence items - the reporter's report and the captured invoice, the
controller's trace and access grants, the tool provider's log and the
agent wallet's transaction - one consensus round, and the outcome the
contract derives from it. It runs the real contract in the official
genlayer-test direct runner, with the fixture documents served byte for byte,
the chain answered in StudioNet's own shape and the panel answered from
fixtures/cases.json. No network, no keys, no funds.
"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEST = "tests/direct/test_contract_smoke.py::test_compromise_incident_end_to_end"
ATTO = 10 ** 18


def gen(atto) -> str:
    atto = int(atto)
    whole = atto // ATTO
    rest = (atto % ATTO) * 10000 // ATTO
    return format(whole, ",") + "." + str(rest).zfill(4) + " GEN"


def show(record: dict) -> None:
    advice = record["compensation_or_bounty_recommendation"]
    print("RedTeam Court sample adjudication (Direct Mode)")
    print("=" * 72)
    print(f"record          {record['adjudication_id']}  ({record['kind']})")
    print(f"incident        {record['incident_id']}  {record['incident_kind']}  "
          f"agent {record['agent_id']}")
    print(f"policy          {record['policy_id']} v{record['policy_version']}  "
          f"{record['policy_hash'][:16]}...")
    print()
    print(f"verdict         {record['verdict']}   settles: {record['settles']}")
    print(f"severity        {record['severity']} of 5   confidence {record['confidence']}   "
          f"corroboration {record['corroboration']}")
    factors = record["severity_factors"]
    print(f"  factors       rule weight {factors['rule_weight']}, harm "
          f"{factors['material_harm']}, financial {factors['financial_impact']}, "
          f"ongoing {factors['ongoing_exposure']}, cap {factors['cap']}")
    print("impact          " + ", ".join(record["impact_classification"]))
    print("responsibility  " + ", ".join(
        f"{s['party'].lower()} {s['bps'] // 100}%" for s in record["responsibility_allocation"]))
    print("remediation     " + ", ".join(record["required_remediation"]))
    print(f"compensation    {gen(advice['compensation_atto'])} of "
          f"{gen(advice['reserved_compensation_atto'])} reserved   report bond "
          f"{advice['report_bond']}")
    print(f"appeal until    {record['appeal_deadline']}")
    print()
    print("findings")
    for f in record["rules"] + record["indicators"]:
        if f["state"] in ("ABSENT", "NOT_APPLICABLE"):
            continue
        quotes = "; ".join('"' + q["text"] + '"' for q in f["quotes"])
        print(f"  {f['id']:<30}{f['state']:<14}by {f['by']:<6}{quotes[:70]}")
    print()
    print("evidence receipts")
    print(f"  {'id':<4}{'source':<18}{'by':<11}{'origin':<11}{'status':<12}{'counted':<8}"
          "relevance")
    for r in record["receipts"]:
        print(f"  {r['evidence_id']:<4}{r['source_type']:<18}{r['submitted_by']:<11}"
              f"{r['origin']:<11}{r['status']:<12}{str(r['counted']):<8}"
              f"{r['relevance_status']}")
    print()
    print("reason codes")
    print("  " + ", ".join(c for c in record["reason_codes"] if not c.startswith("CHAIN:")))
    print()
    print("summary")
    print("  " + record["reasoning_summary"])


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp) / "record.json"
        env = dict(os.environ, REDTEAM_SAMPLE_OUT=str(out))
        run = subprocess.run([sys.executable, "-m", "pytest", TEST, "-q", "-p",
                              "no:cacheprovider"], cwd=ROOT, env=env,
                             capture_output=True, text=True)
        if run.returncode != 0 or not out.exists():
            print(run.stdout[-3000:], run.stderr[-2000:])
            print("the sample adjudication did not complete")
            return 1
        record = json.loads(out.read_text(encoding="utf-8"))
    if "--json" in sys.argv:
        print(json.dumps(record, indent=2))
    else:
        show(record)
    return 0


if __name__ == "__main__":
    sys.exit(main())
