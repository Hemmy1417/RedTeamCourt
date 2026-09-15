# Deployment

## Deployment of record

RECORD_PENDING

## Environment

| Item | Value |
|---|---|
| Network | GenLayer StudioNet |
| RPC | `https://studio.genlayer.com/api` |
| Chain id | 61999 |
| Explorer | `https://explorer-studio.genlayer.com` |
| Runner | `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`, pinned in the contract's first comment block |
| Python | 3.12.2 |
| `genlayer-py` | 0.16.3 (deploys, writes, reads) |
| `genlayer-test` | 0.29.2 (Direct Mode) |
| `genvm-linter` | 0.11.0 |

No environment variable is required. Keys never come from the environment:

| File | Holds | Created by |
|---|---|---|
| `.data/deployer.json` | the deployer key; StudioNet is gasless, so it holds no funds | `scripts/deploy_studionet.py`, on first use |
| `.data/demo_wallets.json` | the demo parties' keys (controller, agent wallet, Harbor, Northwind, Quayside, Docfetch, stranger, vendors, attacker) | `scripts/generate_fixtures.py`, only when `fixtures/wallets.json` does not exist |

`.data/` is gitignored and no script prints a key. `fixtures/wallets.json` holds only
public addresses, so a clean clone regenerates byte-identical fixtures without a key.
Optional settings in `.env.example`: `REDTEAM_LIVE_WRITES=1` lets `tests/integration`
send one write to the canonical deployment; `GENVM_VERSION` picks the runner bundle
`scripts/fetch_genvm_bundle.py` seeds.

## Build

There is no build step: the contract is Python source that GenVM runs as deployed.
`contracts/redteam_court.py` must be ASCII with LF line endings (the deploy script
refuses anything else), and the blank line after the `Depends` comment is load-bearing.

```bash
genvm-lint check contracts/redteam_court.py
```

## Deploy

```bash
python scripts/deploy_studionet.py
```

The script refuses to deploy unless the contract file is committed and unmodified,
signs with `.data/deployer.json`, waits for `FINALIZED`, asserts the leader's execution
result is `SUCCESS` (a finalized transaction can still carry an execution error), reads
the deployed source back with `gen_getContractCode`, compares its sha256 with the
committed file, and writes `deploy/deployment.json`: the address, the deploy
transaction, the signer, the status and votes, the source commit and blob, both hashes,
and the explorer links.

```bash
python scripts/deploy_studionet.py --verify
```

re-checks source parity for the recorded deployment at any later commit.

## Health check

```bash
python scripts/inspect_deployment.py
```

Read-only: source parity, the deployed method count, `health_check` and `get_stats`
(every fund and the claimable total), the configured version and bounds, the demo
agent's standing now, and which actions are open on each of its incidents.

## A sample run

`scripts/live_scenarios.py` performs every step below against a deployment, with the
fixtures served from a commit-pinned raw GitHub base, and records every transaction in
`deploy/live_scenarios_transcript.json`. It is resumable: every hash is saved before its
receipt is awaited, so an interrupted run never sends a step twice.

```bash
python scripts/live_scenarios.py <address> --raw-base https://raw.githubusercontent.com/Hemmy1417/RedTeamCourt/<commit>/fixtures/
```

| Step | Call | Signer |
|---|---|---|
| register the policy | `register_policy(policy_json)` with `fixtures/world.json`'s policy, its origins pointed at the raw base | controller |
| register the tool, the reporters and the agent | `register_tool`, `register_reporter`, `register_agent`, `confirm_agent_wallet` | Docfetch, each reporter, controller, agent wallet |
| fund | `post_security_bond`, `fund_bounty_pool` with value | controller |
| create an incident | `open_incident(agent_id, 1, incident_json)` with exactly the report bond | Harbor |
| submit evidence | `submit_evidence(incident_id, "USER_REPORT", url, sha256, ...)` | Harbor |
| adjudicate | `request_adjudication(incident_id)` | anyone |
| appeal | `submit_evidence(...)` for the new item, then `submit_appeal(incident_id, adjudication_id, reason, [evidence_id])` | Harbor |
| readjudicate | `request_readjudication(appeal_id)` | anyone |
| finalize and withdraw | `finalize_incident(incident_id)`, then `withdraw()` | anyone; Harbor |

A single step can be sent with the CLI once the network is selected
(`genlayer network set studionet`), for example:

```bash
genlayer call <address> agent_security_status --args AGT-000001 2026-09-15T12:00:00Z
```

## Inspecting a result

- `get_latest_adjudication(incident_id)` returns the full record: verdict, severity and
  its factors, responsibility, remediation, impact, confidence, payment advice,
  evidence receipts, findings with their quotes, reason codes and `record_digest`.
- `incident_status(incident_id, as_of)` says which action is open to whom.
- `genlayer receipt <tx> --stdout` shows each node's stdout, where a disagreeing
  validator prints `[DISAGREE]` and its own reading (`[MINE]`).
- The explorer shows every transaction at `/tx/<hash>` and the contract at
  `/address/<address>`.

## Resetting test data

A deployed contract's state cannot be reset, and nothing should try: incidents,
records and the ledger are the point. To start clean, deploy a fresh contract - it has
its own empty state - and point `live_scenarios.py` at the new address with a new
transcript (move `deploy/live_scenarios_transcript.json` aside first; the script refuses
a transcript that belongs to another deployment). Funds left in an old deployment are
withdrawable by their owners at any time.

The deployment of record is never appealed at the protocol level; the appeal path is the
contract's own `submit_appeal`, which is recorded state like any other write.

## Superseded deployments

A deployment is superseded when the contract changes after it; its records stay, marked as
history, and are never described as proof for the current source.

| Address | Source commit | Why it was superseded | Its record |
|---|---|---|---|
| `0x708A0B8dD827213de651f11185EDbe129AeB0229` | `3930411` | the mutation sweep on that commit showed the evidence registry trusted declared categories: a settled record relabelled as threat intelligence or a policy document escaped both the replay rejection and the cross-incident exclusion; a security review then showed party boundaries crossable (a reporter's name excluding the controller's records, manipulation charged to whoever cited an item, a respondent's takedown holding the case, a withdrawal blocking the loser's appeal, a global registry, early requests by respondents, standing withdrawals, a shared remediation cap, a chain record verifying a fix) | `deploy/superseded/0x708A0B8d/` (record, live transcript and log, partial mutation sweep) |

## Disposable deployments

These deployments were diagnostic, never canonical; each ran catalogue cases to show
how StudioNet's validators read them, and its record is under `deploy/diagnostics/`.

| Address | Contract commit | Run | What it showed |
|---|---|---|---|
| `0x2911fE2FB130572563F90646803A17992c59Bd58` | `372493b` | `run_20260915T061945.json` | 13 of 21 cases held; own-sphere quoting, causes held undecided, an untested disclosure read as not reproducing |
| `0x814359895216fcdd1D32161cA736932E64658CAC` | `cb769c2` | `run_20260915T072301.json` | 19 of 21 held; RC10 read an accidental cache delivery as an attacker, RC14's exception quoted only Meridian's own records |
| `0x63FAA645a45f66cA9D3E3B56b55D0AF8cBC04E4c` | `6362d13` | `run_20260915T075012.json` | 6 of 8 held; RC10 read as a misconfiguration from conduct alone, and the phase A readjudication split on R1 and R7 |
| `0x59003423d8D3f32360e6c7650DAFcc6299CD9660` | `0e7dda7` | `run_20260915T101732.json` | 5 of 5 held: RC10, RC14, RC23 and both phase A rounds |
