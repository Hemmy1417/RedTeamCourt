# Submission

**Category** - cybersecurity and AI-agent security: incident and disclosure adjudication.

**Title** - RedTeam Court: Security Adjudication for AI Agents.

**One-line thesis** - an AI agent's controller publishes a security policy and posts a
bond and a bounty pool; when a reporter files an incident or a disclosure, one consensus
round reads hash-bound evidence and chain records, and the contract's own code turns the
agreed findings into a verdict, a severity, responsibility, remediation and payment.

**Repository** - https://github.com/Hemmy1417/RedTeamCourt

**Canonical StudioNet address** - `0xcE3f7Bbec8b6Ded0Db1f7f9A166F5c34d0A5d96b`

**Explorer URL** - https://explorer-studio.genlayer.com/address/0xcE3f7Bbec8b6Ded0Db1f7f9A166F5c34d0A5d96b

**Deployment tx** - `0x8f082898b497bad9162874c222f5ff3af15b14078197f724984bfd9697863ea6`

**Deployment source** - commit `71b7f1b`, https://github.com/Hemmy1417/RedTeamCourt/blob/71b7f1b3501a44be1f0c033ea79a2a37d0d9b393/contracts/redteam_court.py (byte-identical on chain)

## Why GenLayer is required

Whether an AI agent breached its controller's security policy is a reading: the policy is
natural language, and the evidence is agent traces, tool-call logs, access records and
reports on the parties' own hosts. A deterministic contract can store hashes and a
severity someone typed, but cannot tell an injected instruction in a fetched invoice from
the controller's own configuration, or a tool's cache fault from an attack. One operator's
model can read it, but then the controller, the reporter and every contract that reads the
agent's standing must trust that operator's fetches, chain node and model. GenLayer makes
the reading itself the thing that is agreed: each validator fetches and verifies the
evidence, reads the cited chain transactions, asks its own model, and ratifies only a
consequence it derives from its own findings.

## Consensus mechanism

`gl.vm.run_nondet_unsafe(leader_fn, validator_fn)` once per adjudication, readjudication,
remediation review or adversarial case. Every validator reproduces the round from its own
fetches, chain reads and model call; gates the leader's payload against its own verified
bytes (exact keys, code-decided fields recomputed, every quote re-grounded, every support
rule met); compares every row, fact, chain fact, scan and the panel state; and compares
the consequence derived from each side's findings - verdict, severity, responsibility,
remediation, impact, confidence, compensation and bounty eligibility, report bond,
containment, corroboration, and on a settling record the rules it rests on and who
manipulated it. Notes, quote choice and shadings with no consequence are never compared.
The rule is stored in the contract and returned by `get_config`.

## Deterministic responsibilities

Identity (every recorded account is its signer); policy versions and when they bind;
evidence admission and origin classification; sha256 verification before any read;
chain facts; spending-limit, counterparty and logging rules; secret, hidden-text,
adjudicator-marker, staleness, trace-gap, time-reversal, impersonation, unlinked-agent and
cross-incident-reuse scans; the party-interest and configuration-record support rules;
the verdict, severity and its factors, responsibility shares, remediation, impact,
confidence, compensation, bounty and report bond; reservations, withdrawals and the
pull-payment ledger; every window and state transition.

## Failure policy

Fail closed and hold rather than guess. A reporter's unreadable or changed item, too
little eligible evidence, manipulation by both sides, a rule too vague to decide, an
undecided occurrence or an unusable model answer holds the incident with nothing moved;
every held state has a permissionless wall-clock exit that releases every reservation and
returns the report bond. A mitigating cause must be supported from outside the
controller's sphere, so doubt never shifts responsibility off it. A readjudication does
not run unless it can read again everything the appealed round read. A refused payable
call returns its deposit instead of raising. Money moves only at finalization, from the
ratified record's arithmetic, within reservations made at filing.

## Reuse surface

`agent_security_status(agent_id, as_of)` answers "should I trust this agent now" in one
read: standing, the policy in effect and its hash, open incidents and findings, the highest
open severity, containment, required remediation, verified remediations and the funds
behind the agent. `incident_status` says which action is open to whom;
`get_latest_adjudication` returns the full immutable record. `docs/integration.md` has the
shapes and a consumer snippet.

## Test results

RESULTS_PENDING

## Live evidence

LIVE_PENDING

## Limitations

Consensus assumes an honest validator majority. A hash proves bytes did not change, not
that they are true; provenance rests on registered origins and on the rule that a party's
own sphere cannot carry a finding in its favour. A chain record proves what the chain
recorded, not who held the key. Panel findings depend on validator models; a split stores
nothing and costs the honest party time. Bonded filings can hold a bond's reservations,
or another reporter's public records, until they close. Everything committed is public on chain;
confidential evidence is withheld from the contract's records, not from the chain. No
audit; the demo policy, agent and evidence are fixtures in this repository; StudioNet is a
test network. RedTeam Court does not replace security professionals, incident responders
or legal process, and executes no remediation.

## Reviewer fast path

```bash
python -m pip install -r requirements-test.txt && python scripts/fetch_genvm_bundle.py
```

```bash
python scripts/run_direct_mode.py
```

```bash
python -m pytest tests/direct -q
```

```bash
python scripts/deploy_studionet.py --verify
```

Then read, in order: `docs/architecture.md` (the boundary between code and consensus),
`docs/consensus.md` (what validators compare and what the live diagnostics showed), and
`docs/threat-model.md` (all thirty attacks with their tests). The contract is one file,
`contracts/redteam_court.py`.

## Portal description

PORTAL_PENDING
