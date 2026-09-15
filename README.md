<p align="center"><img src="docs/assets/redteam-court-mark.svg" width="140" alt="RedTeam Court"/></p>

# RedTeam Court - Security Adjudication for AI Agents

**A standalone GenLayer Intelligent Contract that decides, under validator consensus, whether an AI agent breached the security policy its controller published, why it happened, how severe it was, who is responsible, what must be remediated, and what the controller's posted funds owe.**

An agent's controller publishes a versioned security policy, registers the agent and posts a security bond and a bounty pool. A reporter files an incident or a vulnerability disclosure against the policy version in effect, with a report bond. Every party commits evidence bound to the sha256 of its exact bytes, or a chain transaction every node reads for itself. One consensus round has each validator fetch and verify every item, read every fact and chain record in code, and answer only the questions code cannot - each finding carrying quotes every validator re-grounds in its own bytes, and never resting only on the favoured party's own records. Code then derives the verdict, the severity, responsibility, remediation and every amount.

No model output ever reaches a verdict, a severity or an amount.

Canonical deployment: [`0xcE3f7Bbec8b6Ded0Db1f7f9A166F5c34d0A5d96b`](https://explorer-studio.genlayer.com/address/0xcE3f7Bbec8b6Ded0Db1f7f9A166F5c34d0A5d96b) on GenLayer StudioNet, from commit `71b7f1b`, byte-identical.

## At a glance

| Question | Answer |
|---|---|
| What is RedTeam Court | A standalone Intelligent Contract primitive: the evidence, adjudication and accountability layer for AI-agent security incidents and disclosures. No frontend, no backend, no operator. |
| Who calls it | Controllers of AI agents, reporters (affected parties and security researchers), and any contract that decides whether to trust an agent through `agent_security_status`. |
| What does it decide | Whether an agent's conduct breached its controller's policy or an escalation rule authorised it; whether an attacker, a misconfiguration, a tool or a dependency caused it; whether harm occurred and exposure continues; whether a vulnerability reproduced; whether a fix is verified. |
| Why GenLayer must decide it | The policy is natural language and the evidence is traces, logs, access records and reports on the parties' own hosts. A deterministic contract cannot tell an injected instruction from the controller's configuration, and one operator's model is an authority neither party can check and no second consumer can reuse. |
| What evidence it uses | Items committed to the incident from the registered origins of its parties or the policy's public sources, hash-verified before any read; and chain transactions read from a fixed registry. Code classifies each item's origin, and a finding favouring a party must quote something outside that party's sphere. |
| How consensus works | `gl.vm.run_nondet_unsafe` once per round. Each validator reproduces the round from its own fetches, chain reads and model call, gates the leader's payload against its own bytes, and agrees only if what was read matches and the consequence it derives from its own findings equals the leader's. |
| How money moves | Three payable entries (`post_security_bond`, `fund_bounty_pool`, `open_incident`), reservations at filing, payments only at finalization from the ratified record's own arithmetic, and one exit (`withdraw`, a pull-payment ledger). A refused deposit is returned, never reverted. |
| What tests prove it | 387 Direct Mode tests covering all 30 brief attacks, forged leaders through the captured validator, hostile model output, severity and payment bounds, appeals, stalls and remediation; GenVM lint and validation; preflight; live diagnostics on StudioNet. See "Verified". |

## What it is

- **Identity is the signer.** Every recorded account - controller, reporter, tool provider, appellant - is the wallet that signed.
- **The policy binds before the incident.** Versions are immutable and take effect only after notice; an incident binds the version in effect when it was filed.
- **Hash-bound evidence, classified by origin.** Bytes are verified before anything reads them; code records whose registered origin served each item.
- **Chain records nobody controls.** Spending-limit and counterparty rules are decided by code from transactions every node reads for itself.
- **Code scans before any model.** Secrets, hidden text, text addressed to the adjudicator, trace gaps and reversed times, stale records, impersonated issuers, evidence about another agent, and records reused from another incident are excluded before the panel is asked.
- **Consensus decides the reading.** Whether a rule was breached or an exception applied, why it happened, harm, ongoing exposure, reproduction, a verified fix, and whether an item was tampered with or aims at the panel.
- **Burden of proof.** A finding that favours a party must rest on something outside that party's sphere; a cause that would move responsibility off the controller is the controller's to show.
- **Code derives the outcome.** Thirteen verdicts, severity 0-5 from explicit factors, responsibility in basis points, remediation classes, impact classes, confidence, compensation, bounty and report bond.
- **Every state has an exit.** `close_stalled_incident` is permissionless and wall-clock; remediation is verified by test results, not claims.
- **Appeals judge what the first panel saw.** A readjudication writes a new record naming what changed, and does not run unless it can read again everything the appealed round read - so no party wins an appeal by withdrawing its own evidence.
- **An on-chain adversarial-test engine.** Register attacks against a policy version; anyone runs them through the real pipeline.

## How it works

### For a controller

1. `register_policy(policy_json)`, then `register_agent(agent_json)`; the agent's wallet signs `confirm_agent_wallet`.
2. `post_security_bond(agent_id)` and `fund_bounty_pool(agent_id)` with GEN.
3. When an incident is filed: `submit_counterreport` and `submit_evidence` from your own origins.
4. After a finding: publish remediation evidence, then `submit_remediation_report`; a review on test results supported from outside your sphere clears it.
5. `request_withdrawal` and, after the delay, `complete_withdrawal` from what incidents have not reserved.

### For a reporter

1. `register_reporter(reporter_json)` with the origins you publish records from.
2. `open_incident(agent_id, policy_version, incident_json)` with exactly the policy's report bond - an INCIDENT, or a DISCLOSURE with a confidentiality period.
3. Publish each item under your origins, then `submit_evidence(...)` with its sha256, or cite a chain transaction.
4. After the round, `submit_appeal` inside the window with new evidence of your own.
5. `withdraw()` the compensation or bounty and your returned bond.

### For anyone

`request_adjudication`, `request_readjudication`, `finalize_incident`, `close_stalled_incident`, `request_remediation_review`, `lift_disclosure_embargo` and `run_adversarial_case` are permissionless. A reporter whose controller went quiet is never stuck.

## Verdicts

| Verdict | Meaning | Money |
|---|---|---|
| `CONFIRMED_VIOLATION` | a rule was breached, no cause established | compensation with harm; bond returned |
| `CONFIRMED_COMPROMISE` | a rule was breached under an attacker's control | compensation at the controller's committed share; bond returned |
| `LIKELY_MISCONFIGURATION` | a rule was breached because the controller's configuration allowed it | compensation with harm; bond returned |
| `LIKELY_EXTERNAL_FAILURE` | a rule was breached because a tool or a declared dependency failed | none from the controller's bond; bond returned |
| `CONFIRMED_VULNERABILITY` | a disclosure reproduced and breaches a rule | bounty at the severity tier; bond returned |
| `REQUIRES_CONTAINMENT` | no rule proven, but an attacker controls the agent and exposure continues | none; bond returned |
| `POLICY_COMPLIANT` | the conduct happened and every alleged rule was clear or authorised | none; bond returned |
| `FALSE_POSITIVE` | the conduct did not happen, or the vulnerability did not reproduce | report bond to the controller |
| `REJECTED` | a replay of a settled incident, or the reporter manipulated the record | report bond to the controller |
| `INSUFFICIENT_EVIDENCE` | too little eligible evidence | **held** |
| `CONFLICTING_EVIDENCE` | both sides manipulated the record | **held** |
| `SOURCE_UNAVAILABLE` | a reporter's item unreadable or changed, or a chain unreadable | **held** |
| `INCONCLUSIVE` | a rule too vague to decide, an undecided occurrence, or an unusable model answer | **held** |

A held incident moves nothing: an appeal or the stall exit decides it, and the stall exit releases every reservation and returns the report bond.

## Severity

```text
violation-class  = heaviest violated rule weight            (data-class: at least sensitivity + 1)
                   + 1 for material harm or agent-wallet value >= high_value_atto
                   + 1 for exposure evidence shows is still open
containment      = 3 + 1 for harm
policy compliant = 1                                        everything else = 0
cap              = 3 when the record rests on one side's items alone, else 5
```

Full factors, impact classes and confidence in [`docs/severity-model.md`](docs/severity-model.md).

## Lifecycle

```text
open_incident --> OPEN --submit_counterreport (all respondents)--> RESPONDED
 (reporter,        |                                                  |
  report bond,     +------------ request_adjudication (anyone) -------+
  reservation)                          |
                                        v
                                   ADJUDICATED --submit_appeal + request_readjudication--> ADJUDICATED
                                   /         \                (new record, same reservation)
              finalize_incident   /           \   close_stalled_incident (wall clock)
              (settling record)  v             v
                            FINALIZED     CLOSED_UNRESOLVED
                                 |        (reservations released, bond returned)
                   finding open: submit_remediation_report + request_remediation_review
                                 |
                              withdraw()
```

## Contract

`contracts/redteam_court.py`, runner `py-genlayer:1jb45aa8...` (pinned), 25 writes (3 payable), 20 views.

### GenLayer consensus functions

| Function | Kind | What runs under consensus |
|---|---|---|
| `request_adjudication(incident_id)` | write | fetch and verify every item, read every cited transaction, scan in code, ask the panel what code cannot decide |
| `request_readjudication(appeal_id)` | write | the same round over the case and appeal evidence; a new record naming what changed |
| `request_remediation_review(incident_id)` | write | the same round over remediation evidence, asking whether the fix is verified |
| `run_adversarial_case(case_id)` | write | the same round over a registered synthetic incident |

### Write methods

| Method | Who | Payable | Notes |
|---|---|---|---|
| `register_policy(policy_json)` | controller | no | version 1, binds at once |
| `publish_policy_version(policy_id, policy_json)` | owner | no | binds after the activation delay |
| `deactivate_policy(policy_id)` | owner | no | after the same notice; terminal |
| `register_tool(tool_json)` | tool provider | no | |
| `register_reporter(reporter_json)` | reporter | no | one per wallet |
| `register_agent(agent_json)` | the policy's owner | no | |
| `confirm_agent_wallet(agent_id)` | the agent's wallet | no | |
| `post_security_bond(agent_id)` | controller | yes | pays compensation |
| `fund_bounty_pool(agent_id)` | controller | yes | pays bounties |
| `request_withdrawal(agent_id, fund, amount_atto)` | controller | no | one pending per fund |
| `complete_withdrawal(agent_id, fund)` | controller | no | after the delay, from what is unreserved |
| `open_incident(agent_id, policy_version, incident_json)` | reporter | yes | exactly the report bond; reserves compensation or bounty |
| `submit_evidence(incident_id, ...)` | a party | no | case, appeal or remediation phase |
| `submit_counterreport(incident_id, statement)` | controller, tool provider | no | |
| `request_adjudication(incident_id)` | anyone | no | consensus |
| `submit_appeal(incident_id, adjudication_id, reason, new_evidence_ids)` | a party | no | inside the window |
| `request_readjudication(appeal_id)` | anyone | no | consensus |
| `finalize_incident(incident_id)` | anyone | no | money moves here |
| `close_stalled_incident(incident_id)` | anyone | no | wall-clock exit |
| `lift_disclosure_embargo(incident_id)` | anyone | no | after the embargo |
| `submit_remediation_report(incident_id, statement, evidence_ids)` | controller | no | |
| `request_remediation_review(incident_id)` | anyone | no | consensus |
| `withdraw()` | any wallet owed | no | pull payment |
| `register_adversarial_case(...)` | policy owner | no | |
| `run_adversarial_case(case_id)` | anyone | no | consensus |

### Read methods

`agent_security_status`, `incident_status`, `get_incident`, `get_adjudication`, `get_latest_adjudication`, `get_incident_history` (paged), `get_evidence`, `get_appeal`, `get_policy`, `get_agent`, `get_tool`, `get_reporter`, `list_agent_incidents` (paged), `get_claimable`, `get_returned_deposits` (paged), `get_adversarial_case`, `list_adversarial_cases` (paged), `get_config`, `health_check`, `get_stats`. Views never revert on unknown ids and read bounded slices only; [`docs/integration.md`](docs/integration.md) has the shapes.

### Consensus guarantees

- The payload carries no verdict, severity, share or amount; validators agree on the outcome by deriving it from their own findings.
- Every quote is re-grounded in each validator's own verified bytes; a finding favouring a party that rests only on that party's sphere is refused by the gate.
- Notes, quote choice and shadings with no consequence are recorded, never compared.
- A round that splits stores nothing and moves nothing.

## Verified

| Check | Result |
|---|---|
| `python -m pytest tests/direct -q` | 387 passed |
| `genvm-lint check contracts/redteam_court.py` | lint and validation pass, 45 methods |
| `ruff check .` | clean |
| `python scripts/generate_fixtures.py --check` | fixtures match |
| `python scripts/mutation_check.py --jobs 3` on `71b7f1b` | 172 of 181 killed; tests added for the 9 survivors, which were then re-run: 9 killed (`deploy/mutation_sweep_71b7f1b.txt`, `deploy/mutation_survivors_recheck.txt`) |
| `python -m pytest tests/integration -q` against the deployment | 6 passed, 1 skipped (the opt-in live write) |

One run on the deployment of record, 110 transactions, finished 2026-09-15T15:58:30Z (`deploy/live_scenarios_transcript.json`, `deploy/live_scenarios.log`).

| What | Result |
|---|---|
| Adversarial cases through the on-chain engine | 20 of 22 held; RC14, RC22 did not (below) |
| Incident with real GEN | first round held at `INCONCLUSIVE` on the reporter's own items; the appeal with the chain record was readjudicated to `CONFIRMED_COMPROMISE` severity 5 ([readjudication](https://explorer-studio.genlayer.com/tx/0xb0782f5823c1710df2b33ee0d300dbcec9efe3f9a00320ed5551be796f754734)); finalized ([tx](https://explorer-studio.genlayer.com/tx/0xdda3734ca17355eaac6b1a1ccf1a180417e9d8d939174bdac8e892387422fa4b)); Harbor withdrew 0.06 GEN and its wallet rose by exactly that |
| Disclosure | `CONFIRMED_VULNERABILITY` severity 4; Northwind withdrew bounty and bond, 0.11 GEN, exactly |
| False report | `FALSE_POSITIVE`; report bond forfeit |
| Remediation | without tests `INSUFFICIENT_EVIDENCE` (code); with the retest `VERIFIED` (panel) |
| Stall exit, policy version 2 | `CLOSED_UNRESOLVED`; version 2 published with its activation delay (2026-09-15T15:37:16Z to 2026-09-15T15:42:16Z) |
| Refusals | 15 attempted, every one refused on chain |
| Ledger | held equals paid in minus withdrawn at all 7 checkpoints; the chain balance read at the end, 410000000000000000 atto, equals what the contract holds |

Not held, stated plainly: RC14 (a legitimate emergency suspension) came back `INSUFFICIENT_EVIDENCE`: three of five nodes found the authorised exception but quoted only Meridian's own alert and trace, so the support rule refused it, as designed. RC22 (an unsafe exploit payload the agent refused) came back `INCONCLUSIVE`: every voting model read the refused attempt as a reproduction, the support rule refused that reading, and the question was left undecided. Both failed toward holding: no money moved and nothing was finalized.

## Repository

```text
contracts/redteam_court.py      the contract
tests/direct/                   Direct Mode suite (twelve modules)
tests/integration/              StudioNet checks against the canonical deployment
fixtures/                       evidence documents, demo wallets, the case catalogue
scripts/generate_fixtures.py    regenerates fixtures/ byte for byte
scripts/run_direct_mode.py      one readable sample adjudication
scripts/preflight.py            repository invariants
scripts/mutation_check.py       mutation kill sweep with an accept-control
scripts/deploy_studionet.py     deploy and verify source parity
scripts/inspect_deployment.py   read-only inspection of a deployment
scripts/diagnostic_rounds.py    disposable rounds that show why validators split
scripts/chain_transfer.py       the wallet-to-wallet transfers the cases cite
scripts/live_scenarios.py       the live run on StudioNet, with real GEN
docs/                           architecture, threat model, policy, evidence, severity, remediation, consensus, security, integration, deployment
DECISION.md                     why this primitive, collisions, consumers, departures from the brief
SUBMISSION.md                   copy-ready submission text
```

## Getting started

```bash
python -m pip install -r requirements-test.txt
```

```bash
python scripts/fetch_genvm_bundle.py
```

```bash
python -m pytest tests/direct -q
```

```bash
python scripts/run_direct_mode.py
```

`fetch_genvm_bundle.py` seeds the GenVM runner bundle that `genlayer-test` 0.29.2 cannot fetch on a cold cache. Nothing above needs a key or a network account; [`docs/deployment.md`](docs/deployment.md) covers StudioNet.

## Security

Everything retrieved is untrusted data. Code excludes secrets, hidden text, text aimed at the adjudicator, gapped or reversed logs, impersonated issuers and reused records before any model is asked; the prompt frames every item and statement as a claim; manipulation is attributed to the party whose origin served it; and no model produces a verdict or an amount. [`docs/security.md`](docs/security.md) states the assets, actors, trust assumptions and fail-closed policy, and [`docs/threat-model.md`](docs/threat-model.md) walks all thirty brief attacks.

## Limitations

- Consensus assumes an honest validator majority.
- A hash proves the bytes did not change, not that they are true; provenance rests on registered origins and on the rule that a party's own sphere cannot carry a finding in its favour.
- `minimum_evidence_items` counts eligible items, not independent publishers; independence comes from the sphere rule, which makes a finding in a party's favour rest on something outside that party's control.
- A chain record proves what the chain recorded, not who held the key.
- The registry recognises the same bytes and the same transaction, not the same event: a new record of an old event - a later log that covers the same session - is new evidence.
- A registered reporter can file first against the same agent with another reporter's public records; while that bonded filing is open, those records count as reuse.
- Reservations are made at filing: several bonded filings with large claims can hold a bond's capacity until they close, and an incident filed against a fully reserved bond reserves nothing.
- Panel findings depend on validator models; they are grounded and compared on consequence, and a split stores nothing - which costs the honest party time.
- Views take the caller's clock (`as_of`).
- Histories are bounded: eight policy versions, three adjudications per incident, three remediation reviews.
- Everything committed is public on chain; confidential evidence is withheld from this contract's records, not from the chain.

## Not production-ready

No audit. The demo policy, agent, tool and every evidence document are fixtures in this repository; StudioNet is a test network and the funds are test GEN. RedTeam Court does not replace security professionals, incident responders or legal process, does not detect or contain incidents, and executes no remediation.

## Licence

MIT - see [LICENSE](LICENSE).
