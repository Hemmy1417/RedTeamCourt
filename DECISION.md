# Decision record

Why RedTeam Court, why this shape, and why it is a standalone Intelligent Contract.

## The question it answers

> Given a security policy an AI agent's controller published before the incident,
> evidence whose provenance code can classify, and chain transactions every node reads
> for itself: did the agent breach the policy, why, how badly, who is responsible, what
> must be remediated, and what do the controller's posted funds owe?

## Delete-GenLayer test

Remove consensus and one of two things is left.

Either a deterministic contract keeps the incident: hashes, timestamps, a severity
someone typed, an approval. It cannot read an agent trace, tell an injected instruction
in a fetched invoice from the controller's own configuration, notice that a tool-call
log contradicts the trace beside it, or decide whether "the agent must not change a
vendor's payout details unless escalation rule X1 is met" was breached. Every one of
those becomes a party's assertion, and the party with the most to lose writes it.

Or an operator runs one model over the evidence and posts the result. Then the
controller, the reporter and every contract that reads the agent's standing trust that
operator's fetches, its chain node and its model; neither side can check a reading
nobody else performed, and a second marketplace cannot reuse the finding without
trusting the first.

What breaks is exactly the part that needs reading: whether conduct breached a
natural-language rule, whether an attacker, a misconfiguration, a tool or a dependency
caused it, and whether a vulnerability really reproduced. RedTeam Court has independent
validators each fetch and hash-verify the evidence, read the chain, and answer only
those questions with quotes each of them re-grounds; and it keeps every verdict,
severity, share and amount in code (`_derive`, `_severity`, `_responsibility`,
`_settle`). The model never sees a number it could move.

## Why this is not a rejected pattern

| Pattern | Why RedTeam Court is not it |
|---|---|
| a thin LLM wrapper | the model returns findings with quotes; code derives the verdict, severity, responsibility, remediation and money, and refuses any finding whose quotes are not in the bytes or whose support is self-serving |
| a generic AI app | there is no app: one contract, one view for consumers (`agent_security_status`) |
| a format-only validator | validators reproduce the whole round from their own fetches, chain reads and model call, and compare what was read and what it leads to (`_validator_decision`) |
| caller-authored evidence | evidence is bound by sha256 at commitment, its origin is classified by code, a chain transfer is read by every node from a fixed registry, and a finding that favours a party must rest on something outside that party's sphere |
| toy storage | a security bond and bounty pool with reservations, delayed withdrawals, report bonds, appeals, stall exits, remediation reviews and a pull-payment ledger, every terminal state accounting for every atto |
| a full application | detection, containment and remediation execution stay outside; the contract is the evidence, adjudication and accountability layer |

## Portfolio collision analysis

Earlier builds by the same author that touch AI agents, security or adjudication:

| Build | What it decides | Overlap | Why RedTeam Court is not a copy |
|---|---|---|---|
| AgentGuard | whether one agent delivered a service to another, and the split of an escrow | the evidence model, the party-interest rule, the adversarial engine | AgentGuard adjudicates commerce between two agents under terms both assented to. RedTeam Court adjudicates an agent's conduct against its controller's security policy: causal attribution (attacker, misconfiguration, tool, dependency), severity from explicit factors, remediation, disclosures and bounties, and a standing other contracts read. Its sphere rule is wider - a controller's sphere includes the tools and public sources it chose - and a mitigating cause carries the burden of proof. |
| AgentShield | whether an agent's staked commitment was fulfilled | agents, collateral, a tribunal | AgentShield asks whether a promised task met its SLA. RedTeam Court asks whether an agent breached security rules and why, and pays compensation only for harm under a compensable verdict. |
| Rampart | whether a bug-bounty report is valid against a pinned scope, paid from a severity-tiered pool | disclosures, severity tiers, a pool | Rampart is a bounty market for a system's scope. A disclosure here is one of two case kinds about one agent under a behavioural policy; a confirmed vulnerability opens a finding that must be verified fixed, and incidents with compensation share the same record. |
| Gauntlet | whether a challenger breaks a prompt-injection guardrail | prompt injection | Gauntlet is an arena where injection is the game. Here injection is an attack on the adjudication itself, answered by code exclusion, attribution to the submitter and consequence-only consensus. |
| Retinue | whether a content operator's public output kept its mandate | supervising an agent against natural-language rules | Retinue reviews public web output each window. RedTeam Court adjudicates filed incidents over private records - traces, logs, access records - and chain transfers, with adversarial parties on both sides. |
| InsureShield, CredenceLend | whether committed documents satisfy a policy, under adversarial evidence | hash-bound evidence, code facts beside a panel, the adversarial engine | the closest ancestry of the evidence pipeline. Both decide about one party's documents; RedTeam Court adds opposed parties, spheres, causes, severity and remediation. |

Reused deliberately, from builds that shipped: the pinned StudioNet runner, hash
verification before any read, "the model returns findings, code derives the outcome",
word-level quote grounding, the structural gate re-run by every validator and again on
the ratified payload, consequence-only equivalence, the commitment registry, the
pull-payment ledger, returned deposits on payable refusals, and the on-chain
adversarial engine. None of it is presented as new; what is new is the security
adjudication spine on top.

## Ecosystem collision analysis

| Existing kind of tool | What it does | Why it is not this |
|---|---|---|
| security incident trackers and advisory databases | record an incident, its severity and status | a person types the severity and the conclusion; nothing reads the evidence or resolves a dispute between the parties |
| bug-bounty platforms | triage reports and pay researchers | the platform or the vendor decides validity; the researcher cannot check the reading, and nothing ties the result to an agent's standing elsewhere |
| agent runtime guardrails and injection detectors | block or flag an action as it happens | detection, not adjudication: they do not decide afterwards who was responsible, how bad it was or what is owed, and they are one vendor's judgment |
| staked-juror courts | crowd-judge disputes | human jurors over days, on whatever a party pastes; here validators reproduce readings of hash-bound evidence and chain records in one round |
| on-chain cover and claims assessment | pay claims by assessor vote | assessors vote on narratives; they do not read an agent's trace against a policy, and severity is not derived from explicit factors |

## Candidates considered

| # | Candidate | Score /5 | Verdict |
|---:|---|---:|---|
| 1 | **AI-agent security incident and disclosure adjudication, with a controller's bond and bounty pool** | 5 | **selected** - the decision is unavoidably a reading, both sides are adversarial, and the finding is reusable by any consumer |
| 2 | an agent action firewall oracle ("is this action safe now?") | 2 | a pre-action classification under latency; no evidence trail, no counterparty, no dispute |
| 3 | an on-chain security advisory registry for agents | 1 | deterministic storage; the conclusions still come from whoever writes them |
| 4 | a bug-bounty escrow for agent vulnerabilities | 2 | collides with Rampart, and drops the incident half, where causes and compensation need the most reading |
| 5 | an agent insurance claims court | 3 | collides with InsureShield and needs underwriting the evidence cannot supply; the adjudication part is candidate 1 |

## Three consumers

1. **An agent marketplace** checks `agent_security_status` before routing work to an
   agent, and stops at `CONTAINMENT_REQUIRED`.
2. **A payment router or treasury contract** refuses to move funds for an agent wallet
   whose standing requires containment or has no policy in effect.
3. **An insurer or a counterparty** reads the unreserved bond, the verified remediations
   and the policy hash to price how much of an agent's risk is backed.

None of them needs web access, prompts or an equivalence rule: `docs/integration.md`.

## Where the build departs from the brief, and why

| The brief | This build | Why |
|---|---|---|
| modules `models.py`, `policies.py`, `evidence.py`, ... | one file, `contracts/redteam_court.py`, organised in sections with those names | the pinned single-file runner is the proven StudioNet deployment path, and one file keeps the deployed source byte-comparable with the repository |
| `tests/test_*.py` | `tests/direct/test_*.py` with the brief's nine module names plus two, and `tests/integration/` | Direct Mode and live integration run under different harnesses |
| screenshots as evidence | no screenshot category | the contract reads text; an image nothing reads would be admitted as if examined |
| twelve verdicts "such as" | thirteen, adding `CONFIRMED_VULNERABILITY` | a confirmed disclosure pays a bounty and opens a finding; it is not a violation of the incident kind |
| appeals reference a finalized result | appeals reference the standing adjudication inside its window, before anything moves; a finalized finding is revisited through remediation reviews | an appeal after money moved would have to claw it back; before finalization nothing needs undoing |
| `AgentProfile.status`, `policy_ids` | standing derived at read time (`agent_security_status`); one policy per agent | a stored status goes stale the moment a window passes; the policy versions carry the history |
| a remediation "sufficient" judgment | `VERIFIED` only on remediation test results supported from outside the controller's sphere | a fix the controller vouches for alone is a claim |
