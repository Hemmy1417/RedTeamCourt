# Architecture

RedTeam Court is one GenLayer Intelligent Contract, `contracts/redteam_court.py`,
that adjudicates AI-agent security incidents and vulnerability disclosures
against a security policy the agent's controller published in advance. It
records what happened, whether it breached the policy, whether the agent was
under an attacker's control, misconfigured, or let down by a tool or a
dependency, how severe it was, who is responsible, what remediation is
required, and what compensation or bounty the controller's posted funds owe.
Other contracts read one view, `agent_security_status`, to decide whether to
trust an agent.

This document is the specification the contract implements. Symbols are named
so they can be found in the source; there are no line numbers.

## The question, and who is allowed to answer which part

> Given a controller's frozen security policy, evidence whose provenance code
> can classify, and chain transactions every node reads for itself: did the
> agent breach the policy, why, how badly, and what does the controller owe?

| Part of the answer | Decided by | Why |
|---|---|---|
| Who each party is | code: the signing wallet | an account the contract records is the account that signed |
| Which policy version applies | code: the version in effect when the incident was filed | a controller cannot rewrite history after an incident |
| Whether evidence bytes are the committed bytes | code: sha256 before anything reads them | changed bytes are never read |
| Where each item comes from, and whose sphere that is | code: registered party origins and policy public sources | a declared issuer is a claim; the host is a fact |
| What a chain transaction did | code, from each node's own RPC read | the one fact neither reporter nor controller can mint |
| Spending-limit, counterparty and logging rules | code, from verified chain facts and committed records | a model never reads a number or a list that decides money |
| Secrets, hidden text, text aimed at the panel, trace gaps, reversed timestamps, stale or reused evidence | code | deterministic scans of verified bytes |
| Whether a written rule was breached, and whether an escalation rule authorised it | consensus of independent models | natural-language policy over heterogeneous records |
| Attacker control, misconfiguration, tool fault, dependency failure | consensus, with quotes | causal responsibility is a reading, not a lookup |
| Whether the conduct happened, harm occurred, exposure is ongoing, a vulnerability reproduced, a fix is verified | consensus, with quotes | same |
| Verdict, severity, responsibility shares, remediation, impact, confidence, compensation, bounty, report-bond outcome | code, from the agreed findings | no model output reaches an amount, a share or a severity |

## Parties

| Party | Registers with | Controls |
|---|---|---|
| Controller | `register_policy`, `register_agent` | its policy (versioned, on notice), its agent, its security bond and bounty pool, its own evidence, counter-reports and remediation reports |
| Agent wallet | `confirm_agent_wallet` | nothing else: it shows the declared operating wallet exists and answers for the agent |
| Tool provider | `register_tool` | its tool profile and origins; its evidence and counter-report when its tool is implicated |
| Reporter | `register_reporter` | its incidents and disclosures, its report bond, its evidence and appeals |
| Anyone | - | asking for adjudication, readjudication and remediation review; finalizing; closing a stalled incident; lifting an expired embargo; running adversarial cases; reading views |

Every recorded account is the transaction signer. An agent is registered by
the controller that owns its policy; a reporter cannot be the agent's
controller, its wallet, or the provider of the tool it implicates.

## Security policy

A policy is JSON with an exact key set, stored canonically and hashed into
`policy_hash` (`_parse_policy`, `_policy_hash`). Versions are immutable. A new
version, and a deactivation, take effect only after the activation delay of the
version in effect (`_notice_seconds`), so an incident filed during that notice
still binds the rules the agent was under; one pending version at a time.

| Field | Meaning |
|---|---|
| `rules` | 1-12 rules `{rule_id, kind, text, severity 1-5}` plus, per kind, `data_class`, `tool_id`, `required_categories`, `limit_atto` or `counterparties` |
| `allowed_actions` | what the agent is explicitly allowed to do (context for the panel) |
| `escalation_rules` | 0-4 `{rule_id, text}`: when an otherwise restricted action is authorised |
| `data_classes` | 0-8 `{class_id, sensitivity 0-4}` referenced by `DATA_CLASS` rules |
| `external_dependencies` | 0-4 names of services the agent depends on |
| `public_sources` | 0-6 https path prefixes accepted as public evidence |
| `minimum_evidence_items`, `maximum_evidence_age_days` | evidence requirements |
| `response_window_seconds`, `appeal_window_seconds`, `stall_window_seconds`, `activation_delay_seconds`, `withdrawal_delay_seconds`, `confidentiality_max_seconds` | wall-clock windows |
| `report_bond_atto` | the exact bond a reporter posts (0 to `REPORT_BOND_CAP`) |
| `max_compensation_atto`, `min_compensable_severity`, `compromise_liability_bps` | compensation bounds |
| `bounty_tiers_atto` | six non-decreasing amounts indexed by severity 0-5; tier 0 is 0 |
| `high_value_atto` | agent-wallet value at or above which financial impact raises severity |

Rule kinds (`_plan`):

- `FORBIDDEN_ACTION`, `RESTRICTED_ACTION`, `DATA_CLASS` and `TOOL_PERMISSION` are
  read by the panel.
- `SPENDING_LIMIT` and `COUNTERPARTY_ALLOWLIST` are decided by code from verified
  transactions the agent's declared wallet sent (`_chain_rule_finding`); with no
  such transaction the rule is `UNVERIFIABLE`. A policy with either kind needs the
  agent's wallet declared.
- `LOGGING_REQUIREMENT` is breached by code when, for some category the rule
  names, no eligible record of that category came from the controller's own
  origin; otherwise the panel reads it.
- With no eligible evidence at all, every panel-read rule is `UNVERIFIABLE` by code.

## Money

All amounts are atto (1 GEN = 10^18). Value enters through three payable
methods and leaves through one pull-payment `withdraw`.

| Fund | Paid in by | Reserved when | Paid out to |
|---|---|---|---|
| Security bond (per agent) | controller, `post_security_bond` | an INCIDENT is filed: `min(claim, max_compensation_atto, free bond)` | the reporter as compensation at finalization; the controller after a delayed withdrawal |
| Bounty pool (per agent) | controller, `fund_bounty_pool` | a DISCLOSURE is filed: `min(bounty_tiers_atto[5], free pool)` | the reporter as a bounty at finalization; the controller after a delayed withdrawal |
| Report bond (per incident) | reporter, `open_incident` | at filing | back to the reporter, or to the controller on `FALSE_POSITIVE` or `REJECTED` |

- A reservation is made at filing, so concurrent incidents never over-commit a fund.
- A withdrawal request does not shrink what incidents can reserve; one per fund may
  be pending, and it completes after `withdrawal_delay_seconds` from whatever is then
  unreserved (`request_withdrawal`, `complete_withdrawal`). A request not completed
  within one further delay lapses, so no controller keeps a standing request to empty
  its bond the moment it sees an incident coming.
- A payable method that refuses a deposit never raises when value was sent. StudioNet
  credits the value of a payable transaction that raises to the contract with no
  ledger entry behind it, so the deposit is credited back to the sender and the
  refusal recorded (`_return_deposit`, `get_returned_deposits`).

| Terminal state | Security bond | Bounty pool | Report bond |
|---|---|---|---|
| `FINALIZED` with compensation | reservation released; compensation to the reporter | untouched | returned |
| `FINALIZED` with a bounty | untouched | reservation released; bounty to the reporter | returned |
| `FINALIZED` `FALSE_POSITIVE` or `REJECTED` | reservation released | reservation released | to the controller |
| `FINALIZED`, any other settling verdict | reservation released | reservation released | returned |
| `CLOSED_UNRESOLVED` (a stall exit) | reservation released | reservation released | returned |

Conservation, asserted by the tests and the live run:
`bonds + bounty pools + held report bonds + claimable credits = paid in - withdrawn`.

## Incident lifecycle

```text
open_incident (registered reporter, exact report bond, reservation)
  -> OPEN --------------------------------------------------------------+
       submit_evidence (reporter / controller / implicated tool)        |
       submit_counterreport (controller, and the tool provider when a   |
                             tool is implicated) -> RESPONDED           |
  request_adjudication (the reporter: at once when RESPONDED; anyone:  |
                        after the response window)                      |
  -> ADJUDICATED (record AD-nnnnnn; the appeal window opens)            |
       submit_appeal (a party, in the window, naming the standing       |
                      record and 1-3 items it committed since)          |
       request_readjudication (anyone) -> ADJUDICATED (a new record     |
                      naming what changed; a new appeal window)         |
  finalize_incident (anyone, after the window, settling record)         |
  -> FINALIZED (money moves; a violation-class or containment verdict   |
                opens a finding on the agent's standing)                |
       submit_remediation_report (controller, 1-4 remediation items) +  |
       request_remediation_review (anyone) -> VERIFIED clears it        |
  close_stalled_incident (anyone, wall clock) -> CLOSED_UNRESOLVED <----+
```

An incident is adjudicated at most `MAX_ADJUDICATIONS` times: the first round and
two readjudications. The appealed record is never modified, and a readjudication must
read again everything the appealed round read (`_unread_since`): evidence is hash-bound,
so nobody can change what the first panel saw, but a party can stop serving it, and a
round without it would judge less than the record it replaces. Until every such item is
served again the readjudication does not run; if it never is, the appeal lapses and
the appealed record stands.

Every non-terminal state has a permissionless wall-clock exit
(`close_stalled_incident`):

| State | Exit | Rule |
|---|---|---|
| `OPEN` / `RESPONDED`, never adjudicated | after the response window and the stall window | reservations released, report bond returned |
| `ADJUDICATED` with an appeal nobody heard | after the stall window from the appeal's filing | the appeal lapses and the appealed record stands: it settles if it settles, otherwise everything is released |
| `ADJUDICATED` with a holding verdict | after the appeal window and the stall window | reservations released, report bond returned |
| `ADJUDICATED` with a settling verdict | `finalize_incident` after the appeal window | settles; closing is refused |
| A finding under remediation | none needed | it stays on the agent's standing; up to `MAX_REMEDIATION_REVIEWS` reports |

## Evidence

An item is `{source_type, source_locator, content_hash, source_identity,
observed_at, agent_trace_reference, description, access_constraints}` plus, for a
chain transaction, `{anchor_chain, anchor_tx}` and no locator (`submit_evidence`).
It is admitted only if the submitter is a party to the incident; the locator is
https, passes URL hygiene (`_url_parts`) and sits under a registered origin of the
incident's parties or a public source of its policy (`_origin_of`); no text field
carries a credential, personal data, an instruction to the adjudicator or hidden
text (`_write_text_error`); `observed_at` is not in the future; and the same bytes,
location or transaction is not already committed to the incident. Each party
commits at most `MAX_ROLE_EVIDENCE` items to a case and its appeals. An item joins
the case before the first adjudication, the appeal while the incident is
adjudicated, and the remediation after a finding is finalized.

Categories: `AGENT_TRACE`, `TOOL_CALL_LOG`, `API_RECEIPT`, `ACCESS_RECORD`,
`AUDIT_LOG`, `SYSTEM_ALERT`, `REMEDIATION_TEST` (structured JSON, strict schemas
in `_structured_facts`); `POLICY_DOCUMENT`, `THREAT_INTEL`, `VULNERABILITY_REPORT`,
`USER_REPORT`, `TIMESTAMPED_FILE`, `ATTACK_ARTIFACT` (text); and
`CHAIN_TRANSACTION`. There is no screenshot category: the contract reads text.

### Origins and spheres

Each item's origin class is recorded at submission: `REPORTER`, `CONTROLLER`,
`TOOL`, `PUBLIC` (by the longest registered prefix that serves the locator) or
`CHAIN`. A sphere is every origin a party chose before the incident
(`OWN_SPHERE`): the reporter's sphere is its own origins; the controller's is its
own origins, the policy's public sources and the agent's tools, because it wrote
the one and picked the others and a host it controls can sit behind any of them.
A chain record is in nobody's sphere.

### At every round, on every node

1. Fetch each item and verify sha256 before reading it; read each cited
   transaction from the fixed `ANCHOR_CHAINS` registry (`_read_chain`).
2. Read structured facts in code and render each verified transaction as short
   code-written text the panel can quote (`_chain_text`).
3. Scan in code (`_scan`, `_code_indicators`, `_registry_hits`):

| Indicator | Meaning | Effect |
|---|---|---|
| `EVIDENCE_UNLINKED` | a structured record for another agent, or text naming other agents and not this one | excluded |
| `DUPLICATE_EVIDENCE` | the same bytes or transaction again | the later copy excluded |
| `HIDDEN_TEXT` | invisible characters or hiding styles (not in an `ATTACK_ARTIFACT`) | excluded |
| `ADJUDICATOR_MARKER` | text addressed to the adjudication | excluded, and counted as manipulation by its submitter |
| `SECRET_EXPOSURE` | a credential or personal data in the bytes | excluded, text withheld, `ROTATE_CREDENTIALS` required |
| `STALE_EVIDENCE` | a structured record dated further before the incident than the policy allows | excluded |
| `TRACE_SEQUENCE_GAP` / `TRACE_TIME_REVERSAL` | a trace, tool-call log or audit log skips entries or runs backwards | excluded |
| `SOURCE_IDENTITY_MISMATCH` | the declared issuer, or the issuer inside a structured record, names an incident party other than the one whose origin served the bytes, and does not name that party | excluded |
| `ANCHOR_NOT_FOUND` | a cited transaction does not exist or failed | excluded |
| `CROSS_CASE_REUSE` (registry) | bytes or a transaction an earlier incident on the same agent committed as a record of an event, whatever the item is declared as now; an incident that closed unresolved or finalized `REJECTED` decided nothing and does not count | excluded; a replay of a finalized incident's records, relabelled or not, is `REJECTED` |

An excluded item is shown to the panel without its text (`EXCLUDED_TEXT`).

### Who carries an unreadable item

`_holding_ids`: each party keeps its own records available, and an item is the
party's whose registered origin serves it, whoever cited it. A respondent's item
that is unreachable, changed or never finalized counts for nothing, so no
respondent can stall a case by taking its host down - including a record of its
own that the reporter cited. The reporter carries the burden of proof, so an item
from the reporter's origins in that state holds the case at `SOURCE_UNAVAILABLE`;
a chain registry that does not answer holds whoever cited it. Oversized or malformed bytes are excluded whoever committed them.

## The panel

Asked only what code cannot decide (`_plan`, `_panel_blob`):

| Subject | States | Asked |
|---|---|---|
| each alleged rule code did not decide | `VIOLATED`, `NOT_VIOLATED`, `AUTHORIZED_EXCEPTION`, `UNCLEAR_POLICY`, `UNVERIFIABLE` | always |
| `REPORTED_ACTION_OCCURRED` | `PRESENT`, `ABSENT`, `UNDETERMINED` | incidents |
| `AGENT_UNDER_EXTERNAL_CONTROL`, `CONTROLLER_MISCONFIGURATION` | same | incidents |
| `TOOL_FAULT` | same | incidents implicating a tool |
| `EXTERNAL_DEPENDENCY_FAILURE` | same | incidents under a policy with dependencies |
| `MATERIAL_HARM` | same | incidents |
| `ONGOING_EXPOSURE` | same | incidents and disclosures |
| `EVIDENCE_TAMPERING`, `ADJUDICATOR_INJECTION` | same | always |
| `VULNERABILITY_REPRODUCED` | same | disclosures |
| `REMEDIATION_VERIFIED` | same | remediation reviews |

Every decided state carries quotes each validator re-grounds in its own verified
bytes (`_quote_grounded`). **The party-interest rule** (`_support_satisfies`): a
finding that favours a party must quote at least one item from outside that
party's sphere. `VIOLATED`, harm, ongoing exposure, misconfiguration and a present
action or reproduction favour the reporter; `NOT_VIOLATED`, an authorised
exception, attacker control, a tool fault, a dependency failure, a verified fix
and an absent action or reproduction favour the controller. The prompt spells the
rule out as evidence ids per state (`_quote_from`). A party's admission against
its own interest is good support; its self-serving record is not; and each floor
has its mirror test. One subject also needs a kind of record (`SUPPORT_CATEGORIES`,
`_support_met`): a `CONTROLLER_MISCONFIGURATION` finding counts only quotes from
tool-call logs, access records and audit logs, because that an agent was able to act is
its conduct, not a record of how it was configured - and only structured categories,
because their schema is checked, where a text category is only a label. A
`REMEDIATION_VERIFIED` finding counts only quotes from remediation test results.

**Manipulation is attributed to the party that controls the bytes**
(`_manipulated_ids`, `_authors_of`, `_discounted`): text aimed at the adjudication
found by code, and tampering or panel-steering found by the panel on the items its
finding quotes. The owner is the party whose registered origin served the item, so a
reporter who cites the controller's own steering statement has steered nothing; a
public source or a chain record belongs to no party. A reporter who submitted manipulated items is
`REJECTED`; a respondent's manipulated items stop supporting anything and the
case proceeds; manipulation on both sides is `CONFLICTING_EVIDENCE`.

**A cause is the controller's to show.** Attacker control, a tool fault and a
dependency failure each shift a proven violation away from the controller, so an
undecided cause holds nothing: one the evidence does not support is not
established, and the violation stays the controller's.

## Derivation (pure code, `_derive`)

Precedence, first match wins:

1. every reporter record replays evidence a finalized incident settled on -> `REJECTED`
2. a reporter item unreachable or changed, or a chain unreadable -> `SOURCE_UNAVAILABLE`
3. the panel's answer unusable -> `INCONCLUSIVE`
4. both sides submitted manipulated items -> `CONFLICTING_EVIDENCE`
5. the reporter submitted manipulated items -> `REJECTED`
6. fewer eligible items than the policy requires -> `INSUFFICIENT_EVIDENCE`
7. an alleged rule the policy is too vague to decide -> `INCONCLUSIVE`
8. a rule violated while the action is found not to have happened, or a disclosure whose reproduction is not established -> `INCONCLUSIVE`
9. a rule violated -> `CONFIRMED_COMPROMISE` (attacker control) / `LIKELY_MISCONFIGURATION` / `LIKELY_EXTERNAL_FAILURE` (tool fault or dependency failure) / `CONFIRMED_VIOLATION`, checked in that order; a disclosure -> `CONFIRMED_VULNERABILITY`
10. an incident with no rule violated, attacker control and ongoing exposure -> `REQUIRES_CONTAINMENT`
11. the action did not occur, or the vulnerability did not reproduce -> `FALSE_POSITIVE`
12. it occurred (reproduced) and every alleged rule is clear or authorised -> `POLICY_COMPLIANT`
13. whether it occurred is undecided -> `INCONCLUSIVE`
14. otherwise -> `INSUFFICIENT_EVIDENCE`

Holding verdicts - `INSUFFICIENT_EVIDENCE`, `CONFLICTING_EVIDENCE`,
`SOURCE_UNAVAILABLE`, `INCONCLUSIVE` - move no money and cannot be finalized.

**Severity** (`_severity`, 0-5): for a violation-class verdict, the heaviest violated
rule's weight (a data-class rule weighs at least its class sensitivity plus one),
+1 for material harm or agent-wallet value at or above `high_value_atto`, +1 for
ongoing exposure; `REQUIRES_CONTAINMENT` is 3 (+1 for harm); `POLICY_COMPLIANT` is 1;
everything else 0. A record resting on one sphere's items caps at 3. The factors
are stored with the record (`severity_factors`).

**Responsibility** (`_responsibility`, basis points summing to 10000):

| Verdict | Allocation |
|---|---|
| `CONFIRMED_VIOLATION`, `LIKELY_MISCONFIGURATION`, `CONFIRMED_VULNERABILITY` | controller 10000 |
| `CONFIRMED_COMPROMISE` | controller `max(compromise_liability_bps, 5000 if misconfigured)`, tool provider 5000 if at fault (capped), attacker the rest |
| `LIKELY_EXTERNAL_FAILURE` | tool provider 10000 if at fault, otherwise external 10000 |
| `REQUIRES_CONTAINMENT` | unassigned 10000 |
| everything else | none |

**Remediation** (`_remediation`), **impact** (`_impact`) and **confidence**
(`_confidence`) are fixed tables; see [`severity-model.md`](severity-model.md) and
[`remediation.md`](remediation.md).

**Compensation** = `reserved_compensation * controller_bps / 10000`, only for an
INCIDENT whose verdict is `CONFIRMED_VIOLATION`, `CONFIRMED_COMPROMISE` or
`LIKELY_MISCONFIGURATION`, with material harm, severity at least
`min_compensable_severity`, and a controller share. **Bounty** = `bounty_tiers_atto[severity]`, capped by the
reservation, only for `CONFIRMED_VULNERABILITY`. **Report bond**: forfeited on
`FALSE_POSITIVE` and `REJECTED`, returned otherwise.

## Consensus

`gl.vm.run_nondet_unsafe` once per adjudication, readjudication, remediation
review or adversarial case (`_run_round`). Each validator reproduces the round from
its own fetches, RPC reads and model call (`_node_round`), runs the structural gate
on the leader's payload against its own bytes (`_parse_payload`), then compares
what was read - every row, fact, chain fact and scan, and the panel state
(`_evidence_difference`) - and the consequence each side's findings lead to
(`_consequence_difference`): verdict, severity, responsibility, remediation, impact,
confidence, compensation and bounty eligibility, report bond, containment,
corroboration, and on a settling record the rules a confirmed finding rests on and
who manipulated it. Indicator shadings, notes and quote choice are recorded, never
compared. Full detail in [`consensus.md`](consensus.md).
