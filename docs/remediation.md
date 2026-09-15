# Remediation, responsibility and payment

RedTeam Court records what must be remediated and who is responsible; it executes
nothing. No method revokes a permission, rotates a key or isolates an agent. The
record is a recommendation other systems act on, and `agent_security_status` is how
they read it.

## Remediation classes

| Class | Means |
|---|---|
| `MONITOR` | keep watching; nothing needs to change |
| `RESTRICT_TOOL` | narrow what the agent may do through a tool |
| `REVOKE_PERMISSION` | withdraw a grant the conduct used |
| `ROTATE_CREDENTIALS` | replace credentials that were used by an attacker or exposed in evidence |
| `PATCH_POLICY` | rewrite a rule too vague to decide |
| `RETRAIN_OR_RECONFIGURE` | change how the agent behaves |
| `ISOLATE_AGENT` | take the agent out of service |
| `REQUIRE_HUMAN_REVIEW` | put a person in the loop for this kind of action |
| `DISCLOSE_VULNERABILITY` | publish the confirmed weakness once it is safe to |
| `RETEST_BEFORE_RESTORE` | prove the fix before the agent returns |

`_remediation` maps an outcome to classes, listed in `REMEDIATION_CLASSES` order:

| Outcome | Classes |
|---|---|
| `CONFIRMED_VIOLATION` | `RETRAIN_OR_RECONFIGURE`, plus per violated rule: `REVOKE_PERMISSION` (forbidden, restricted, data-class), `RESTRICT_TOOL` (tool permission), `REQUIRE_HUMAN_REVIEW` (spending limit, counterparty), `MONITOR` (logging) |
| `CONFIRMED_COMPROMISE` | `ROTATE_CREDENTIALS`, `ISOLATE_AGENT`, `RETEST_BEFORE_RESTORE` |
| `LIKELY_MISCONFIGURATION` | `REVOKE_PERMISSION`, `RETRAIN_OR_RECONFIGURE`, `RETEST_BEFORE_RESTORE` |
| `LIKELY_EXTERNAL_FAILURE` | `REQUIRE_HUMAN_REVIEW`, and `RESTRICT_TOOL` for a tool fault or `MONITOR` for a dependency |
| `CONFIRMED_VULNERABILITY` | `RETRAIN_OR_RECONFIGURE`, `DISCLOSE_VULNERABILITY`, `RETEST_BEFORE_RESTORE` |
| `REQUIRES_CONTAINMENT` | `ISOLATE_AGENT`, `REQUIRE_HUMAN_REVIEW`, `RETEST_BEFORE_RESTORE` |
| `POLICY_COMPLIANT` | `MONITOR` |
| `INCONCLUSIVE` on a rule too vague to decide | `PATCH_POLICY` |
| any violation-class verdict with ongoing exposure | adds `ISOLATE_AGENT` |
| a credential or personal data found in any submitted evidence, whatever the verdict | adds `ROTATE_CREDENTIALS` |

`containment_required` is true exactly when `ISOLATE_AGENT` is in the set.

## Responsibility

`_responsibility` allocates basis points that sum to 10000, or nothing:

| Verdict | Allocation |
|---|---|
| `CONFIRMED_VIOLATION`, `LIKELY_MISCONFIGURATION`, `CONFIRMED_VULNERABILITY` | `CONTROLLER` 10000 |
| `CONFIRMED_COMPROMISE` | `CONTROLLER` the policy's `compromise_liability_bps`, raised to 5000 when the controller misconfigured the agent; `TOOL_PROVIDER` 5000 when the tool was at fault, never more than what is left; `ATTACKER` the rest |
| `LIKELY_EXTERNAL_FAILURE` | `TOOL_PROVIDER` 10000 for a tool fault, otherwise `EXTERNAL` 10000 |
| `REQUIRES_CONTAINMENT` | `UNASSIGNED` 10000 |
| everything else | none |

The controller commits to its compromise liability in the policy before any incident,
so a compromise is never argued down to nothing after the fact. A cause that shifts
responsibility away from the controller - attacker control, a tool fault, a dependency
failure - must be supported from outside the controller's own sphere; an undecided one
shifts nothing.

## Compensation and bounties

- **Reserved at filing.** An incident reserves `min(claim, max_compensation_atto,
  unreserved bond)`; a disclosure reserves `min(bounty_tiers_atto[5], unreserved pool)`
  (`open_incident`). A payment can never exceed its reservation, and `_settle` refuses
  to run if it would.
- **Compensation** is `reserved * controller_bps / 10000`, only for an incident whose
  verdict is `CONFIRMED_VIOLATION`, `CONFIRMED_COMPROMISE` or `LIKELY_MISCONFIGURATION`,
  with material harm, severity at least `min_compensable_severity`, and a controller
  share (a policy may commit a compromise liability of 0).
- **A bounty** is `bounty_tiers_atto[severity]`, capped by the reservation, only for
  `CONFIRMED_VULNERABILITY`.
- **The report bond** goes to the controller on `FALSE_POSITIVE` or `REJECTED`, and back
  to the reporter otherwise.
- **Once.** Money moves only when an incident finalizes (`_settle`), whole or not at
  all; an incident finalizes once; and the records a finalized incident settled on
  cannot win another: the registry keys bytes and transactions, not declared
  categories, so a filing whose reporter records all replay them is `REJECTED` even
  when they are relabelled (`_registry_hits`).
- **Pull payment.** Payments are credits; each wallet calls `withdraw`, which clears
  its credit before the transfer.
- **Nothing on a held verdict.** A holding verdict cannot be finalized; its exit is an
  appeal or `close_stalled_incident`, which releases every reservation and returns the
  report bond.

## Remediation lifecycle

A finalized violation-class or containment verdict opens a finding on the agent's
standing (`remediation_status` `REQUIRED`).

1. Any party commits remediation evidence to the finalized incident
   (`submit_evidence`; phase `REMEDIATION`), each within its own bound.
2. The controller reports the fix, naming 1 to `MAX_REMEDIATION_EVIDENCE` items no
   review has read (`submit_remediation_report`). A report is a claim.
3. Anyone asks for a review (`request_remediation_review`): one consensus round over
   the named items, asking `REMEDIATION_VERIFIED`, `EVIDENCE_TAMPERING` and
   `ADJUDICATOR_INJECTION`.
4. `_derive_remediation` decides:

| Condition, first match | Review verdict |
|---|---|
| a named item unreadable in the way that holds | `SOURCE_UNAVAILABLE` |
| the model's answer unusable | `INCONCLUSIVE` |
| manipulated items | `CONFLICTING_EVIDENCE` |
| no eligible `REMEDIATION_TEST` among the items | `INSUFFICIENT_EVIDENCE` |
| the panel finds the fix verified, on support from outside the controller's sphere | `VERIFIED` |
| the panel finds it not verified | `NOT_VERIFIED` |
| otherwise | `INCONCLUSIVE` |

`VERIFIED` clears the finding from the agent's standing; any other verdict returns it
to `REQUIRED` for another report, up to `MAX_REMEDIATION_REVIEWS`. Patch notes alone are
never verification, and the controller's own test results cannot verify its own fix:
the reporter's retest, or another source outside the controller's sphere, has to carry
it.

## Standing

`agent_security_status(agent_id, as_of)` reads, first match:

| Standing | When |
|---|---|
| `NO_ACTIVE_POLICY` | no policy version is in effect at `as_of` |
| `CONTAINMENT_REQUIRED` | an open finding requires `ISOLATE_AGENT` |
| `REMEDIATION_REQUIRED` | an open finding is not yet verified |
| `UNDER_INVESTIGATION` | an incident is neither finalized nor closed |
| `IN_GOOD_STANDING` | none of the above |

It also returns the open incident and finding ids, the highest open severity, the union
of required remediation, the number of verified remediations and the funds behind the
agent.

## The brief's rules, and where the code keeps them

| Rule | Kept by |
|---|---|
| never execute destructive remediation | no method acts on an agent; remediation is a list in a record |
| never expose secrets in the result | secrets are refused at every write, evidence carrying them is excluded and its text withheld, and quotes pass a secret scan (`_write_text_error`, `_scan`, `_valid_finding_shape`) |
| never compensate beyond the configured bounty or escrow | reservations at filing, the reservation check in `_settle` |
| never finalize severe outcomes when evidence is unavailable | an unreadable reporter item holds at `SOURCE_UNAVAILABLE`; holding verdicts cannot be finalized |
| preserve the original incident and policy version | the incident binds the version in effect at filing; records are stored once (`_store_record`) and a readjudication writes a new one |
| distinguish recommendation from execution | `required_remediation` is data |
| prevent duplicate bounty or compensation claims | one finalization per incident; replays of settled records are `REJECTED` |
| use `INCONCLUSIVE` or `SOURCE_UNAVAILABLE` when fault cannot be established safely | the derivation's holding verdicts |
