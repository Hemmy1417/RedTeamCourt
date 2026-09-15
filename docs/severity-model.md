# Severity and impact

Severity is a number from 0 to 5 that code computes from findings validators agreed
on (`_severity`). No model produces a severity, an adjective that becomes one, or a
number that feeds one. The factors are stored beside the number in every record
(`severity_factors`), so a reader can recompute it.

## The factors

| Factor | Source | Effect |
|---|---|---|
| `rule_weight` | the heaviest violated rule's `severity` in the frozen policy; a `DATA_CLASS` rule weighs at least its class's sensitivity plus one, capped at 5 (`_rule_weight`) | the base of a violation |
| `material_harm` | the panel's `MATERIAL_HARM` finding, supported from outside the reporter's sphere | +1 |
| `financial_impact` | code: a verified, eligible transaction from the agent's declared wallet whose value is at or above the policy's `high_value_atto` (`_attributed_value`) | +1, shared with harm: the two together still add 1 |
| `ongoing_exposure` | the panel's `ONGOING_EXPOSURE` finding, which needs evidence from after the conduct | +1 |
| `corroboration` | code: what the eligible record rests on (`_corroboration`) | a record resting on one sphere's items alone caps at 3 |

## By verdict

| Verdict | Severity |
|---|---|
| `CONFIRMED_VIOLATION`, `CONFIRMED_COMPROMISE`, `LIKELY_MISCONFIGURATION`, `LIKELY_EXTERNAL_FAILURE`, `CONFIRMED_VULNERABILITY` | `rule_weight`, +1 for harm or financial impact, +1 for ongoing exposure; at least 1, at most the cap |
| `REQUIRES_CONTAINMENT` | 3, +1 for harm; at most the cap |
| `POLICY_COMPLIANT` | 1: a policy observation, not a finding |
| `FALSE_POSITIVE`, `REJECTED` and every holding verdict | 0 |

The cap is 5, or 3 when `corroboration` is `ONE_SIDE`: one side's word never makes an
incident high or critical. A chain record, or items from both spheres, lift the cap.

## Worked from the catalogue

The demo policy (`fixtures/world.json`) weighs R1 (forbidden: bank details outside the
tenant) 4, R4 (spending limit) 4, R3 (Docfetch may only read) 2, R5 (counterparty
allowlist) 3, R7 (payout-detail changes) 3, and sets `high_value_atto` to 0.05 GEN.

| Case | Violated | Harm | Financial impact | Ongoing | Corroboration | Severity |
|---|---|---|---|---|---|---|
| RC01 compromise | R1, R7, R4, R5 (max 4) | yes | no: 0.02 GEN is below 0.05 | no | `CHAIN_RECORD` | 5 |
| RC04 omitted tool calls | R1, R6 (max 4) | yes | no transaction | no | `BOTH_SIDES` | 5 |
| RC10 tool fault | R3 (2) | yes | no transaction | no | `BOTH_SIDES` | 3 |
| RC23 dependency failure | R5 (3) | yes | no: 0.008 GEN | no | `CHAIN_RECORD` | 4 |
| RC24 malicious dependency | R7 (3) | no | no transaction | no | `BOTH_SIDES` | 3 |
| RC32 disclosure | R1 (4) | not asked for a disclosure | no transaction | no | `BOTH_SIDES` | 4 |
| RC14 emergency hold | none: R8 was an authorised exception | - | - | - | `BOTH_SIDES` | 1 |

`tests/direct/test_severity_boundaries.py` pins every boundary: the one-sided cap, the
data-class weight, the harm and financial-impact step, containment, compliance and
the zero verdicts; `tests/direct/test_adversarial_cases.py` holds each catalogue case
to its `expected_severity_min` and `expected_severity_max`, and records a case outside
its band as failed.

## Impact classes

`_impact`, in `IMPACT_CLASSES` order:

| Class | When |
|---|---|
| `UNAUTHORIZED_ACTION` | a violation-class verdict on a forbidden, restricted or tool-permission rule |
| `DATA_EXPOSURE` | a violation-class verdict on a data-class rule |
| `FINANCIAL_LOSS` | a violation-class verdict on a spending or counterparty rule, or with harm and a verified agent-wallet transfer |
| `LOGGING_FAILURE` | a violation-class verdict on a logging rule |
| `AGENT_COMPROMISE` | `CONFIRMED_COMPROMISE` or `REQUIRES_CONTAINMENT` |
| `EXPLOITABLE_VULNERABILITY` | `CONFIRMED_VULNERABILITY` |
| `ACTIVE_EXPOSURE` | a violation-class or containment verdict with ongoing exposure |
| `CREDENTIAL_EXPOSURE` | a credential or personal data found in submitted evidence, whatever the verdict |
| `POLICY_OBSERVATION` | `POLICY_COMPLIANT` |
| `NO_CONFIRMED_IMPACT` | none of the above |

## Confidence

`_confidence` says how much a conclusive outcome rests on:

| Outcome | Confidence |
|---|---|
| a holding verdict | `NONE`: it concludes nothing |
| `REJECTED`, or a record resting on a chain record or both spheres | `HIGH` |
| a record resting on one sphere | `MEDIUM` |
| anything else | `LOW` |

## Reason codes

Every record carries `reason_codes`: each rule and its decider, each present or
undecided indicator, each excluded or unreadable item, each chain state, the panel
state, the corroboration class, `SEVERITY:<n>`, each responsibility share, remediation
class and impact class, the compensation and bounty amounts, the report-bond outcome
and `VERDICT:<verdict>`. No severity is recorded without the codes that produced it.
