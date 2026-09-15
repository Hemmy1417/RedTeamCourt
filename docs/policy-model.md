# Security policy

A controller publishes a security policy before anything can be alleged against its
agent. The policy is the whole standard: nothing in the evidence, a party's statement
or a model's reading adds a rule or removes one. `_parse_policy` validates it; the
canonical JSON is stored and hashed with its id, version and owner into `policy_hash`
(`_policy_hash`), which every record of every incident under that version carries.

## Fields

Exactly these keys (`POLICY_KEYS`); anything missing or extra is refused.

| Field | Bounds | Used for |
|---|---|---|
| `name`, `description` | 80 and 400 characters | display |
| `rules` | 1 to `MAX_RULES` (12), ids `R1`-`R99` | the standard; see below |
| `allowed_actions` | up to 12 short entries | context the panel reads beside the rules |
| `escalation_rules` | up to 4 `{rule_id: X1-X9, text}` | when an otherwise restricted action is authorised |
| `data_classes` | up to 8 `{class_id, sensitivity 0-4}` | classes `DATA_CLASS` rules name; sensitivity raises a rule's weight |
| `external_dependencies` | up to 4 names | whether `EXTERNAL_DEPENDENCY_FAILURE` is asked |
| `public_sources` | up to 6 https path prefixes | public evidence the policy accepts; in the controller's sphere |
| `minimum_evidence_items` | 1 to 10 | fewer eligible items is `INSUFFICIENT_EVIDENCE` |
| `maximum_evidence_age_days` | 1 to 3650 | older structured records are `STALE_EVIDENCE`; older incidents cannot be filed |
| `response_window_seconds` | 60 s to 30 days | respondents' time to answer |
| `appeal_window_seconds` | 60 s to 30 days | time to appeal a record |
| `stall_window_seconds` | 60 s to 30 days | when a held incident may be closed |
| `activation_delay_seconds` | 60 s to 30 days | notice a new version or a deactivation must give |
| `withdrawal_delay_seconds` | 60 s to 30 days | delay on taking funds back |
| `confidentiality_max_seconds` | 0 to 30 days | longest embargo a disclosure may request |
| `report_bond_atto` | 0 to 10 GEN | the exact bond a reporter posts |
| `max_compensation_atto` | 0 to 10^24 | the most one incident can reserve |
| `min_compensable_severity` | 1 to 5 | below it, no compensation |
| `compromise_liability_bps` | 0 to 10000 | the controller's committed share of a compromise |
| `bounty_tiers_atto` | six non-decreasing amounts; tier 0 is 0 | the bounty per severity |
| `high_value_atto` | 1 to 10^24 | agent-wallet value that counts as financial impact |

Every amount is atto and every share basis points, so what a policy commits to is
integer arithmetic.

## Rules

Each rule is `{rule_id, kind, text, severity 1-5}` plus the fields its kind needs
(`RULE_KEYS`, `_rule_error`):

| Kind | Extra field | Decided by |
|---|---|---|
| `FORBIDDEN_ACTION` | - | the panel |
| `RESTRICTED_ACTION` | - | the panel, which may find an escalation rule authorised the conduct (`AUTHORIZED_EXCEPTION`) |
| `DATA_CLASS` | `data_class`, a declared class | the panel; weight at least the class's sensitivity plus one |
| `TOOL_PERMISSION` | `tool_id` | the panel |
| `LOGGING_REQUIREMENT` | `required_categories`, 1-4 structured categories | code when a named category is missing from what the controller's own origin served eligibly; otherwise the panel |
| `SPENDING_LIMIT` | `limit_atto` | code, from verified transactions the agent's declared wallet sent |
| `COUNTERPARTY_ALLOWLIST` | `counterparties`, 1-8 wallets | code, the same way |

A model never reads a limit, an allowlist or an amount that decides anything
(`_chain_rule_finding`).

For a rule the panel reads, the states are:

| State | Meaning | Consequence |
|---|---|---|
| `VIOLATED` | the evidence shows the conduct breached the rule | a finding against the agent |
| `NOT_VIOLATED` | the evidence shows it did not | clear |
| `AUTHORIZED_EXCEPTION` | the letter was breached, but an escalation rule authorised it and its condition was met | clear |
| `UNCLEAR_POLICY` | the conduct is shown, but the rule's text cannot decide it | `INCONCLUSIVE` and `PATCH_POLICY` |
| `UNVERIFIABLE` | the evidence cannot show what the agent did | counts against no one |

A rule too vague to decide never punishes: RC15 alleges R9, "The agent should behave
responsibly with sensitive operations", and holds at `INCONCLUSIVE`.

## Versions

- `register_policy` publishes version 1; it binds from that transaction. The owner is
  the signer.
- `publish_policy_version` adds a version that takes effect only after the activation
  delay of the version in effect (`_notice_seconds`). One pending version at a time,
  at most `MAX_VERSIONS`, owner only.
- `deactivate_policy` ends the policy after the same notice; terminal, owner only.
  Afterwards no incident can be filed and the agent's standing reads
  `NO_ACTIVE_POLICY`.
- An incident binds the version in effect when it is filed; the filing must name that
  version (`open_incident`), and every later round, appeal and remediation review reads
  the same version. A policy relaxed after an incident never reaches it (RC31,
  `tests/direct/test_policy_validation.py`).

## Agents and tools

- `register_tool` records a tool, its description and the origins its provider
  publishes from; the provider is the signer.
- `register_agent` is signed by the owner of the agent's policy, names registered
  tools, the controller's origins and, when the policy has spending or counterparty
  rules, the agent's operating wallet.
- `confirm_agent_wallet` is signed by that wallet once. It shows the wallet exists and
  answers for the agent; it does not show the agent uses no other.

## What the brief asks a policy to define

| Requirement | Where it lives |
|---|---|
| agent identity and controller | `register_agent`: the controller is the signer; the agent's name, controller name, origins and wallet |
| allowed tools | the agent's `allowed_tools`; `TOOL_PERMISSION` rules |
| allowed data classes | `data_classes`; `DATA_CLASS` rules |
| restricted and forbidden actions | `RESTRICTED_ACTION` and `FORBIDDEN_ACTION` rules; `allowed_actions` |
| spending or transaction limits | `SPENDING_LIMIT` and `COUNTERPARTY_ALLOWLIST` rules |
| authentication and authorization requirements | written into rules and escalation rules (the demo's X1: a vendor-confirmed ticket signed by a human approver); there is no separate field |
| logging requirements | `LOGGING_REQUIREMENT` rules |
| human-escalation conditions | `escalation_rules` |
| external dependency assumptions | `external_dependencies` |
| incident severity rules | each rule's `severity`, data-class sensitivity, `high_value_atto`, `min_compensable_severity`, `compromise_liability_bps`, `bounty_tiers_atto` |
| evidence requirements | `minimum_evidence_items`, `maximum_evidence_age_days`, `public_sources` |
| policy version and activation status | versions, activation delay, deactivation |

## Telling the cases apart

| Situation | How the record shows it |
|---|---|
| an explicit violation | a rule `VIOLATED`, no established cause: `CONFIRMED_VIOLATION` |
| an ambiguous rule | `UNCLEAR_POLICY`: `INCONCLUSIVE` with `PATCH_POLICY` |
| conduct no rule covers | only rules in the bound version can be alleged; a rule that does not cover the conduct is `NOT_VIOLATED` |
| a misconfiguration | `CONTROLLER_MISCONFIGURATION` present, shown by a record of configuration: `LIKELY_MISCONFIGURATION` |
| an external service failure | `TOOL_FAULT` or `EXTERNAL_DEPENDENCY_FAILURE` present: `LIKELY_EXTERNAL_FAILURE` |
| malicious control of the agent | `AGENT_UNDER_EXTERNAL_CONTROL` present: `CONFIRMED_COMPROMISE`, or `REQUIRES_CONTAINMENT` when no rule is proven but exposure continues |

The demo policy used by the fixtures, the Direct Mode suite and the live run is
`fixtures/world.json`.
