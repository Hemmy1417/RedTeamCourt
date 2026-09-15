# Integration

RedTeam Court is a primitive: an agent marketplace, a payment router, a wallet
policy engine or another Intelligent Contract reads it before trusting an agent. A
consumer needs one view and none of the machinery - no web access, no prompts, no
equivalence rule, no parsing of evidence.

## The one read a consumer needs

`agent_security_status(agent_id, as_of)` answers "should I trust this agent now?" in
one call. A view has no clock, so the caller passes one: an ISO-8601 UTC timestamp,
ideally the chain's own time.

Captured from the Direct Mode suite, while Harbor Supplies' incident was open:

```json
{"found": true, "agent_id": "AGT-000001", "as_of": "2026-09-15T12:00:10Z",
 "standing": "UNDER_INVESTIGATION",
 "policy_id": "SP-000001", "policy_version_in_effect": 1,
 "policy_hash": "6861fca0cee7fc1db575152c3253d275e1ff0a99f2e7cc76fd1eb7185e587d6a",
 "agent_wallet": "0x7d2355281d516af9e489e8526e127fd8c29cface", "wallet_confirmed": true,
 "open_incident_ids": ["IN-000001"], "open_finding_ids": [],
 "max_open_severity": 0, "containment_required": false, "required_remediation": [],
 "verified_remediations": 0,
 "security_bond_atto": "500000000000000000",
 "security_bond_unreserved_atto": "400000000000000000",
 "bounty_pool_atto": "300000000000000000",
 "bounty_pool_unreserved_atto": "300000000000000000",
 "withdrawal_pending": false}
```

and after the compromise finalized:

```json
{"standing": "CONTAINMENT_REQUIRED",
 "open_incident_ids": [], "open_finding_ids": ["IN-000001"],
 "max_open_severity": 5, "containment_required": true,
 "required_remediation": ["ROTATE_CREDENTIALS", "ISOLATE_AGENT", "RETEST_BEFORE_RESTORE"],
 "security_bond_atto": "450000000000000000",
 "security_bond_unreserved_atto": "450000000000000000"}
```

| `standing` | Meaning | A cautious consumer |
|---|---|---|
| `IN_GOOD_STANDING` | a policy is in effect, nothing open | proceeds |
| `UNDER_INVESTIGATION` | an incident is open; nothing is decided | proceeds with limits, or waits |
| `REMEDIATION_REQUIRED` | a finalized finding is not yet verified fixed | restricts what it routes to the agent |
| `CONTAINMENT_REQUIRED` | a finalized finding requires isolating the agent | stops |
| `NO_ACTIVE_POLICY` | the controller has no policy in effect | treats the agent as unaccountable |

## From another contract

```python
court = gl.get_contract_at(Address(REDTEAM_COURT_ADDRESS))
status = court.view().agent_security_status(agent_id, gl.message_raw["datetime"])
if not status["found"] or status["standing"] in ("CONTAINMENT_REQUIRED",
                                                 "NO_ACTIVE_POLICY"):
    raise gl.vm.UserError("[EXPECTED] the agent is not trusted by RedTeam Court")
if status["max_open_severity"] >= 4:
    ...   # e.g. cap what this contract lets the agent move
```

Gate on `standing`, `containment_required` and `max_open_severity`, never on an
amount or a free-text field; pin `policy_hash` if the consumer only trusts a policy it
has reviewed.

## Three consumers

| Consumer | Question it asks | Fields it reads |
|---|---|---|
| an agent marketplace | may this agent take new work? | `standing`, `max_open_severity`, `security_bond_unreserved_atto` |
| a payment router or treasury contract | may this agent's wallet move funds through me? | `standing`, `containment_required`, `agent_wallet`, `wallet_confirmed` |
| an insurer or a counterparty setting terms | how much of this agent's risk is backed? | `security_bond_unreserved_atto`, `bounty_pool_unreserved_atto`, `verified_remediations`, `policy_hash` |

## The flow, in calls

| Step | Call | Who |
|---|---|---|
| 1 | `register_policy(policy_json)` -> `SP-nnnnnn` | controller |
| 2 | `register_tool(tool_json)` -> `TL-nnnnnn` | tool provider |
| 3 | `register_agent(agent_json)` -> `AGT-nnnnnn` | the policy's owner |
| 4 | `confirm_agent_wallet(agent_id)` | the agent's wallet |
| 5 | `post_security_bond(agent_id)`, `fund_bounty_pool(agent_id)` **payable** | controller |
| 6 | `register_reporter(reporter_json)` | reporter, once |
| 7 | `open_incident(agent_id, policy_version, incident_json)` **payable, exactly the report bond** -> `IN-nnnnnn` | reporter |
| 8 | `submit_evidence(incident_id, ...)` -> `EV-nnnnnn` | reporter, controller, implicated tool's provider |
| 9 | `submit_counterreport(incident_id, statement)` | controller, tool provider |
| 10 | `request_adjudication(incident_id)` -> `AD-nnnnnn` | **anyone**: at once when every respondent answered, otherwise after the response window |
| 11 | `submit_appeal(incident_id, adjudication_id, reason, new_evidence_ids)` -> `AP-nnnnnn` | a party, inside the appeal window |
| 12 | `request_readjudication(appeal_id)` -> `AD-nnnnnn` | **anyone** |
| 13 | `finalize_incident(incident_id)` | **anyone**, after the appeal window, on a settling record |
| 13' | `close_stalled_incident(incident_id)` | **anyone**, on the wall clock |
| 14 | `submit_remediation_report(incident_id, statement, evidence_ids)` | controller |
| 15 | `request_remediation_review(incident_id)` -> `AD-nnnnnn` | **anyone** |
| 16 | `lift_disclosure_embargo(incident_id)` | **anyone**, once the embargo has passed |
| 17 | `withdraw()` | any wallet with a credit |
| - | `request_withdrawal(agent_id, fund, amount_atto)`, `complete_withdrawal(agent_id, fund)` | controller |
| - | `publish_policy_version(policy_id, policy_json)`, `deactivate_policy(policy_id)` | the policy's owner |
| - | `register_adversarial_case(...)`, `run_adversarial_case(case_id)` | the policy's owner; **anyone** |

## Other reads

| Read | Returns |
|---|---|
| `incident_status(incident_id, as_of)` | which action is open to whom now: `can_request_adjudication`, `reporter_can_request_adjudication`, `appeal_window_open`, `can_finalize`, `can_close_stalled`, `can_report_remediation`, `can_request_remediation_review`, `embargo_liftable` |
| `get_incident(incident_id)` | the incident, its parties, windows, reservations, verdict, payments and remediation state; a disclosure's text is withheld until its embargo lifts |
| `get_adjudication(id)`, `get_latest_adjudication(incident_id)` | the full record: findings, receipts, reason codes, severity factors, responsibility, remediation, payment advice, `record_digest` |
| `get_incident_history(incident_id, offset, limit)` | the ids of every record for the incident in the order written: adjudications and readjudications, then remediation reviews |
| `get_evidence(evidence_id)`, `get_appeal(appeal_id)` | what was committed and argued |
| `get_policy(policy_id, version)` | a version, its hash and when it binds; version 0 reads the latest |
| `get_agent`, `get_tool`, `get_reporter` | profiles, funds, a reporter's upheld, false-positive and rejected counts |
| `list_agent_incidents(agent_id, offset, limit)` | paged incident ids |
| `get_claimable(wallet)`, `get_returned_deposits(offset, limit)` | the ledger |
| `get_adversarial_case(id)`, `list_adversarial_cases(policy_id, version, offset, limit)` | the test engine |
| `get_config()`, `health_check()`, `get_stats()` | every enum and bound, the equivalence statement, counts and funds held |

Every list is paged (at most `PAGE_LIMIT`); no view scans an unbounded collection.

## What a caller must get right

- **Amounts are atto-GEN strings.** JSON numbers cannot carry 10^18 safely.
- **Evidence must be served when a round runs.** The bytes at a committed location must
  hash to the commitment when every validator fetches them; a reporter's host that
  changes them holds the case.
- **Before the response deadline only the reporter can request the adjudication**, and
  only once every respondent has answered (`reporter_can_request_adjudication`); after
  it, anyone can (`can_request_adjudication`).
- **A reporter's registered name must not overlap the agent's, controller's or tool's
  name.** `open_incident` returns the report bond with the reason when it does.
- **A round is a transaction, not a view.** Poll `incident_status` rather than
  re-sending `request_adjudication`.
- **Held is not refused.** A holding verdict means "not decided yet": an appeal or the
  stall exit decides it, and nothing has moved.
- **Standing is advice.** RedTeam Court records findings; it never blocks an agent. The
  consumer decides what a standing means for it.

## What RedTeam Court does not do

It does not monitor agents, detect incidents, execute remediation, price risk, or hold
anything but native GEN. It adjudicates what a reporter files against a policy the
controller published, from evidence the parties commit and chain records every node
reads.
