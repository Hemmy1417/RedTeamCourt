# Evidence

Every log, document, report, web page and agent message is untrusted data. A party
commits where evidence lives and the sha256 of its exact bytes; nothing is fetched
until a round, and then every node fetches and verifies it for itself. A chain
transaction is cited by chain and hash, and every node reads it from a fixed registry.

## Submitting an item

`submit_evidence(incident_id, source_type, source_locator, content_hash,
source_identity, observed_at, agent_trace_reference, description, access_constraints,
anchor_chain, anchor_tx)`

| Check | Rule | Where |
|---|---|---|
| submitter | the reporter, the controller, or the implicated tool's provider | `_role` |
| phase | case before the first adjudication; appeal while adjudicated; remediation after a finding is finalized; nothing otherwise | `submit_evidence` |
| category | one of `CATEGORIES` | `_evidence_input_error` |
| locator | https, at most 300 characters, no credentials, no port but 443, no IP literal, no local or internal names, no fragment, backslash, encoded separator, dot-segment or empty segment | `_url_parts` |
| origin | under a registered origin of the incident's parties or a public source of its policy; the longest matching prefix wins, a tie goes to the submitter's own class | `_origin_of` |
| content hash | 64 lowercase hex characters | `_evidence_input_error` |
| chain item | no locator and no hash; a chain in `ANCHOR_CHAINS`; a 32-byte transaction hash | `_evidence_input_error` |
| text fields | issuer, description and trace reference are bounded and carry no credential, personal data, text addressed to the adjudicator, or hidden characters | `_write_text_error` |
| time | `observed_at` is an ISO-8601 UTC timestamp not in the future | `_evidence_input_error` |
| access | `PUBLIC` or `CONFIDENTIAL` | `_evidence_input_error` |
| duplicates | the same bytes, location or transaction already committed to the incident is refused | `submit_evidence` |
| bounds | `MAX_ROLE_EVIDENCE` per party across the case and its appeals; remediation evidence bounded separately, also per party | `submit_evidence` |

Origins are https path prefixes ending in `/` with at least one path segment, so no
party can claim a whole host other parties publish on (`_prefix_error`).

## Categories

Structured records are JSON with `document_type` equal to the category, `agent_id`,
`issuer` and `as_of`, plus a strict schema; integers only, so a float, a boolean, a
string or a negative number is malformed, never a fact (`_structured_facts`).

| Category | Schema | Facts code reads |
|---|---|---|
| `AGENT_TRACE` | `steps`: `{seq, at, kind, tool, summary}`, kind in `TRACE_STEP_KINDS` | entries, tool calls, actions, escalations, sequence gaps, time reversals, duration |
| `TOOL_CALL_LOG` | `calls`: `{seq, at, tool, status, authorization, summary}` | entries, errors, denied, unauthorized, gaps, reversals, duration |
| `AUDIT_LOG` | `events`: `{seq, at, actor, event, outcome}` | entries, failures, gaps, reversals, duration |
| `API_RECEIPT` | `endpoint`, `request_id`, `status_code`, `units`, `amount_atto` | status code, units, amount |
| `ACCESS_RECORD` | `grants`: `{principal, resource, permission, granted_at, revoked_at}` | grants, active as of the record, revoked |
| `SYSTEM_ALERT` | `alert_id`, `severity_label`, `raised_at`, `rule`, `affected_records` | severity rank, affected records |
| `REMEDIATION_TEST` | `test_suite`, `run_at`, `target_finding`, `total`, `passed`, `failed` that add up | total, passed, failed |

Text categories: `POLICY_DOCUMENT`, `THREAT_INTEL`, `VULNERABILITY_REPORT`,
`USER_REPORT`, `TIMESTAMPED_FILE`, and `ATTACK_ARTIFACT` - captured attacker content,
which is the subject of an investigation and is not scanned for hidden text.
`CHAIN_TRANSACTION` is the chain's own record.

The brief lists screenshots. There is no screenshot category: the contract reads
text, and an image nothing can read would be admitted as if it had been examined.

Amounts in facts reach the panel already converted to GEN in code
(`_fact_for_panel`); no model scales a number.

## At every round

1. **Fetch and verify** (`_fetch_row`): the bytes are hashed before anything reads
   them. `UNAVAILABLE` for a failed fetch or empty body, `HASH_MISMATCH` for different
   bytes, `TOO_LARGE` above `FETCH_BYTES_CAP` (8000 bytes), `UNPARSEABLE` for bytes that
   are not UTF-8 text or break their category's schema, `EXAMINED` otherwise.
2. **Read the chain** (`_read_chain`): `VERIFIED` only for a final, successful
   transaction; `NOT_FOUND`, `FAILED`, `PENDING` or `UNAVAILABLE` otherwise. StudioNet's
   `value_credited: false` counts as no value.
3. **Scan in code** (`_scan`, `_code_indicators`, `_registry_finding`). Each indicator
   below excludes the item it names, whoever submitted it:

| Indicator | Found when |
|---|---|
| `EVIDENCE_UNLINKED` | a structured record's `agent_id` is another agent, or text names other agent ids and not this one |
| `DUPLICATE_EVIDENCE` | a later item repeats earlier bytes or a transaction; the first copy stays, so nobody can knock another party's item out by committing it again |
| `HIDDEN_TEXT` | zero-width, invisible or bidirectional control characters, or hiding styles (`HIDDEN_CHARACTERS`, `HIDDEN_STYLES`) |
| `ADJUDICATOR_MARKER` | a phrase addressed to the adjudication (`ADJUDICATOR_MARKERS`); attack payloads aimed at the agent are not scanned for |
| `SECRET_EXPOSURE` | a private key or key block, a seed phrase, an AWS, GitHub, Slack or Stripe secret, a bearer token, a JSON web token, a session cookie, a password, API key or client secret assignment, a US SSN, or a Luhn-valid card number (`SECRET_PATTERNS`) |
| `STALE_EVIDENCE` | a structured record's `as_of` is further before the incident than `maximum_evidence_age_days` |
| `TRACE_SEQUENCE_GAP` | a trace or log skips or repeats a sequence number |
| `TRACE_TIME_REVERSAL` | an entry is dated before the one above it |
| `SOURCE_IDENTITY_MISMATCH` | the declared issuer, or the issuer inside a structured record, names an incident party other than the one whose origin served the bytes |
| `ANCHOR_NOT_FOUND` | a cited transaction does not exist or failed |
| `CROSS_CASE_REUSE` | bytes or a transaction an earlier incident claimed, unless that incident closed unresolved. Committing an item claims it when it is a record of an event (`REGISTERED_CATEGORIES`) or when a reporter could not have minted it - anything the controller's or a tool's origin served, and every chain record (`UNMINTABLE_ORIGINS`) - whatever category it is declared as; a reporter's own or a public policy document, threat intelligence or attack artifact may recur |

4. **Show the panel** only readable items, each with its verified origin and who
   submitted it; an excluded item's text is replaced by `EXCLUDED_TEXT`.

## Who an unreadable item holds

`_holding_ids`: an item from the reporter's origins that is unreachable or changed,
or a transaction the reporter cited that is not yet final, holds the case at
`SOURCE_UNAVAILABLE` - the reporter carries the burden of proof, and an agent is never
judged on a record the nodes could not read. An item from a respondent's origins in
that state counts for nothing, whoever cited it, so no respondent can stall a case by
taking its own host down. A chain registry that does not answer holds whoever cited
it. Oversized or malformed bytes are excluded whoever committed them.

An appeal changes one thing: a readjudication must read again every item the appealed
round examined or verified (`_unread_since`). Otherwise a party could appeal and then
stop serving its own admission, and the round replacing the record would judge less than
the first panel saw. Such a readjudication does not run; the appeal waits until the item
is served again, or lapses and the appealed record stands. The rule stops only on the
appellant's own items and on chain records: were the other side's withdrawal to stop it,
the side the standing record favours could block every appeal against it by taking its
own item down.

## Spheres and support

Every eligible item has an origin class: `REPORTER`, `CONTROLLER`, `TOOL`, `PUBLIC` or
`CHAIN`. The reporter's sphere is its own origins; the controller's is its own origins,
the policy's public sources and the agent's tools (`OWN_SPHERE`), because the controller
wrote the policy and chose the tools, and a host it controls can sit behind any of them.
A chain record belongs to nobody.

A finding that favours a party must quote at least one item from outside that party's
sphere (`FAVOURS`, `_support_satisfies`). An admission against a party's own interest
therefore counts, and a party's self-serving record does not. A finding that the
controller misconfigured its agent must also quote a record of configuration - a
tool-call log, an access record or an audit log (`SUPPORT_CATEGORIES`) - not only the
agent's conduct. Those are structured categories on purpose: a declared category is a
claim, and only a structured one is checked against the document's own type. RC13 shows the rule at
work: a public page speaking as "Docfetch Security Team", offered by the controller to
blame the tool, is excluded as an impersonation, and the compromise stands with no tool
share. RC10 shows its mirror: the reporter's own report of Docfetch's cache fault moves
the failure to the tool, where a notice from Docfetch alone could not.

## Receipts

Every record carries one receipt per item (`_receipts`):

| Field | Meaning |
|---|---|
| `source_locator`, `source_identity`, `origin`, `submitted_by`, `access_constraints` | where it came from, as committed and as verified |
| `retrieved_at` | the round's time |
| `content_hash`, `hash_verified`, `status`, `source_reachable` | what the fetch or chain read found |
| `freshness_status` | `AS_OF` a structured record's date, the chain's time, or `UNDATED` |
| `authenticity_status` | `ACCEPTED`, `EXCLUDED:<why>`, or `HOLDS_OUTCOME:<status>` |
| `relevance_status` | `NAMES_AGENT`, `NAMES_ANOTHER_AGENT`, `UNSTATED`, `SENT_BY_AGENT_WALLET`, `NOT_SENT_BY_AGENT_WALLET`, or `NOT_ASSESSED` |
| `tamper_status` | `FLAGGED` for a changed hash, a gap, a reversal, a missing transaction, an impersonation, or tampering the panel found |
| `conflict_status` | `MANIPULATION`, `SUPPORTS_A_FINDING`, or `NONE` |
| `counted` | whether it was eligible |
| `summary` | code-written: a structured record's facts, the chain text, or the submitter's description |
| `limitations` | what this category can and cannot prove (`LIMITATIONS`) |

A `CONFIDENTIAL` item's locator and summary are withheld from the receipt, and its
quotes are stored as a sha256 with the note of any finding that cites it withheld
(`_redacted_findings`).
