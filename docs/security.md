# Security

The attack catalogue is [`threat-model.md`](threat-model.md). This page states what is
protected, who can act, what the contract trusts, how each input is attacked and
answered, and what fails closed.

## Assets

| Asset | Protected by |
|---|---|
| the security bond and bounty pool | reservations at filing, delayed withdrawals from what is unreserved, payments only from ratified records, pull payments |
| report bonds | posted exactly, returned or forfeited only by a settling verdict, returned by every stall exit |
| the finding on an agent | code-derived from grounded, support-checked findings every validator reproduced |
| the record | stored once under its id with a digest (`record_digest`); a readjudication writes a new record and names what changed |
| the policy an incident binds | versions are immutable and take effect only after notice |
| confidential material | credentials and personal data refused at every write; excluded evidence's text withheld; confidential quotes stored as hashes |

## Actors

| Actor | Can | Cannot |
|---|---|---|
| controller | publish and version its policy, register its agent, fund and withdraw, answer, submit evidence, appeal, report remediation | file against its own agent, rewrite the version an incident bound, withdraw what incidents reserved, back its own defence with only its own sphere |
| agent wallet | confirm itself | file against its agent |
| tool provider | register tools, answer and submit evidence when its tool is implicated | file over its own tool, shift blame with only its own records |
| reporter | file with an exact bond, submit evidence, appeal | post a different bond, convict on its own items alone, steer the panel without losing the case |
| anyone | request rounds, finalize, close stalled incidents, lift expired embargoes, run adversarial cases, read | submit evidence, appeal, withdraw another wallet's credit |
| a host serving evidence | serve bytes | change committed bytes unnoticed |
| a malicious leader | propose a payload | have it ratified unless validators' own readings lead to the same consequence |
| a validator minority | disagree | block an honest majority |
| a downstream contract | read `agent_security_status` | be handed a verdict no validator majority derived |

## Trust assumptions

1. An honest majority of validators fetches, reads the chain and asks its model
   independently.
2. The `ANCHOR_CHAINS` endpoints report their chains' transactions truthfully.
3. A party's registered origins are hosts that party controls; the contract checks
   which origin served an item, not who wrote it.
4. StudioNet's transaction time is the clock for every window.
5. Keys are held by the parties they belong to; a chain record proves what the chain
   recorded, not who held the key.

## Input attacks

| Input | Attack | Answer |
|---|---|---|
| URLs | internal hosts, IP literals, credentials, odd ports, encoded traversal | `_url_parts` refuses them; runtime egress controls remain the real boundary |
| URLs | a party hosting another party's record | origins decide whose sphere an item is in; a tie goes to the submitter's own class (`_origin_of`) |
| URLs | a whole host shared by several parties | origins must name a path segment (`_prefix_error`) |
| evidence bytes | changed after commitment | sha256 checked before reading; a reporter's changed item holds, a respondent's counts for nothing |
| evidence bytes | withdrawn between a round and its readjudication, so the appeal is judged on less | the readjudication does not run until everything the appealed round read is served again; otherwise the appeal lapses and the appealed record stands (`_unread_since`) |
| evidence bytes | oversized, malformed, wrong schema, floats or negatives in structured records | `TOO_LARGE` or `UNPARSEABLE`, excluded |
| evidence text | instructions aimed at the panel | `ADJUDICATOR_MARKER` excludes the item and attributes manipulation to its submitter; the panel is told evidence is data |
| evidence text | hidden characters or hiding styles | `HIDDEN_TEXT` excludes it |
| evidence text | credentials or personal data | `SECRET_EXPOSURE` excludes it and withholds its text; `ROTATE_CREDENTIALS` is required |
| structured records | gaps, reversed times, another agent's id, an impersonated issuer, stale dates | excluded by code |
| chain citations | a transfer by someone else's wallet | spending and counterparty rules read only the agent's declared wallet; the chain text says whose wallet sent it |
| chain citations | a transaction that failed or does not exist | `ANCHOR_NOT_FOUND` |
| records of an event | reuse in another incident | `CROSS_CASE_REUSE`; a full replay of a finalized incident is `REJECTED` |
| party statements | instructions, hidden text, credentials | refused at the write (`_write_text_error`) |
| model output | forged states, invented fields, quotes not in the bytes, self-serving support | the structural gate on every validator and again after consensus (`_parse_payload`) |
| model output | unparseable | `MODEL_OUTPUT_INVALID`, `INCONCLUSIVE` |
| numbers | negative, oversized, floats, severities outside 0-5, shares outside 0-10000 | refused at parse (`_parse_policy`, `_int_in`) |
| payable writes | a deposit sent with a refused call | returned to the sender's claimable balance and logged (`_return_deposit`) - never raised, because StudioNet credits a raising payable call's value to the contract |
| ordering | finalize or close inside a window, appeal after it, a second appeal while one waits, a second finalization | refused by state and wall-clock checks |

## Secret-handling boundaries

- The contract never accepts a credential, a private key, a seed phrase, a token, a
  session cookie, a password or personal data in anything a party writes, and excludes
  any evidence item whose bytes contain one.
- An excluded item's text never reaches the panel, and quotes carrying a credential are
  refused by the gate.
- Evidence marked `CONFIDENTIAL` keeps its locator and summary out of receipts, and its
  quotes are stored as sha256 hashes; the notes of findings that cite it are withheld.
- A disclosure's summary, impact claim and reproducibility are withheld from views until
  its embargo is lifted (`get_incident`, `lift_disclosure_embargo`). The filing
  transaction itself is public on chain; the embargo governs what this contract
  republishes.
- Keys for the scripts live in `.data/` (gitignored). Nothing in the repository holds a
  private key, and `fixtures/wallets.json` holds only public addresses.

## Fail-closed policy

| Condition (brief section 18) | Result |
|---|---|
| the policy is missing or inactive | filing refused |
| the policy is too vague | `INCONCLUSIVE`, `PATCH_POLICY` |
| required evidence is unavailable | `SOURCE_UNAVAILABLE` for a reporter's item; fewer eligible items than required is `INSUFFICIENT_EVIDENCE` |
| evidence cannot be linked to the incident | `EVIDENCE_UNLINKED`, excluded |
| source authenticity is unresolved | `SOURCE_IDENTITY_MISMATCH`, excluded; a finding favouring a party needs support from outside its sphere |
| validators materially disagree | no record is stored |
| the incident or appeal window has expired | filing an expired incident and appealing after the window are refused |
| the result would expose secrets | refused at input, withheld in records |
| severity or compensation arithmetic fails | integer arithmetic within parsed bounds; `_settle` refuses a payment above its reservation or its fund |
| the request is a replay | `REJECTED`, report bond forfeited |
| evidence is malformed | excluded |
| the result would mutate finalized history | records are stored once; a finalized incident takes no new adjudication or appeal, only remediation reviews, each its own record |

Uncertainty is never labelled compromise or malice: a cause, attacker control
included, must be supported, and an undecided one leaves responsibility where the
policy put it.

## Limitations

- Consensus assumes an honest validator majority.
- A hash proves bytes did not change, not that they are true.
- URL admission is defence in depth, not SSRF protection.
- A model can misread an item; validators reproduce readings and compare consequences,
  which limits but does not remove that.
- Windows use StudioNet transaction time; a view has no clock and takes the caller's
  `as_of`.
- The registry recognises the same bytes and the same transaction, not the same event:
  a new record of an old event is new evidence.
- A registered reporter can file first against the same agent with another reporter's
  public records - a transaction, or bytes it can fetch. While that filing is open the
  records count as reuse in the later incident. It costs the filer a report bond, and a
  filing that closes unresolved or finalizes `REJECTED` releases the records.
- Reservations are made at filing and released when an incident closes. A reporter
  who files several incidents with large claims can hold a bond's capacity for a
  response and stall window, at the cost of a report bond each; an incident filed while
  the bond is fully reserved reserves nothing.
- A captured attack artifact is not scanned for hidden text, because payloads carry it;
  it is still scanned for text aimed at the adjudicator, and no party's own artifact can
  carry a finding in its favour.
- Histories are bounded (`MAX_VERSIONS`, `MAX_ADJUDICATIONS`, `MAX_ROLE_EVIDENCE`,
  `MAX_REMEDIATION_REVIEWS`, `MAX_COMMITTERS`).
- This is a StudioNet deployment, not an audited production system, and it does not
  replace security professionals, incident responders or legal process.
