# Consensus

RedTeam Court runs one consensus round per decision: an adjudication
(`request_adjudication`), a readjudication (`request_readjudication`), a remediation
review (`request_remediation_review`) and an adversarial case
(`run_adversarial_case`). Every one goes through `_run_round`, which calls
`gl.vm.run_nondet_unsafe(leader_fn, validator_fn)`. Both functions run the same
procedure, `_node_round`; the validator then compares.

Symbols are named so they can be found in `contracts/redteam_court.py`.

## The nondeterministic calls

| Call | Where | What goes in | What comes back | Why code cannot replace it |
|---|---|---|---|---|
| `gl.nondet.web.get` | `_fetch_row` | one committed https location | bytes, hashed with sha256 before anything reads them | the records live on the parties' hosts; every node fetches them for itself |
| `gl.nondet.web.post` (JSON-RPC) | `_rpc_call`, from `_read_genlayer_tx` and `_read_evm_tx` | a chain from the fixed `ANCHOR_CHAINS` registry and a transaction hash, never a URL a party chose | the chain's own record: finality, sender, recipient, value, time | a transfer on StudioNet or Base Sepolia is not readable from deterministic execution; every node reads the registry itself |
| `gl.nondet.exec_prompt(..., response_format="json")` | `_node_round` | `PANEL_HEADER` and a canonical data block (`_panel_blob`): the frozen policy, the parties' statements marked as claims, each readable item's verified text with its origin, the facts code read, and only the questions code could not decide, each with the evidence ids its states may quote (`quote_from`) | per rule and per indicator: a state, up to three quotes and a note | whether an agent's conduct breached a written rule, and why it happened, is a reading of natural language across heterogeneous records |

An item code excluded is shown to the model without its text (`EXCLUDED_TEXT`).
The model call runs only when its answer can change the outcome (`_plan`): with a
reporter's item unreadable, nothing eligible, or nothing left to ask, the round
records `SKIPPED` with the reason and no model is consulted.

## Leader

`_node_round`, in order:

1. Fetch every committed location and verify its sha256 (`_fetch_row`). Status
   `EXAMINED`, `UNAVAILABLE`, `HASH_MISMATCH`, `TOO_LARGE` or `UNPARSEABLE`; a byte
   count only for verified bytes.
2. Read every cited transaction from the registry (`_read_chain`): `VERIFIED`,
   `NOT_FOUND`, `FAILED`, `PENDING` or `UNAVAILABLE`, with details only when verified.
   A verified transaction is rendered as short code-written text (`_chain_text`).
3. Read structured records into facts (`_structured_facts`) and scan verified text
   (`_scan`): which items name the agent or another agent, hide text, address the
   adjudicator, or carry a credential.
4. Plan (`_plan`): code indicators, the registry finding, eligible evidence, the
   rules code decides, the questions asked, and whether to convene the panel.
5. Ask the model and ground its answer (`_panel_findings`). Every quote must occur
   in an eligible item's verified text (`_quote_grounded`); a decided state whose
   quotes do not meet its support rules (`_support_met`: the party-interest rule, and
   a record of configuration for a misconfiguration) is recorded as undecided, and the
   node prints `[DOWNGRADE]` with the raw quotes.
6. Return the payload: rows, facts, chain facts, scans, panel state and reason,
   rule findings, code and panel indicators. The payload carries no verdict,
   severity, share or amount (`PAYLOAD_KEYS`).

## Validator

`_validator_decision`:

1. Run `_node_round` itself: its own fetches, its own chain reads, its own model call.
2. Gate the leader's payload against its own verified texts (`_parse_payload`).
3. Compare what was read (`_evidence_difference`).
4. Derive the consequence of its own findings and of the leader's (`_derive`) and
   compare them (`_consequence_difference`).

Each refusal prints its reason: `[DISAGREE] leader payload failed the structural
gate`, `[DISAGREE] evidence: <field>`, or `[DISAGREE] consequence: <field>`
followed by `[MINE]` with this node's own verdict and panel states. StudioNet
records each node's stdout, which is how the diagnostic runs below name the cause
of every split.

## Equivalence

`EQUIVALENCE_STATEMENT` in the contract is the exact rule. In short:

| Must match | Why |
|---|---|
| every row's status and byte count | the record is what every node read, where it enters the record |
| every structured fact, chain fact and code scan | code decides from these; a node that read different bytes or a different chain answer cannot ratify |
| the panel state and its reason | whether a model was asked is itself a code decision |
| the consequence: verdict, severity, responsibility shares, remediation set, impact classes, confidence, compensation and bounty eligibility, the controller's share when compensation is due, report-bond outcome, containment, corroboration | these are what the record does |
| on a violation-class verdict, the rules the finding rests on; on a settling verdict, who was found manipulating the record | both are written on the agent's standing and the reporter's record |

| May differ | Why |
|---|---|
| notes and quote choice | models phrase the same reading differently; quotes are grounded and recorded, and their consequence is already inside the derived consequence |
| an indicator state with no consequence | an absent cause and an undecided one lead to the same outcome, and a misconfiguration inside a compromise changes no share while the policy's compromise liability is 5000 bps or more |
| how the rules were shaded on a held record | a held record settles nothing |

Requiring agreement on anything with no consequence breaks rounds without making
any outcome safer: diverse model families phrase and shade differently, and only
what an outcome depends on has to be the same.

## Forged-leader defense

`_parse_payload` refuses a payload unless:

- it has exactly `PAYLOAD_KEYS`, the schema version, and the round's mode, subject,
  round, time, `policy_hash` and `evidence_commitment`;
- rows match the committed locations in order, with statuses and byte counts that
  are consistent (`TOO_LARGE` exactly when the verified size exceeds
  `FETCH_BYTES_CAP`);
- chain facts match the cited transactions and carry details only when verified;
- facts exist exactly for examined structured items and pass `_valid_fact`;
- scans list only examined items, in order, with no item both linked and unlinked
  and no hidden-text flag on an attack artifact;
- the panel state and reason are what `_plan` computes from those rows, facts,
  chain facts and scans;
- every code indicator and every code-decided rule equals what `_plan` computes;
- a skipped or invalid panel carries exactly the undecided findings;
- every panel finding has a known state, cites only eligible items in order, carries
  at most three quotes of 8-240 characters with no credential in them, every quote
  grounds in the validator's own verified text, and every decided state meets its
  support rules.

After consensus, `_run_round` runs `_parse_payload` once more on the ratified text
before anything is derived or written; a payload that fails raises
`[LLM_ERROR] ratified payload failed the gate` and the transaction stores nothing.

`tests/direct/test_consensus_equivalence.py` hands the captured validator forged
leader results: a severe verdict without evidence, an invented severity field,
quotes not in the bytes, a self-serving finding, forged code fields, a forged
manipulation finding, divergent source content and a different chain read.

## Failure

| Failure | Handling |
|---|---|
| a location is unreachable or serves different bytes | the row says so; an item from the reporter's origins holds the case at `SOURCE_UNAVAILABLE`, a respondent's counts for nothing (`_holding_ids`); in a readjudication, an appellant's own item or a chain record the appealed round read that cannot be read again stops the round, and the appeal waits or lapses (`_unread_since`) |
| a chain registry does not answer | `UNAVAILABLE` holds whoever cited it; a reporter's transaction not yet final holds the case |
| bytes that do not parse, or exceed the cap | `UNPARSEABLE` or `TOO_LARGE`: excluded, whoever committed them |
| the model call raises | `[TRANSIENT] the model call failed`; validators agree only if they also hit a transient failure, and nothing is stored |
| the model answers in a shape no parser accepts | `MODEL_OUTPUT_INVALID`: every panel question undecided, and the verdict `INCONCLUSIVE` unless a replay or an unreadable reporter item decides first |
| a model answer that cannot be grounded | the state falls to undecided (`[DOWNGRADE]`) |
| a leader error of the model's own making (`[LLM_ERROR]`) | validators disagree, so the round is retried with another leader |
| validators disagree | the round is not ratified: no record is stored, the incident keeps its state, and anyone may ask again; every held state has a wall-clock exit (`close_stalled_incident`) |
| the protocol leaves the transaction undetermined | the same: no record and no transfer; reservations stay until a later round settles or the stall exit releases them |

No failure of a round moves money. Credits change only when an incident settles or
closes (`_settle`, `_close_unresolved`), a withdrawal completes, or a refused deposit
is returned (`_return_deposit`); value leaves only through `withdraw`.

## Why consensus is load-bearing

Remove the round and deterministic code no longer has:

- the bytes of any off-chain record, so it cannot tell whether a committed trace,
  log or report still says what its hash promised;
- the chain's own record of a transfer, so a spending-limit or counterparty rule
  becomes a party's assertion;
- a reading of whether the agent's conduct breached a natural-language rule, and why.

A single operator could supply all three, but then the controller, the reporter
and every contract that reads `agent_security_status` would have to trust that
operator's fetches, its chain node and its model. The round replaces that trust
with independent reproduction: each validator fetches, reads the chain and asks
its own model, and only a consequence the majority derives from its own reading is
written.

## Live diagnostics

Before the canonical deployment, disposable deployments ran the catalogue's
on-chain cases through the adversarial engine and recorded every node's model,
vote and stdout under `deploy/diagnostics/`.

The first run (`run_20260915T061945.json`, contract at `372493b`) passed 13 of 21
cases. The recorded panels and the nodes' stdout name three causes for the eight
failures:

- an undecided cause held a proven violation at `INCONCLUSIVE` (RC04, RC09, RC10,
  RC13, RC23, RC24). In RC09, RC10 and RC24 the leader's model had found the cause,
  but quoted only the controller's own sphere, so the finding was downgraded to
  undecided before the hold applied;
- the same own-sphere quoting downgraded an authorised exception, leaving the rule
  unverifiable and the case `INSUFFICIENT_EVIDENCE` (RC14);
- a disclosure never tried against the agent was read as not reproducing, which
  made it a `FALSE_POSITIVE` (RC21).

What changed in response: the panel is handed `quote_from`, the evidence ids each
state may quote; a mitigating cause is the controller's to show, so an undecided
one holds nothing; the consequence compares the rules a finding rests on and who
manipulated the record only where they have an effect; and the questions draw the
lines models split on (`INDICATOR_QUESTIONS`).

The second run (`run_20260915T072301.json`, `cb769c2`) held 19 of 21. Every voting node
in RC10 read another customer's archive instruction, delivered by Docfetch's cache fault,
as an attacker's control; three of the four voting models in RC14 still quoted only
Meridian's alert and trace for the authorised exception. The attacker question now defines an
attacker and names accidental delivery as not one, the DF-88 notice and Harbor's report
say no attacker was involved, and Harbor's ticket quotes the notice it received in full.

The third run (`run_20260915T075012.json`, `6362d13`) moved RC10 to a misconfiguration
the nodes read from the trace alone - the agent POSTed, so its configuration must have
let it - which is conduct, not a record of configuration; a misconfiguration now counts
only quotes from records of configuration (`SUPPORT_CATEGORIES`). It also rehearsed the
live run's phase A: the first round held as designed, and the readjudication found no
consensus, because validators split on whether R1 and R7 were breached when the only
support outside Harbor's records was the chain's payment. Phase A now alleges the payment
rules that record decides in code.

The fourth run (`run_20260915T101732.json`, `0e7dda7`) replayed the five readings that had
split or drifted - RC10, RC14, RC23 and both phase A rounds - and all five held.
