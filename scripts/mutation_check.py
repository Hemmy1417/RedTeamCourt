#!/usr/bin/env python3
"""Mutation kill check: prove the Direct Mode suite pins each load-bearing
guard, not merely that the code passes today.

For each mutation the contract is copied to a scratch directory with ONE
guard mechanically broken, and the whole Direct Mode suite runs against the
copy. A mutation is KILLED when the suite fails and SURVIVED when it passes
(an unpinned guard). The run starts with an accept-control: the unmodified
copy must pass, or every kill would be vacuous.

Anchors are code TEXT, never line numbers. An anchor that is not found
exactly once is reported as ANCHOR MISSING - the guard moved or was deleted,
which is its own finding. Equivalent mutants (a guard a second guard makes
unobservable) are not listed; the ones considered and excluded are named at
the bottom of this file with the reason.

Run:  python scripts/mutation_check.py             (full sweep)
      python scripts/mutation_check.py --anchors   (anchor check only)
      python scripts/mutation_check.py --only gate (only mutations whose name
                                                    contains "gate")
      python scripts/mutation_check.py --jobs 3    (three scratch copies at
                                                    once; default 1)
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = "contracts/redteam_court.py"


def off(line: str) -> str:
    """The same condition, never true, at the same indentation."""
    head = line[:len(line) - len(line.lstrip())]
    keyword = line.lstrip().split(" ", 1)[0]
    return head + keyword + " False:\n"


MUTATIONS = [
    # -- verdict precedence (_derive) ------------------------------------------------
    ("a replay of settled evidence is not rejected",
     "    if reporter_records and all(e in ctx[\"replays\"] for e in reporter_records):\n",
     "    if False:\n"),
    ("an unreadable holding item no longer holds",
     "    elif holding:\n", "    elif False:\n"),
    ("unusable model output still settles",
     "    elif payload[\"panel_state\"] == PANEL_INVALID:\n        verdict = \"INCONCLUSIVE\"\n"
     "    elif reporter_manipulated and respondent_manipulated:\n",
     "    elif False:\n        verdict = \"INCONCLUSIVE\"\n"
     "    elif reporter_manipulated and respondent_manipulated:\n"),
    ("manipulation on both sides is not conflicting evidence",
     "    elif reporter_manipulated and respondent_manipulated:\n", "    elif False:\n"),
    ("a manipulated report is not rejected",
     "    elif reporter_manipulated:\n", "    elif False:\n"),
    ("a respondent's manipulation counts against the reporter",
     "    reporter_manipulated = ROLE_REPORTER in accused\n",
     "    reporter_manipulated = len(accused) > 0\n"),
    ("the policy's minimum evidence count is ignored",
     "    elif len(eligible) < policy[\"minimum_evidence_items\"]:\n",
     "    elif len(eligible) == 0:\n"),
    ("a vague policy settles",
     "    elif unclear:\n", "    elif False:\n"),
    ("a violation whose conduct the panel found absent settles",
     "happened == ABSENT\n                       or (kind == KIND_DISCLOSURE",
     "False\n                       or (kind == KIND_DISCLOSURE"),
    ("a disclosure that did not reproduce is confirmed",
     "                       or (kind == KIND_DISCLOSURE and happened != PRESENT)):\n",
     "                       or False):\n"),
    ("a compromise is not recognised",
     "        elif \"AGENT_UNDER_EXTERNAL_CONTROL\" in present:\n"
     "            verdict = \"CONFIRMED_COMPROMISE\"\n",
     "        elif False:\n            verdict = \"CONFIRMED_COMPROMISE\"\n"),
    ("a misconfiguration is not recognised",
     "        elif \"CONTROLLER_MISCONFIGURATION\" in present:\n"
     "            verdict = \"LIKELY_MISCONFIGURATION\"\n",
     "        elif False:\n            verdict = \"LIKELY_MISCONFIGURATION\"\n"),
    ("a tool fault is not an external failure",
     "        elif \"TOOL_FAULT\" in present or \"EXTERNAL_DEPENDENCY_FAILURE\" in present:\n",
     "        elif \"EXTERNAL_DEPENDENCY_FAILURE\" in present:\n"),
    ("a dependency failure is not an external failure",
     "        elif \"TOOL_FAULT\" in present or \"EXTERNAL_DEPENDENCY_FAILURE\" in present:\n",
     "        elif \"TOOL_FAULT\" in present:\n"),
    ("containment is never required",
     "    elif kind == KIND_INCIDENT and \"AGENT_UNDER_EXTERNAL_CONTROL\" in present \\\n",
     "    elif False and \"AGENT_UNDER_EXTERNAL_CONTROL\" in present \\\n"),
    ("containment is required without ongoing exposure",
     "            and \"ONGOING_EXPOSURE\" in present:\n        verdict = \"REQUIRES_CONTAINMENT\"\n",
     "            and True:\n        verdict = \"REQUIRES_CONTAINMENT\"\n"),
    ("a false report is not a false positive",
     "    elif happened == ABSENT:\n", "    elif False:\n"),
    ("an unsettled rule still reads as compliant",
     "    all_clear = len(rules) > 0 and all(f[\"state\"] in (NOT_VIOLATED, AUTHORIZED_EXCEPTION)\n",
     "    all_clear = len(rules) > 0 and all(f[\"state\"] != VIOLATED\n"),
    ("an authorised exception is not compliant",
     "    all_clear = len(rules) > 0 and all(f[\"state\"] in (NOT_VIOLATED, AUTHORIZED_EXCEPTION)\n",
     "    all_clear = len(rules) > 0 and all(f[\"state\"] in (NOT_VIOLATED,)\n"),
    ("undecided conduct is insufficient rather than inconclusive",
     "    elif happened == UNDETERMINED:\n", "    elif False:\n"),
    # -- the commitment registry -------------------------------------------------------
    ("any earlier committer makes a replay",
     "                if str(prior.status) == INCIDENT_FINALIZED and it[\"evidence_id\"] not in replays:\n",
     "                if it[\"evidence_id\"] not in replays:\n"),
    ("an incident closed unresolved still blocks its evidence",
     "                if str(prior.status) != INCIDENT_CLOSED and it[\"evidence_id\"] not in hits:\n",
     "                if it[\"evidence_id\"] not in hits:\n"),
    ("the committing incident flags its own evidence",
     "            earlier = ids[:ids.index(incident_id)] if incident_id in ids else ids\n",
     "            earlier = ids\n"),
    ("shared-by-nature categories are registered too",
     "            if it[\"category\"] not in REGISTERED_CATEGORIES:\n                continue\n",
     "            if False:\n                continue\n"),
    # -- who carries an unreadable item (_holding_ids, _plan) ----------------------------
    ("a respondent's unreachable item holds the case",
     "                and submitter[r[\"evidence_id\"]] == ROLE_REPORTER:\n",
     "                and True:\n"),
    ("a reporter's changed bytes do not hold",
     "        if r[\"status\"] in (ROW_UNAVAILABLE, ROW_HASH_MISMATCH) \\\n",
     "        if r[\"status\"] in (ROW_UNAVAILABLE,) \\\n"),
    ("a chain registry that did not answer does not hold",
     "        if f[\"state\"] == CHAIN_UNAVAILABLE or \\\n", "        if False or \\\n"),
    ("a respondent's pending transaction holds the case",
     "                (f[\"state\"] == CHAIN_PENDING and submitter[f[\"evidence_id\"]] == ROLE_REPORTER):\n",
     "                (f[\"state\"] == CHAIN_PENDING):\n"),
    ("the panel is convened while a reporter item is unread",
     "    if _holding_ids(ctx, rows, chain):\n        skip = SKIP_NOT_EXAMINED\n",
     "    if False:\n        skip = SKIP_NOT_EXAMINED\n"),
    ("excluded evidence stays eligible",
     "    eligible = [e for e in usable if e not in tainted]\n",
     "    eligible = list(usable)\n"),
    ("a logging duty needs only one kind of record",
     "            elif rule[\"kind\"] == \"LOGGING_REQUIREMENT\" and not all(\n",
     "            elif rule[\"kind\"] == \"LOGGING_REQUIREMENT\" and not any(\n"),
    ("logs from any origin satisfy the controller's logging duty",
     "                    any(origin_of[e] == ORIGIN_CONTROLLER and category_of[e] == category\n",
     "                    any(category_of[e] == category\n"),
    ("the logging duty is never decided by code",
     "            elif rule[\"kind\"] == \"LOGGING_REQUIREMENT\" and not all(\n",
     "            elif False and not all(\n"),
    ("the spending limit is not enforced",
     "        bad = [f[\"evidence_id\"] for f in attributed if f[\"value_atto\"] > rule[\"limit_atto\"]]\n",
     "        bad = []\n"),
    ("spending exactly the limit breaches it",
     "        bad = [f[\"evidence_id\"] for f in attributed if f[\"value_atto\"] > rule[\"limit_atto\"]]\n",
     "        bad = [f[\"evidence_id\"] for f in attributed if f[\"value_atto\"] >= rule[\"limit_atto\"]]\n"),
    ("the counterparty allowlist is not enforced",
     "               if f[\"recipient\"] not in rule[\"counterparties\"]]\n",
     "               if False]\n"),
    ("any wallet's transactions are attributed to the agent",
     "                  and f[\"sender\"] == wallet]\n", "                  ]\n"),
    ("an excluded transaction still decides a chain rule",
     "                  and f[\"evidence_id\"] in eligible and wallet != \"\"\n",
     "                  and wallet != \"\"\n"),
    # -- code scans (_code_indicators, _scan) --------------------------------------------
    ("a duplicate is not flagged",
     "        if key in seen:\n            duplicates.append(it[\"evidence_id\"])\n",
     "        if False:\n            duplicates.append(it[\"evidence_id\"])\n"),
    ("stale evidence is not flagged",
     "             if reference - _iso_epoch(f[\"as_of\"]) > limit]\n", "             if False]\n"),
    ("a sequence gap is not flagged",
     "            and fact_of[e][\"values\"][\"sequence_gaps\"] > 0]\n", "            and False]\n"),
    ("a time reversal is not flagged",
     "                 and fact_of[e][\"values\"][\"time_reversals\"] > 0]\n",
     "                 and False]\n"),
    ("a declared impersonation is not flagged",
     "        if declared or inside:\n", "        if inside:\n"),
    ("an impersonation inside a document is not flagged",
     "        if declared or inside:\n", "        if declared:\n"),
    ("a transaction the chain never recorded is not flagged",
     "               if f[\"state\"] in (CHAIN_NOT_FOUND, CHAIN_FAILED)]\n",
     "               if f[\"state\"] == CHAIN_FAILED]\n"),
    ("a captured attack payload is excluded as hidden text",
     "        if it[\"category\"] != ARTIFACT_CATEGORY and _hidden_hits(text):\n",
     "        if _hidden_hits(text):\n"),
    ("hidden text is not scanned",
     "        if it[\"category\"] != ARTIFACT_CATEGORY and _hidden_hits(text):\n",
     "        if False:\n"),
    ("text aimed at the adjudicator is not scanned",
     "        if _adjudicator_hits(text):\n            scans[\"markers\"].append(eid)\n",
     "        if False:\n            scans[\"markers\"].append(eid)\n"),
    ("a credential in evidence is not scanned",
     "        if _secret_kinds(text):\n            scans[\"secrets\"].append(eid)\n",
     "        if False:\n            scans[\"secrets\"].append(eid)\n"),
    ("a structured document about another agent is linked",
     "            if fact[\"agent_id\"] == ctx[\"agent_id\"]:\n", "            if True:\n"),
    # -- support, manipulation and discounting -------------------------------------------
    ("a party's own sphere supports its own finding",
     "    return any(origins.get(e) not in own for e in distinct)\n", "    return True\n"),
    ("a decided finding needs no quote at all",
     "    if len(distinct) == 0:\n        return False\n", "    if False:\n        return False\n"),
    ("a readjudication may run without what the appealed round read",
     "        lost = _unread_since(original, record)\n",
     "        lost = []\n"),
    ("a misconfiguration needs no record of configuration",
     "        distinct = [e for e in distinct if categories.get(e) in allowed]\n",
     "        pass\n"),
    ("tools and public sources sit outside the controller's sphere",
     "              ROLE_CONTROLLER: (ORIGIN_CONTROLLER, ORIGIN_TOOL, ORIGIN_PUBLIC)}\n",
     "              ROLE_CONTROLLER: (ORIGIN_CONTROLLER,)}\n"),
    ("an ABSENT that forfeits a bond needs no support",
     "    return state == PRESENT or (state == ABSENT and subject_id in ABSENT_DECIDES)\n",
     "    return state == PRESENT\n"),
    ("manipulated support is not discounted",
     "        quotes = [q for q in f[\"quotes\"] if q[\"evidence_id\"] not in manipulated]\n",
     "        quotes = list(f[\"quotes\"])\n"),
    ("a discounted finding keeps its state",
     "            state = UNVERIFIABLE if is_rule else UNDETERMINED\n            fell.append(f[\"id\"])\n",
     "            fell.append(f[\"id\"])\n"),
    ("panel-found manipulation is not attributed",
     "        if f[\"state\"] == PRESENT and (f[\"id\"] in STEERING_CODE\n"
     "                                      or f[\"id\"] in PANEL_MANIPULATION):\n",
     "        if f[\"state\"] == PRESENT and (f[\"id\"] in STEERING_CODE):\n"),
    ("steering found by code is not attributed",
     "        if f[\"state\"] == PRESENT and (f[\"id\"] in STEERING_CODE\n"
     "                                      or f[\"id\"] in PANEL_MANIPULATION):\n",
     "        if f[\"state\"] == PRESENT and (f[\"id\"] in PANEL_MANIPULATION):\n"),
    # -- the structural gate and the validator ---------------------------------------------
    ("the gate does not re-ground quotes",
     "        if not _quote_grounded(q, eligible, texts):\n", "        if False:\n"),
    ("a verified row's size is not bound to its status",
     "            if (r[\"status\"] == ROW_TOO_LARGE) != (r[\"byte_count\"] > FETCH_BYTES_CAP):\n",
     "            if False:\n"),
    ("the gate lets a code finding differ from the plan",
     "        if indicators[i] != plan[\"code_indicators\"][i]:\n", "        if False:\n"),
    ("what was read is not compared on the chain",
     "    for key in (\"facts\", \"chain\", \"linked\", \"unlinked\", \"hidden\", \"markers\", \"secrets\"):\n",
     "    for key in (\"facts\", \"linked\", \"unlinked\", \"hidden\", \"markers\", \"secrets\"):\n"),
    ("the consequence is not compared",
     "        difference = _consequence_difference(own_outcome, _derive(ctx, parsed))\n",
     "        difference = \"\"\n"),
    ("a leader error of the model's making is ratified",
     "    if leader_text.startswith(ERROR_LLM):\n        return False\n",
     "    if False:\n        return False\n"),
    ("any validator error ratifies a transient leader error",
     "            return own_text.startswith(ERROR_TRANSIENT)\n", "            return True\n"),
    ("a different expected error ratifies",
     "        return own_text == leader_text\n", "        return True\n"),
    ("an excluded item's text reaches the panel",
     "                      \"text\": EXCLUDED_TEXT if excluded else texts[eid]})\n",
     "                      \"text\": texts[eid]})\n"),
    # -- severity, responsibility, remediation, impact, confidence --------------------------
    ("harm does not raise severity",
     "        if factors[\"material_harm\"] or factors[\"financial_impact\"]:\n",
     "        if factors[\"financial_impact\"]:\n"),
    ("financial impact does not raise severity",
     "        if factors[\"material_harm\"] or factors[\"financial_impact\"]:\n",
     "        if factors[\"material_harm\"]:\n"),
    ("ongoing exposure does not raise severity",
     "        if factors[\"ongoing_exposure\"]:\n            score = score + 1\n",
     "        if False:\n            score = score + 1\n"),
    ("a one-sided record is not capped",
     "        factors[\"cap\"] = 3\n", "        factors[\"cap\"] = 5\n"),
    ("value at the high-value line is not financial impact",
     "               \"financial_impact\": value > 0 and value >= policy[\"high_value_atto\"],\n",
     "               \"financial_impact\": value > 0 and value > policy[\"high_value_atto\"],\n"),
    ("data sensitivity does not weigh a data-class rule",
     "                weight = max(weight, min(5, c[\"sensitivity\"] + 1))\n",
     "                weight = weight\n"),
    ("containment severity ignores harm",
     "        score = 3 + (1 if factors[\"material_harm\"] else 0)\n", "        score = 3\n"),
    ("compliance carries no severity",
     "        return (1, factors)\n", "        return (0, factors)\n"),
    ("a misconfigured compromise keeps a lower controller share",
     "            controller = max(controller, BPS // 2)\n", "            controller = controller\n"),
    ("a faulty tool carries no share of a compromise",
     "        tool = min(BPS // 2 if \"TOOL_FAULT\" in present else 0, BPS - controller)\n",
     "        tool = 0\n"),
    ("a tool share can exceed what the controller left",
     "        tool = min(BPS // 2 if \"TOOL_FAULT\" in present else 0, BPS - controller)\n",
     "        tool = BPS // 2 if \"TOOL_FAULT\" in present else 0\n"),
    ("an external failure blames the external party over a faulty tool",
     "        if \"TOOL_FAULT\" in present:\n            return [[\"TOOL_PROVIDER\", BPS]]\n",
     "        if False:\n            return [[\"TOOL_PROVIDER\", BPS]]\n"),
    ("containment assigns no party",
     "    if verdict == \"REQUIRES_CONTAINMENT\":\n        return [[\"UNASSIGNED\", BPS]]\n",
     "    if False:\n        return [[\"UNASSIGNED\", BPS]]\n"),
    ("ongoing exposure does not isolate the agent",
     "    if verdict in VIOLATION_CLASS and \"ONGOING_EXPOSURE\" in present:\n"
     "        out.append(\"ISOLATE_AGENT\")\n",
     "    if False:\n        out.append(\"ISOLATE_AGENT\")\n"),
    ("a leaked credential needs no rotation",
     "    if \"SECRET_EXPOSURE\" in present:\n        out.append(\"ROTATE_CREDENTIALS\")\n",
     "    if False:\n        out.append(\"ROTATE_CREDENTIALS\")\n"),
    ("a vague policy asks for no patch",
     "    elif verdict == \"INCONCLUSIVE\" and unclear:\n", "    elif False:\n"),
    ("a tool-permission breach does not restrict the tool",
     "            elif kind == \"TOOL_PERMISSION\":\n                out.append(\"RESTRICT_TOOL\")\n",
     "            elif False:\n                out.append(\"RESTRICT_TOOL\")\n"),
    ("a logging breach asks for no monitoring",
     "            elif kind == \"LOGGING_REQUIREMENT\":\n                out.append(\"MONITOR\")\n",
     "            elif False:\n                out.append(\"MONITOR\")\n"),
    ("a credential in evidence is not an impact",
     "    if \"SECRET_EXPOSURE\" in present:\n        out.append(\"CREDENTIAL_EXPOSURE\")\n",
     "    if False:\n        out.append(\"CREDENTIAL_EXPOSURE\")\n"),
    ("a held record claims confidence",
     "    if verdict in HOLDING:\n        return \"NONE\"\n", "    if False:\n        return \"NONE\"\n"),
    # -- money (_derive, _settle, filing, funds) ------------------------------------------------
    ("compensation needs no proven harm",
     "        and \"MATERIAL_HARM\" in present and severity >= policy[\"min_compensable_severity\"] \\\n",
     "        and severity >= policy[\"min_compensable_severity\"] \\\n"),
    ("compensation ignores the minimum severity",
     "        and \"MATERIAL_HARM\" in present and severity >= policy[\"min_compensable_severity\"] \\\n",
     "        and \"MATERIAL_HARM\" in present \\\n"),
    ("compensation ignores the controller's share",
     "    compensation = ctx[\"reserved_compensation_atto\"] * controller_bps // BPS \\\n",
     "    compensation = ctx[\"reserved_compensation_atto\"] \\\n"),
    ("the bounty is not capped by its reservation",
     "    bounty = min(policy[\"bounty_tiers_atto\"][severity], ctx[\"reserved_bounty_atto\"]) \\\n",
     "    bounty = policy[\"bounty_tiers_atto\"][severity] \\\n"),
    ("a false positive keeps its report bond",
     "    report_bond = BOND_FORFEIT if verdict in (\"FALSE_POSITIVE\", \"REJECTED\") else BOND_RETURN\n",
     "    report_bond = BOND_FORFEIT if verdict in (\"REJECTED\",) else BOND_RETURN\n"),
    ("a holding verdict settles",
     "            \"settles\": verdict not in HOLDING,\n", "            \"settles\": True,\n"),
    ("a forfeited bond goes back to the reporter",
     "        self._credit(_addr_hex(incident.controller) if forfeit else reporter, bond)\n",
     "        self._credit(reporter, bond)\n"),
    ("reservations are not released at finalization",
     "        self._release_reservations(incident, agent)\n        reporter = _addr_hex(incident.reporter)\n",
     "        reporter = _addr_hex(incident.reporter)\n"),
    ("a compensation reservation ignores the free bond",
     "                                              policy[\"max_compensation_atto\"], free))\n",
     "                                              policy[\"max_compensation_atto\"]))\n"),
    ("a compensation reservation ignores the policy maximum",
     "                                              policy[\"max_compensation_atto\"], free))\n",
     "                                              free))\n"),
    ("a bounty reservation ignores the pool",
     "            reserve_bounty = max(0, min(policy[\"bounty_tiers_atto\"][5], free))\n",
     "            reserve_bounty = policy[\"bounty_tiers_atto\"][5]\n"),
    ("a withdrawal ignores reservations",
     "        pay = min(requested, balance - reserved)\n", "        pay = requested\n"),
    ("a withdrawal completes before its delay",
     "        if _iso_epoch(self._now()) < _iso_epoch(after):\n", "        if False:\n"),
    ("a stranger's deposit is kept in the bond",
     "        if gl.message.sender_address != agent.controller:\n"
     "            return self._return_deposit(method, \"only the agent's controller funds it\")\n",
     "        if False:\n"
     "            return self._return_deposit(method, \"only the agent's controller funds it\")\n"),
    ("a refused filing that carried value reverts",
     "            if value > 0:\n                return self._return_deposit(\"open_incident\", err)\n",
     "            if False:\n                return self._return_deposit(\"open_incident\", err)\n"),
    ("the report bond need not be exact",
     "        if value != policy[\"report_bond_atto\"]:\n", "        if False:\n"),
    ("a withdrawal may exceed the fund",
     "        if amount_atto > balance:\n", "        if False:\n"),
    ("a second withdrawal replaces the pending one",
     "        if pending != \"\":\n", "        if False:\n"),
    ("withdraw pays twice",
     "        self.credits[wallet] = u256(0)\n", "        pass\n"),
    # -- policies, parties, filing -----------------------------------------------------------------
    ("anyone may publish a policy version",
     "        if gl.message.sender_address != record.owner:\n"
     "            self._fail(\"only the policy owner can publish a version\")\n",
     "        if False:\n            self._fail(\"only the policy owner can publish a version\")\n"),
    ("a new version takes effect at once",
     "        effective = _epoch_iso(at + self._notice_seconds(policy_id, at))\n",
     "        effective = now\n"),
    ("a pending version may be replaced",
     "        if _iso_epoch(str(head.effective_from)) > at:\n", "        if False:\n"),
    ("deactivation takes effect at once",
     "        record.deactivated_from = _epoch_iso(at + self._notice_seconds(policy_id, at))\n",
     "        record.deactivated_from = now\n"),
    ("a deactivated policy keeps binding",
     "        if str(record.deactivated_from) != \"\" and at >= _iso_epoch(str(record.deactivated_from)):\n",
     "        if False:\n"),
    ("an agent may be registered under another controller's policy",
     "        if gl.message.sender_address != record.owner:\n"
     "            self._fail(\"an agent is registered by the controller that owns its policy\")\n",
     "        if False:\n"
     "            self._fail(\"an agent is registered by the controller that owns its policy\")\n"),
    ("any wallet may confirm the agent wallet",
     "        if self._sender_hex() != str(agent.agent_wallet):\n", "        if False:\n"),
    ("the filed version is not checked",
     "        if not _is_int(policy_version) or policy_version != int(pv.version):\n",
     "        if False:\n"),
    ("an expired incident may be filed",
     "        if at - occurred > policy[\"maximum_evidence_age_days\"] * 86400:\n", "        if False:\n"),
    ("a controller may file against its own agent",
     "        if gl.message.sender_address == agent.controller:\n"
     "            return (\"a controller cannot file against its own agent\", None)\n",
     "        if False:\n            return (\"a controller cannot file against its own agent\", None)\n"),
    ("evidence from outside every origin is admitted",
     "            if origin == \"\":\n", "            if False:\n"),
    ("the same bytes may be committed twice",
     "            elif str(ev.sha256) == content_hash or str(ev.url) == canonical:\n",
     "            elif False:\n"),
    ("a party may commit unlimited evidence",
     "        elif mine >= MAX_ROLE_EVIDENCE:\n", "        elif False:\n"),
    ("a stranger may submit evidence",
     "        if role == \"\":\n            self._fail(\"only the reporter, the controller or the implicated tool's \"\n",
     "        if False:\n            self._fail(\"only the reporter, the controller or the implicated tool's \"\n"),
    ("a reporter may counter-report",
     "        if role not in (ROLE_CONTROLLER, ROLE_TOOL):\n", "        if role == \"\":\n"),
    ("the controller may answer twice",
     "            if str(incident.controller_responded_at) != \"\":\n", "            if False:\n"),
    ("answering never readies the incident",
     "            incident.status = INCIDENT_RESPONDED\n", "            pass\n"),
    ("adjudication may be requested before respondents answer",
     "        if status == INCIDENT_OPEN and at <= _iso_epoch(str(incident.response_deadline)):\n",
     "        if False:\n"),
    # -- appeals, finalization, stall exits ---------------------------------------------------------
    ("an appeal may name any record",
     "        if adjudication_id != ids[len(ids) - 1]:\n", "        if False:\n"),
    ("an appeal after the window is accepted",
     "        if _iso_epoch(now) > _iso_epoch(str(incident.appeal_deadline)):\n"
     "            self._fail(\"expired appeal: the appeal window closed at \"\n",
     "        if False:\n            self._fail(\"expired appeal: the appeal window closed at \"\n"),
    ("an appeal one second late is accepted",
     "        if _iso_epoch(now) > _iso_epoch(str(incident.appeal_deadline)):\n"
     "            self._fail(\"expired appeal: the appeal window closed at \"\n",
     "        if _iso_epoch(now) > _iso_epoch(str(incident.appeal_deadline)) + 1:\n"
     "            self._fail(\"expired appeal: the appeal window closed at \"\n"),
    ("appeals are unlimited",
     "        if len(ids) >= MAX_ADJUDICATIONS:\n", "        if False:\n"),
    ("an appeal may cite evidence a round already read",
     "            if eid in judged or eid in seen:\n", "            if eid in seen:\n"),
    ("an appellant may cite the other side's evidence",
     "            if str(ev.submitter) != role or str(ev.phase) != PHASE_APPEAL:\n",
     "            if str(ev.phase) != PHASE_APPEAL:\n"),
    ("finalizing ignores the appeal window",
     "        if _iso_epoch(now) <= _iso_epoch(str(incident.appeal_deadline)):\n",
     "        if False:\n"),
    ("finalizing ignores an appeal waiting to be heard",
     "        if self._open_appeal(incident) is not None:\n"
     "            self._fail(\"an appeal is waiting to be heard\")\n",
     "        if False:\n            self._fail(\"an appeal is waiting to be heard\")\n"),
    ("a holding record may be finalized",
     "        if not record[\"settles\"]:\n", "        if False:\n"),
    ("an unadjudicated incident closes without its stall window",
     "            due = _iso_epoch(str(incident.response_deadline)) + stall\n",
     "            due = _iso_epoch(str(incident.response_deadline))\n"),
    ("an unheard appeal never lapses",
     "            due = _iso_epoch(str(appeal.submitted_at)) + stall\n",
     "            due = _iso_epoch(str(appeal.submitted_at)) + 10 ** 9\n"),
    ("a lapsed appeal of a settling record releases instead of settling",
     "            if record[\"settles\"]:\n                self._settle(incident, record, now, \"APPEAL_LAPSED\")\n",
     "            if False:\n                self._settle(incident, record, now, \"APPEAL_LAPSED\")\n"),
    ("a lapsed appeal is not marked",
     "            appeal.status = APPEAL_LAPSED\n", "            pass\n"),
    ("a settling record may be closed unresolved",
     "        if record[\"settles\"]:\n            self._fail(\"this adjudication settles; finalize_incident is its exit\")\n",
     "        if False:\n            self._fail(\"this adjudication settles; finalize_incident is its exit\")\n"),
    ("a held verdict closes without the appeal and stall windows",
     "        due = _iso_epoch(str(incident.appeal_deadline)) + stall\n",
     "        due = _iso_epoch(str(incident.appeal_deadline))\n"),
    # -- remediation, standing, confidentiality --------------------------------------------------------
    ("anyone may report a remediation",
     "        if self._role(incident) != ROLE_CONTROLLER:\n", "        if False:\n"),
    ("a remediation item may be reviewed twice",
     "            if eid in reviewed or eid in seen:\n", "            if eid in seen:\n"),
    ("remediation reviews are unlimited",
     "        if len(incident.review_ids) >= MAX_REMEDIATION_REVIEWS:\n", "        if False:\n"),
    ("a remediation without test results can verify",
     "    elif len(tests) == 0:\n", "    elif False:\n"),
    ("a manipulated remediation can verify",
     "    elif manipulated:\n        verdict = \"CONFLICTING_EVIDENCE\"\n",
     "    elif False:\n        verdict = \"CONFLICTING_EVIDENCE\"\n"),
    ("any review verdict clears the finding",
     "            if outcome[\"verdict\"] == \"VERIFIED\" else REMEDIATION_REQUIRED\n",
     "            if True else REMEDIATION_REQUIRED\n"),
    ("a finalized finding is not added to the agent's standing",
     "            agent.finding_ids.append(str(incident.incident_id))\n", "            pass\n"),
    ("standing ignores containment",
     "        elif containment:\n            standing = STANDING_CONTAINMENT\n",
     "        elif False:\n            standing = STANDING_CONTAINMENT\n"),
    ("standing ignores open incidents",
     "        elif open_incidents:\n            standing = STANDING_INVESTIGATION\n",
     "        elif False:\n            standing = STANDING_INVESTIGATION\n"),
    ("a verified remediation still counts as an open finding",
     "            if str(incident.remediation_status) == REMEDIATION_VERIFIED_STATE:\n",
     "            if False:\n"),
    ("an agent with no policy in effect reads as trusted",
     "        if pv is None:\n            standing = STANDING_NO_POLICY\n",
     "        if False:\n            standing = STANDING_NO_POLICY\n"),
    ("an embargo lifts early",
     "        if _iso_epoch(self._now()) < _iso_epoch(str(incident.embargo_until)):\n",
     "        if False:\n"),
    ("an embargoed disclosure's text is shown",
     "        shown = bool(incident.embargo_lifted)\n", "        shown = True\n"),
    ("a confidential quote is republished",
     "            if access.get(q[\"evidence_id\"]) == ACCESS_CONFIDENTIAL:\n", "            if False:\n"),
    ("a note citing confidential evidence is republished",
     "        if f[\"note\"] != \"\" and any(access.get(e) == ACCESS_CONFIDENTIAL\n",
     "        if False and any(access.get(e) == ACCESS_CONFIDENTIAL\n"),
    ("a confidential locator is shown in a view",
     "                \"source_locator\": str(ev.url) if public else \"(confidential)\",\n",
     "                \"source_locator\": str(ev.url),\n"),
    ("a party's words may carry a credential",
     "    kinds = _secret_kinds(value)\n    if kinds:\n", "    kinds = _secret_kinds(value)\n    if False:\n"),
    ("a party's words may address the adjudicator",
     "    if _adjudicator_hits(value) or _hidden_hits(value):\n", "    if _hidden_hits(value):\n"),
    ("a party's words may hide text",
     "    if _adjudicator_hits(value) or _hidden_hits(value):\n", "    if _adjudicator_hits(value):\n"),
    ("a credential may be quoted",
     "        if _secret_kinds(cut):\n            continue\n", "        if False:\n            continue\n"),
    ("a card number that fails its checksum is a secret",
     "        if 13 <= len(digits) <= 19 and _luhn_ok(digits):\n", "        if 13 <= len(digits) <= 19:\n"),
    # -- the adversarial-test engine --------------------------------------------------------------------
    ("a case may run twice",
     "        if str(case.status) != CASE_REGISTERED:\n            self._fail(\"case has already run\")\n",
     "        if False:\n            self._fail(\"case has already run\")\n"),
    ("a case passes whatever verdict it observes",
     "        case.passed = outcome[\"verdict\"] == str(case.expected_verdict) and \\\n",
     "        case.passed = True and \\\n"),
    ("a case ignores its severity bounds",
     "            int(case.expected_severity_min) <= outcome[\"severity\"] \\\n"
     "            <= int(case.expected_severity_max)\n",
     "            True\n"),
    ("anyone may register a case",
     "        if gl.message.sender_address != pv.owner:\n"
     "            self._fail(\"only the policy owner can register a case\")\n",
     "        if False:\n            self._fail(\"only the policy owner can register a case\")\n"),
]

# Considered and excluded as equivalent (a second guard makes the first
# unobservable, so no test can tell the mutant from the original):
# - `if compensation > reserved or bounty > reserved` in _settle: _derive
#   computes compensation as the reservation times a share of at most 10000
#   bps and caps the bounty at its reservation, and the record is written by
#   the same code, so no settling record can carry more than its reservation.
#   The guard stands as the last check before money moves.
# - `if compensation > bond or bounty > pool` in _settle: a reservation is
#   never more than the free fund at filing, withdrawals never touch reserved
#   amounts, and nothing else lowers a fund, so a reserved amount is always
#   covered.
# - the `raise` when the ratified payload fails the gate in _run_round: Direct
#   Mode cannot forge the ratified value (only a leader result, which each
#   validator gates), so the last line of defence against a colluding majority
#   has no offline route. Its clauses are the gate's, tested there.
# - the duplicate check in _store_record: record ids come from a counter that
#   only ever increases.
# - `if len(record_ids) == 0` is killed by its own test; `request_adjudication`
#   on an incident with only remediation-phase evidence is unreachable because
#   remediation evidence needs a finalized incident.


def run_suite(workdir: pathlib.Path) -> bool:
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/direct", "-q", "-x",
         "-p", "no:cacheprovider", "--no-header"],
        cwd=workdir, capture_output=True, text=True)
    return completed.returncode == 0


def check_anchors(source: str) -> int:
    missing = 0
    for name, old, _new in MUTATIONS:
        hits = source.count(old)
        if hits != 1:
            print(f"ANCHOR MISSING ({hits} hits): {name}")
            missing += 1
    return missing


def copy_repo(scratch: pathlib.Path, index: int) -> pathlib.Path:
    work = scratch / ("repo%d" % index)
    shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns(
        ".git", "__pycache__", ".pytest_cache", "deploy", "artifacts", ".data", "docs"))
    return work


def main() -> None:
    source = (ROOT / CONTRACT).read_text(encoding="utf-8")
    missing = check_anchors(source)
    print(f"{len(MUTATIONS)} mutations, {missing} anchor problems")
    if "--anchors" in sys.argv:
        sys.exit(0 if missing == 0 else 1)

    only = ""
    if "--only" in sys.argv:
        only = sys.argv[sys.argv.index("--only") + 1].casefold()
    jobs = 1
    if "--jobs" in sys.argv:
        jobs = max(1, int(sys.argv[sys.argv.index("--jobs") + 1]))

    todo = [m for m in MUTATIONS
            if source.count(m[1]) == 1 and (not only or only in m[0].casefold())]
    jobs = min(jobs, max(1, len(todo)))

    scratch = pathlib.Path(tempfile.mkdtemp(prefix="redteam-mut-"))
    copies = [copy_repo(scratch, i) for i in range(jobs)]

    print("accept-control: unmodified copy must pass ...", flush=True)
    if not run_suite(copies[0]):
        print("CONTROL FAILED: the unmodified suite does not pass; aborting")
        shutil.rmtree(scratch, ignore_errors=True)
        sys.exit(1)
    print(f"control green; {len(todo)} mutations over {jobs} job(s)\n", flush=True)

    results = [None] * len(todo)
    cursor = [0]
    lock = threading.Lock()
    done = [0]

    def worker(work: pathlib.Path) -> None:
        target = work / CONTRACT
        while True:
            with lock:
                i = cursor[0]
                if i >= len(todo):
                    return
                cursor[0] = i + 1
            name, old, new = todo[i]
            target.write_text(source.replace(old, new), encoding="utf-8", newline="\n")
            passed = run_suite(work)
            target.write_text(source, encoding="utf-8", newline="\n")
            with lock:
                results[i] = passed
                done[0] += 1
                print(f"  [{done[0]}/{len(todo)}] "
                      f"{'SURVIVED' if passed else 'killed  '}: {name}", flush=True)

    threads = [threading.Thread(target=worker, args=(work,)) for work in copies]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    shutil.rmtree(scratch, ignore_errors=True)

    print()
    killed = survived = 0
    for (name, _old, _new), passed in zip(todo, results):
        if passed:
            print(f"SURVIVED: {name}")
            survived += 1
        else:
            print(f"killed:   {name}")
            killed += 1
    print(f"\nmutations: {killed} killed, {survived} survived, {missing} anchor missing")
    sys.exit(0 if survived == 0 and missing == 0 else 1)


if __name__ == "__main__":
    main()
