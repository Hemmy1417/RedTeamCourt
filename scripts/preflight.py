#!/usr/bin/env python3
"""Preflight: fast structural checks that need no network and no GenVM.

Run before the Direct Mode suite and the linter (CI does). Every check is
named; the script prints PASS/FAIL per check and exits non-zero on any
failure. It proves repository invariants, not contract behaviour - with the
emphasis a contract holding bonds, pools and report bonds earns: where value
can move, and how many places can move it.

  python scripts/preflight.py
"""

from __future__ import annotations

import hashlib
import io
import json
import pathlib
import re
import subprocess
import sys
import tokenize

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "redteam_court.py"
FIXTURES = ROOT / "fixtures"
RUNNER = "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6"
FETCH_BYTES_CAP = 8000
OVERSIZED_ON_PURPOSE = ("sources/harbor/capture-oversized.txt",)
HOLDING = ("INSUFFICIENT_EVIDENCE", "CONFLICTING_EVIDENCE", "SOURCE_UNAVAILABLE",
           "INCONCLUSIVE")

# Brief section 21: every named Direct Mode path and the test that walks it.
BRIEF_TESTS = {
    "confirmed policy violation with consistent evidence": "test_compromise_incident_end_to_end",
    "legitimate authorized emergency action": "test_a_legitimate_emergency_action_is_compliant",
    "valid vulnerability report with reproducible impact":
        "test_disclosure_pays_the_severity_bounty",
    "remediation report supported by test evidence":
        "test_a_remediation_supported_by_the_researchers_retest_is_verified",
    "valid appeal with new evidence": "test_a_valid_appeal_with_new_evidence_changes_the_outcome",
    "missing policy": "test_registration_needs_an_existing_active_policy",
    "inactive policy": "test_deactivation_takes_effect_after_notice",
    "unauthorized reporter": "test_who_may_file",
    "stale evidence": "test_stale_evidence_is_excluded",
    "source unavailable": "test_a_reporter_item_that_is_unreachable_holds_the_case",
    "duplicate evidence": "test_the_same_bytes_location_or_transaction_is_committed_once",
    "wrong incident reference": "test_evidence_about_another_agent_is_unlinked",
    "expired incident": "test_filing_refusals",
    "expired appeal": "test_an_expired_appeal_is_refused",
    "malformed severity": "test_policy_parse_refusals",
    "compensation beyond configured bounds":
        "test_compensation_is_bounded_by_the_claim_the_policy_and_the_free_bond",
    "policy version mismatch": "test_a_new_version_takes_effect_only_after_notice",
    "replayed submission": "test_a_replay_of_a_finalized_incident_is_rejected",
    "secret-containing evidence":
        "test_evidence_carrying_a_secret_is_excluded_withheld_and_rotation_required",
    "fabricated logs": "test_impersonated_issuers_are_excluded",
    "altered timestamps": "test_a_trace_whose_times_run_backwards_is_excluded",
    "omitted tool calls": "test_a_trace_with_a_gap_is_excluded_and_the_logging_duty_fails",
    "prompt injection in logs": "test_a_reporter_steering_the_panel_is_rejected",
    "prompt injection in documents": "test_hidden_text_in_a_report_is_excluded",
    "source impersonation": "test_impersonated_issuers_are_excluded",
    "false-positive vulnerability report": "test_an_irrelevant_exploit_payload_is_read_as_data",
    "malicious leader verdict": "test_a_severe_verdict_without_evidence_fails_the_gate",
    "validator disagreement": "test_validators_disagreeing_on_compromise_do_not_settle",
    "external dependency failure": "test_a_dependency_failure_is_not_malice",
    "legitimate emergency behavior": "test_a_legitimate_emergency_action_is_compliant",
    "remediation claim without test evidence":
        "test_a_remediation_claim_without_test_results_is_insufficient",
    "evidence contamination across incidents":
        "test_reuse_across_live_incidents_flags_only_the_later_copy",
}

RESULTS = []


def check(name: str, ok: bool, detail: str = ""):
    RESULTS.append((name, ok, detail))
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "  -> " + detail))


def words(text: str) -> list:
    return re.findall(r"[a-z0-9]+", text.casefold())


def contract_checks():
    raw = CONTRACT.read_bytes()
    text = raw.decode("utf-8")
    lines = text.split("\n")
    check("contract has no CR bytes", b"\r" not in raw)
    check("contract is ASCII", all(b < 128 for b in raw),
          "non-ASCII bytes break the linter and hosted schema encoding")
    check("line 1 is the version comment", lines[0] == "# v0.1.0", lines[0])
    check("line 2 pins the runner", lines[1] == '# { "Depends": "' + RUNNER + '" }', lines[1])
    check("line 3 is blank (Depends block is load-bearing)", lines[2] == "")
    for alias in ("py-genlayer:test", "py-genlayer:latest"):
        check("no runner alias " + alias, alias not in text)
    version = re.search(r'^CONTRACT_VERSION = "([^"]+)"', text, re.M)
    check("CONTRACT_VERSION matches the header",
          version is not None and "# v" + version.group(1) == lines[0])
    check("exactly one gl.Contract",
          len(re.findall(r"^class \w+\(gl\.Contract\):", text, re.M)) == 1)
    floats = [t.string for t in tokenize.generate_tokens(io.StringIO(text).readline)
              if (t.type == tokenize.NUMBER and re.search(r"[.eEjJ]", t.string))
              or (t.type == tokenize.NAME and t.string == "float")]
    check("no float literal or float() in the contract (integer arithmetic only)",
          not floats, ", ".join(floats))
    check("no filesystem, clock or randomness import in the contract",
          not re.search(r"\bopen\(|\bimport (os|time|random|datetime|requests)\b", text))


def money_checks():
    """Where can value move, and is each place the one the docs name?"""
    text = CONTRACT.read_text(encoding="utf-8")
    check("exactly one transfer call site in the contract",
          len(re.findall(r"emit_transfer\(", text)) == 1)
    withdraw = re.search(r"def withdraw\(self\).*?(?=\n    @|\n    # --)", text, re.S)
    check("the transfer lives in withdraw()",
          withdraw is not None and "emit_transfer(" in withdraw.group(0))
    check("withdraw clears the ledger before it transfers",
          withdraw is not None
          and withdraw.group(0).index("self.credits[wallet] = u256(0)")
          < withdraw.group(0).index("emit_transfer("))
    payable = re.findall(r"@gl\.public\.write\.payable\s*\n\s*def (\w+)", text)
    check("exactly three payable methods: the bond, the pool and a filing",
          sorted(payable) == ["fund_bounty_pool", "open_incident", "post_security_bond"],
          ", ".join(payable))
    check("a refused deposit is returned, never reverted (two return sites)",
          text.count("self._return_deposit(") == 4 and "def _return_deposit" in text,
          str(text.count("self._return_deposit(")) + " call sites")
    check("every settlement goes through _settle (finalize and a lapsed appeal)",
          len(re.findall(r"self\._settle\(", text)) == 2)
    check("every release goes through _close_unresolved (three stall routes)",
          len(re.findall(r"self\._close_unresolved\(", text)) == 3)
    check("the claimable total changes only in _credit and withdraw",
          text.count("self.credits_total_atto = u256(int(self.credits_total_atto)") == 2)
    check("the report-bond total changes only at filing, settlement and release",
          text.count("self.report_bonds_total_atto = u256(int(self.report_bonds_total_atto)")
          == 3)
    check("no contract-to-contract call other than the payout proxy",
          "get_contract_at" not in text)


def secret_checks():
    pattern = re.compile(r"0x[0-9a-fA-F]{64}")
    offenders = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts \
                or ".data" in path.parts:
            continue
        if path.suffix.lower() not in (".py", ".md", ".json", ".yml", ".yaml", ".txt",
                                       ".toml", ".cfg", ".ini", ".html", ".example", ""):
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for line in content.splitlines():
            if pattern.search(line) and "private" in line.lower() and "+" not in line:
                offenders.append(str(path.relative_to(ROOT)))
                break
    check("no private keys in the tree", not offenders, ", ".join(offenders))
    env_files = [p.name for p in ROOT.glob(".env*") if p.is_file() and p.name != ".env.example"]
    check("no .env files in the tree (only .env.example)", not env_files, ", ".join(env_files))
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    check(".env.example carries no values",
          all(line.strip().endswith("=") for line in example.splitlines()
              if line.strip() and not line.startswith("#")))
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    check(".data/ and .env are gitignored", ".data/" in ignore and ".env" in ignore)
    config = (ROOT / "gltest.config.yaml").read_text(encoding="utf-8")
    check("gltest config carries no interpolated secrets", "${" not in config)
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8").strip().splitlines()
    check("fixtures are byte-exact in git (-text, last rule)",
          attributes[-1].strip() == "fixtures/** -text")


def fixture_checks():
    sys.path.insert(0, str(ROOT / "scripts"))
    import generate_fixtures
    built = generate_fixtures.build()
    differ = [p for p, data in built.items()
              if not (FIXTURES / p).exists() or (FIXTURES / p).read_bytes() != data]
    check("fixtures regenerate byte-exact from scripts/generate_fixtures.py",
          not differ, ", ".join(differ))
    on_disk = {p.relative_to(FIXTURES).as_posix() for p in FIXTURES.rglob("*") if p.is_file()}
    extra = sorted(on_disk - set(built))
    check("no fixture file outside the generator", not extra, ", ".join(extra))

    cases = json.loads((FIXTURES / "cases.json").read_text(encoding="utf-8"))["cases"]
    ids = [c["case_id"] for c in cases]
    check("case ids are unique", len(ids) == len(set(ids)))
    keys = ("case_id", "attack_category", "notes", "capability", "malicious_input",
            "expected_safe_behavior", "fail_closed", "engine", "onchain", "covered_by",
            "evidence", "panel_answer", "expected_verdict", "expected_severity_min",
            "expected_severity_max")
    missing = [c["case_id"] for c in cases if any(k not in c for k in keys)]
    check("every case names its attacker, input, safe behaviour, verdict and band",
          not missing, ", ".join(missing))
    held_paying = [c["case_id"] for c in cases
                   if c["expected_verdict"] in HOLDING and c["expected_severity_max"] > 0]
    check("no case expects a severity on a held verdict", not held_paying,
          ", ".join(held_paying))

    tests = "\n".join(p.read_text(encoding="utf-8")
                      for p in list((ROOT / "tests" / "direct").glob("*.py"))
                      + [ROOT / "scripts" / "live_scenarios.py"] if p.exists())
    referenced = {e["path"] for c in cases for e in c["evidence"] if e["path"]}
    unused = sorted(p for p in on_disk if p not in referenced
                    and p not in ("cases.json", "wallets.json", "world.json")
                    and p not in tests)
    check("every evidence document is used by a case or a test", not unused,
          ", ".join(unused))

    docs = [p for p in FIXTURES.rglob("*") if p.is_file()
            and p.name not in ("cases.json", "wallets.json", "world.json")]
    big = [p.relative_to(FIXTURES).as_posix() for p in docs
           if p.stat().st_size > FETCH_BYTES_CAP
           and p.relative_to(FIXTURES).as_posix() not in OVERSIZED_ON_PURPOSE]
    check("every evidence document fits the fetch cap, but the one oversized on purpose",
          not big, ", ".join(big))
    cr = [p.name for p in docs if b"\r" in p.read_bytes()]
    check("evidence documents are LF-only (hashes survive checkouts)", not cr, ", ".join(cr))

    ungrounded = []
    for c in cases:
        answer = c["panel_answer"] or {}
        files = {"E" + str(i + 1): e["path"] for i, e in enumerate(c["evidence"])}
        entries = list((answer.get("rules") or {}).values()) + \
            list((answer.get("indicators") or {}).values())
        for entry in entries:
            for q in entry.get("quotes", []):
                if files.get(q["evidence_id"]) is None:
                    continue     # a chain item's text is written by the contract
                source = words((FIXTURES / files[q["evidence_id"]]).read_text(encoding="utf-8"))
                needle = words(q["text"])
                if not any(source[i:i + len(needle)] == needle for i in range(len(source))):
                    ungrounded.append(c["case_id"] + " " + q["evidence_id"])
    check("every recorded panel quote is verbatim in its document",
          not ungrounded, "; ".join(ungrounded))


def coverage_checks():
    tests = "\n".join(p.read_text(encoding="utf-8")
                      for p in (ROOT / "tests" / "direct").glob("test_*.py"))
    cases = json.loads((FIXTURES / "cases.json").read_text(encoding="utf-8"))["cases"]
    contract = CONTRACT.read_text(encoding="utf-8")
    listed = re.search(r"ATTACK_CATEGORIES = \((.*?)\)\n", contract, re.S).group(1)
    brief = [a for a in re.findall(r'"([A-Z_]+)"', listed)
             if a not in ("LEGITIMATE_BASELINE", "OTHER")]
    check("the contract lists the brief's 30 attack categories", len(brief) == 30,
          str(len(brief)))
    covered = {c["attack_category"] for c in cases}
    check("every attack category has a catalogue entry",
          not [a for a in brief if a not in covered])
    unrun = [c["case_id"] for c in cases if not c["engine"]
             and not all((ROOT / part.strip().split(" ")[0]).exists()
                         for part in c["covered_by"].split(","))]
    check("every attack the engine cannot run names an existing test file", not unrun,
          ", ".join(unrun))
    missing = [path for path, fn in BRIEF_TESTS.items() if "def " + fn + "(" not in tests]
    check("every brief section 21 path has a named test", not missing, ", ".join(missing))
    names = ("test_contract_smoke.py", "test_policy_validation.py",
             "test_evidence_integrity.py", "test_severity_boundaries.py",
             "test_prompt_injection.py", "test_adversarial_cases.py",
             "test_consensus_equivalence.py", "test_appeals.py", "test_secret_redaction.py")
    absent = [n for n in names if not (ROOT / "tests" / "direct" / n).exists()]
    check("the brief's nine test modules exist", not absent, ", ".join(absent))


EXTERNAL_NAMES = {"GENVM_VERSION", "REDTEAM_LIVE_WRITES", "gen_getContractCode",
                  "gen_getContractSchema"}
DOCS = ("README.md", "DECISION.md", "SUBMISSION.md", "docs/architecture.md",
        "docs/threat-model.md", "docs/policy-model.md", "docs/evidence-policy.md",
        "docs/severity-model.md", "docs/remediation.md", "docs/consensus.md",
        "docs/security.md", "docs/integration.md", "docs/deployment.md")


def docs_checks():
    missing = [name for name in DOCS if not (ROOT / name).exists()]
    check("every document the brief names exists", not missing, ", ".join(missing))
    source = CONTRACT.read_text(encoding="utf-8")
    stray = []
    for name in DOCS:
        path = ROOT / name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        # every backticked identifier - a helper, a constant, a method, an enum
        # value or a record field - must still occur in the contract as a word;
        # commit ids and the few names that belong to the tooling are not symbols
        for token in set(re.findall(r"`([A-Za-z_][A-Za-z0-9_]*)(?:\([^`]*\))?`", text)):
            if re.fullmatch(r"[0-9a-f]{7,40}", token) or token in EXTERNAL_NAMES:
                continue
            if not re.search(r"(?<![A-Za-z0-9_])" + re.escape(token) + r"(?![A-Za-z0-9_])",
                             source):
                stray.append(name + ":" + token)
    check("docs anchor only to symbols the contract still has", not stray,
          ", ".join(sorted(stray)))
    readme = (ROOT / "README.md").read_text(encoding="utf-8") \
        if (ROOT / "README.md").exists() else ""
    claimed = re.search(r"`python -m pytest tests/direct -q` \| (\d+) passed", readme)
    collected = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/direct", "--collect-only", "-q",
         "-p", "no:cacheprovider"], cwd=ROOT, capture_output=True, text=True)
    found = re.search(r"(\d+) tests? collected", collected.stdout)
    check("the README's Direct Mode count is the suite's own count",
          bool(claimed and found and claimed.group(1) == found.group(1)),
          (claimed.group(1) if claimed else "unstated") + " claimed vs "
          + (found.group(1) if found else "uncollected"))


def address_checks():
    record = ROOT / "deploy" / "deployment.json"
    if not record.exists():
        check("deployment record (skipped: not deployed yet)", True)
        return
    deployment = json.loads(record.read_text(encoding="utf-8"))
    allowed = {deployment["contract_address"].lower(), deployment["signer"].lower()}
    wallets = json.loads((FIXTURES / "wallets.json").read_text(encoding="utf-8"))
    allowed |= {a.lower() for a in wallets.values()}
    stray = []
    docs = [ROOT / "README.md", ROOT / "SUBMISSION.md", ROOT / "DECISION.md"] + \
        list((ROOT / "docs").glob("*.md"))
    for path in docs:
        if not path.exists():
            continue
        for address in re.findall(r"0x[0-9a-fA-F]{40}(?![0-9a-fA-F])",
                                  path.read_text(encoding="utf-8")):
            if address.lower() not in allowed:
                stray.append(path.name + ":" + address)
    placeholders = [p.name for p in docs if p.exists()
                    and re.search(r"LIVE_SUMMARY|TO_BE_FILLED|TODO", p.read_text(encoding="utf-8"))]
    check("no unfilled placeholders in the docs", not placeholders, ", ".join(placeholders))
    check("docs name only the recorded addresses (one canonical deployment)",
          not stray, ", ".join(sorted(set(stray))))
    source = hashlib.sha256(CONTRACT.read_bytes()).hexdigest()
    check("deployment record names the current contract bytes",
          deployment.get("source_sha256") == source,
          "record " + str(deployment.get("source_sha256")) + " vs tree " + source)


def main():
    contract_checks()
    money_checks()
    secret_checks()
    fixture_checks()
    coverage_checks()
    docs_checks()
    address_checks()
    failed = [r for r in RESULTS if not r[1]]
    print("\n" + str(len(RESULTS)) + " checks, " + str(len(failed)) + " failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
