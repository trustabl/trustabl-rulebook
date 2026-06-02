#!/usr/bin/env python3
"""Rulebook consistency gate.

Cross-checks the shipped detection rules (the `trustabl-rules` pack) against the
rulebook's per-policy rationale docs. This is the rulebook analog of the
engine's `TestPolicyRules_AllRulesCovered` guard: it fails CI when the book
drifts from the rules users actually receive.

It enforces three things:

  1. COVERAGE   — every rule in trustabl-rules has a rationale doc covering it.
  2. CONSISTENCY — each doc's front-matter (severity / confidence / scope) matches
                   the rule's YAML. The book may not claim a severity the engine
                   does not ship.
  3. PLACEMENT  — a rule is documented in the chapter (category/topic) where it
                   actually lives, and docs do not reference rules that no longer
                   exist.

Front-matter shape expected on each `docs/Policy/<category>/<topic>.md` (see
docs/policy-rationale-doc-template-guide.md):

    ---
    policy_id: openai_sdk_ssrf
    category: openai_sdk
    topic: ssrf
    rules:
      - id: OAI-016
        severity: high
        confidence: 0.6
        scope: tool
        fix_type: code          # editorial: config | code (not yet in engine schema)
    references: [LLM06, LLM02]   # OWASP LLM Top 10:2025
    ---

Usage:
    python tools/check_rulebook.py [--rules-repo PATH] [--strict]

    --rules-repo  Path to the trustabl-rules checkout (default: ../trustabl-rules,
                  or $TRUSTABL_RULES_REPO).
    --strict      Treat rationale docs with NO front-matter as errors (default:
                  warn — lets the migration land incrementally).

Exit code: 0 = clean, 1 = at least one error (or a strict warning).
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("error: pyyaml is required (pip install pyyaml)")

CONFIDENCE_TOLERANCE = 1e-9
VALID_FIX_TYPES = {"config", "code"}


@dataclass
class RuleSpec:
    """One rule as shipped in trustabl-rules (the source of truth)."""

    rule_id: str
    severity: str
    confidence: float
    scope: str
    category: str
    topic: str
    policy_id: str
    source: str  # relative path of the YAML file
    title: str = ""
    applies_to: list[str] = field(default_factory=list)


@dataclass
class DocRule:
    rule_id: str
    severity: str | None
    confidence: float | None
    scope: str | None
    fix_type: str | None


@dataclass
class RationaleDoc:
    path: Path
    has_front_matter: bool
    policy_id: str | None = None
    category: str | None = None
    topic: str | None = None
    rules: list[DocRule] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


# ── loading trustabl-rules ──────────────────────────────────────────────────


def load_rules(rules_repo: Path) -> tuple[dict[str, RuleSpec], list[str]]:
    """Return {rule_id: RuleSpec} and a list of load errors."""
    rules: dict[str, RuleSpec] = {}
    errors: list[str] = []
    for yaml_path in sorted(rules_repo.rglob("*.yaml")):
        if yaml_path.name == "manifest.yaml":
            continue
        rel = yaml_path.relative_to(rules_repo).as_posix()
        try:
            doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            errors.append(f"{rel}: YAML parse error: {exc}")
            continue
        if not isinstance(doc, dict) or "policy" not in doc:
            continue
        policy = doc.get("policy") or {}
        policy_id = policy.get("id", "")
        category = policy.get("category", "")
        # topic = the YAML basename without extension (the chapter file).
        topic = yaml_path.stem
        for rule in doc.get("rules") or []:
            rid = rule.get("id")
            if not rid:
                errors.append(f"{rel}: a rule has no id")
                continue
            if rid in rules:
                errors.append(
                    f"{rel}: duplicate rule id {rid} "
                    f"(also in {rules[rid].source})"
                )
                continue
            rules[rid] = RuleSpec(
                rule_id=rid,
                severity=str(rule.get("severity", "")),
                confidence=float(rule.get("confidence", 0.0)),
                # scope defaults to "tool" when omitted (engine behavior).
                scope=str(rule.get("scope", "tool")),
                category=str(category),
                topic=str(topic),
                policy_id=str(policy_id),
                source=rel,
                title=str(rule.get("title", "")),
                applies_to=[str(a) for a in (rule.get("applies_to") or [])],
            )
    return rules, errors


# ── loading rationale docs ──────────────────────────────────────────────────


def parse_front_matter(text: str) -> dict | None:
    """Return the parsed YAML front-matter dict, or None if absent/malformed."""
    if not text.startswith("---"):
        return None
    lines = text.splitlines()
    # find the closing fence after line 0
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            block = "\n".join(lines[1:i])
            try:
                data = yaml.safe_load(block)
            except yaml.YAMLError:
                return None
            return data if isinstance(data, dict) else None
    return None


def load_docs(rulebook_repo: Path) -> list[RationaleDoc]:
    policy_dir = rulebook_repo / "docs" / "Policy"
    docs: list[RationaleDoc] = []
    if not policy_dir.is_dir():
        return docs
    for md_path in sorted(policy_dir.rglob("*.md")):
        text = md_path.read_text(encoding="utf-8")
        fm = parse_front_matter(text)
        if fm is None:
            docs.append(RationaleDoc(path=md_path, has_front_matter=False))
            continue
        doc_rules = []
        for r in fm.get("rules") or []:
            if not isinstance(r, dict):
                continue
            conf = r.get("confidence")
            doc_rules.append(
                DocRule(
                    rule_id=str(r.get("id", "")),
                    severity=(str(r["severity"]) if "severity" in r else None),
                    confidence=(float(conf) if conf is not None else None),
                    scope=(str(r["scope"]) if "scope" in r else None),
                    fix_type=(str(r["fix_type"]) if "fix_type" in r else None),
                )
            )
        docs.append(
            RationaleDoc(
                path=md_path,
                has_front_matter=True,
                policy_id=fm.get("policy_id"),
                category=fm.get("category"),
                topic=fm.get("topic"),
                rules=doc_rules,
                references=list(fm.get("references") or []),
            )
        )
    return docs


# ── the checks ──────────────────────────────────────────────────────────────


def check(
    rules: dict[str, RuleSpec],
    docs: list[RationaleDoc],
    rulebook_repo: Path,
    strict: bool,
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []

    documented: set[str] = set()

    for doc in docs:
        rel = doc.path.relative_to(rulebook_repo).as_posix()
        if not doc.has_front_matter:
            msg = f"{rel}: no YAML front-matter (cannot be machine-checked)"
            (errors if strict else warnings).append(msg)
            continue

        for dr in doc.rules:
            rid = dr.rule_id
            spec = rules.get(rid)
            if spec is None:
                errors.append(
                    f"{rel}: documents rule {rid!r}, which is not in the rules pack "
                    f"(removed or typo)"
                )
                continue
            documented.add(rid)

            # CONSISTENCY
            if dr.severity is not None and dr.severity != spec.severity:
                errors.append(
                    f"{rel}: {rid} severity {dr.severity!r} != pack {spec.severity!r}"
                )
            if dr.confidence is not None and abs(dr.confidence - spec.confidence) > CONFIDENCE_TOLERANCE:
                errors.append(
                    f"{rel}: {rid} confidence {dr.confidence} != pack {spec.confidence}"
                )
            if dr.scope is not None and dr.scope != spec.scope:
                errors.append(
                    f"{rel}: {rid} scope {dr.scope!r} != pack {spec.scope!r}"
                )

            # PLACEMENT
            if doc.category and doc.category != spec.category:
                errors.append(
                    f"{rel}: {rid} documented under category {doc.category!r} "
                    f"but the rule lives in {spec.category!r}"
                )
            if doc.topic and doc.topic != spec.topic:
                errors.append(
                    f"{rel}: {rid} documented under topic {doc.topic!r} "
                    f"but the rule lives in {spec.topic!r} ({spec.source})"
                )

            # editorial field validation
            if dr.fix_type is not None and dr.fix_type not in VALID_FIX_TYPES:
                errors.append(
                    f"{rel}: {rid} fix_type {dr.fix_type!r} not in {sorted(VALID_FIX_TYPES)}"
                )

    # COVERAGE — every shipped rule must be documented.
    for rid in sorted(rules):
        if rid not in documented:
            spec = rules[rid]
            errors.append(
                f"rule {rid} ({spec.source}) has no rationale doc "
                f"(expected one covering it under docs/Policy/{spec.category}/{spec.topic}.md)"
            )

    return errors, warnings


def main() -> int:
    ap = argparse.ArgumentParser(description="Rulebook consistency gate.")
    default_rules = os.environ.get("TRUSTABL_RULES_REPO", "../trustabl-rules")
    ap.add_argument("--rules-repo", default=default_rules)
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()

    rulebook_repo = Path(__file__).resolve().parent.parent
    rules_repo = Path(args.rules_repo)
    if not rules_repo.is_absolute():
        rules_repo = (rulebook_repo / rules_repo).resolve()

    if not rules_repo.is_dir():
        print(f"error: rules repo not found: {rules_repo}", file=sys.stderr)
        return 2

    rules, load_errors = load_rules(rules_repo)
    docs = load_docs(rulebook_repo)

    errors, warnings = check(rules, docs, rulebook_repo, args.strict)
    errors = load_errors + errors

    n_docs_fm = sum(1 for d in docs if d.has_front_matter)
    print(
        f"rules pack: {len(rules)} rules from {rules_repo}\n"
        f"rationale docs: {len(docs)} ({n_docs_fm} with front-matter)\n"
    )

    for w in warnings:
        print(f"WARN  {w}")
    for e in errors:
        print(f"ERROR {e}")

    if errors:
        print(f"\nFAILED: {len(errors)} error(s), {len(warnings)} warning(s).")
        return 1
    print(f"\nOK: rulebook consistent ({len(warnings)} warning(s)).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
