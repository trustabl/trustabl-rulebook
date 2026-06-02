#!/usr/bin/env python3
r"""Assemble the rulebook rationale docs into a single Pandoc-ready markdown.

The PDF is a build artifact, never authored by hand: this script projects the
per-policy rationale docs (the chapters) plus a generated rule catalog (the
appendix) into one markdown file, which Pandoc then renders to PDF. Run the
consistency gate (check_rulebook.py) and the index generator (gen_index.py)
first — a book that disagrees with the shipped pack should never be built.

Structure produced (Pandoc + LaTeX `report` class):

    \part{Claude Agent SDK}        <- one part per SDK, in SDK_ORDER
      # Policy Rationale: ...       <- one chapter per topic doc
        ## What this policy covers  <- the doc's own sections
        ...
    \part{OpenAI Agents SDK}
      ...
    \appendix
    \part{Appendix}
      # Rule Catalog                <- compact generated table of all rules

Chapters within a part are ordered by the lowest rule number in the topic, so
the reading order matches the index. Per-doc YAML front-matter is stripped
(Pandoc would mis-parse it mid-document), and intra-rulebook `*.md` links are
flattened to plain text since they do not resolve inside a single PDF.

Usage:
    python tools/build_book.py [--rules-repo PATH] [--out build/trustabl-rulebook.md]
"""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from pathlib import Path

from check_rulebook import load_rules
from gen_index import SDK_FULL, SDK_LABEL, SDK_ORDER, numeric_id, risk_score

FRONT_MATTER = re.compile(r"^---\n.*?\n---\n", re.DOTALL)
# A markdown link whose target points at a rulebook .md file -> keep only the text.
MD_DOC_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\.md[^)]*\)")


def latex(block: str) -> str:
    """Wrap raw LaTeX so Pandoc passes it through verbatim."""
    return "```{=latex}\n" + block + "\n```"


def strip_doc(text: str) -> str:
    text = FRONT_MATTER.sub("", text, count=1)
    text = MD_DOC_LINK.sub(r"\1", text)
    return text.strip()


def topic_order(rules) -> dict[str, list[str]]:
    """For each category, topics ordered by the lowest rule number in them."""
    mins: dict[tuple[str, str], int] = defaultdict(lambda: 10**9)
    for r in rules:
        key = (r.category, r.topic)
        mins[key] = min(mins[key], numeric_id(r.rule_id))
    out: dict[str, list[str]] = {c: [] for c in SDK_ORDER}
    for (cat, topic) in sorted(mins, key=lambda k: (SDK_ORDER.index(k[0]) if k[0] in SDK_ORDER else 99, mins[k])):
        out.setdefault(cat, []).append(topic)
    return out


def appendix_table(rules) -> str:
    """A compact, print-friendly catalog of every rule (no wide URL column)."""
    ordered = sorted(
        rules,
        key=lambda r: (SDK_ORDER.index(r.category) if r.category in SDK_ORDER else 99,
                       numeric_id(r.rule_id), r.rule_id),
    )
    headers = ["Id", "SDK", "Scope", "Sev", "Conf", "Risk", "Policy"]
    rows = [
        [r.rule_id, SDK_LABEL.get(r.category, r.category), r.scope, r.severity,
         f"{r.confidence:.2f}", risk_score(r.severity, r.confidence), r.title]
        for r in ordered
    ]
    widths = [len(h) for h in headers]
    for row in rows:
        for i, c in enumerate(row):
            widths[i] = max(widths[i], len(c))
    def line(cells): return "| " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(cells)) + " |"
    sep = "| " + " | ".join("-" * widths[i] for i in range(len(headers))) + " |"
    return "\n".join([line(headers), sep] + [line(r) for r in rows])


def build(repo: Path, rules_repo: Path) -> str:
    rules_map, errors = load_rules(rules_repo)
    if errors:
        raise SystemExit("rule load errors:\n" + "\n".join(errors))
    rules = list(rules_map.values())
    order = topic_order(rules)
    policy_dir = repo / "docs" / "Policy"

    parts: list[str] = []
    for cat in SDK_ORDER:
        parts.append(latex(f"\\part{{{SDK_FULL[cat]}}}"))
        for topic in order.get(cat, []):
            doc = policy_dir / cat / f"{topic}.md"
            if not doc.exists():
                raise SystemExit(f"missing rationale doc: {doc.relative_to(repo)}")
            parts.append(strip_doc(doc.read_text(encoding="utf-8")))

    parts.append(latex("\\appendix"))
    parts.append(latex("\\part{Appendix}"))
    parts.append("# Rule Catalog\n\nEvery shipped rule, generated from the pack. "
                 "Risk = severity weight × confidence × 100.\n\n"
                 + latex("\\footnotesize") + "\n\n"
                 + appendix_table(rules) + "\n\n"
                 + latex("\\normalsize"))

    return "\n\n".join(parts) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Assemble the rulebook into one markdown for Pandoc.")
    ap.add_argument("--rules-repo", default="../trustabl-rules")
    ap.add_argument("--out", default="build/trustabl-rulebook.md")
    args = ap.parse_args()

    repo = Path(__file__).resolve().parent.parent
    rules_repo = Path(args.rules_repo)
    if not rules_repo.is_absolute():
        rules_repo = (repo / rules_repo).resolve()
    if not rules_repo.is_dir():
        raise SystemExit(f"rules repo not found: {rules_repo}")

    out = repo / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build(repo, rules_repo), encoding="utf-8", newline="\n")
    print(f"wrote {out.relative_to(repo)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
