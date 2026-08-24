#!/usr/bin/env python3
"""Internal-link gate for the rulebook.

Every relative markdown link in this repo must resolve, and every `#anchor`
must name a heading that exists in the target file. A rationale doc that defers
its threat model to a sibling — "Read openai_sdk/ssrf.md for the full rationale"
— is only as good as that link; when the target moves or was never written, the
reader is left with the half of the argument that was deferred away.

Nothing else checks this. check_rulebook.py validates a doc against the rule
pack; the links between docs are invisible to it.

Links inside fenced code blocks are skipped: the template guide illustrates the
cross-reference pattern with a sample path that is correct from a policy doc's
location and not from the guide's own.

Usage:
    python3 tools/check_links.py [--root PATH]

Exit code: 0 = every link resolves, 1 = at least one does not.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# .rules is where the CI workflow checks out trustabl-rules, inside this repo.
# Without skipping it this gate would walk that repo's markdown and fail the
# rulebook's build over links belonging to a different project.
SKIP_DIRS = {".git", ".rules", "build", "node_modules"}
# [text](target) where target is not a URL, mailto:, or a bare anchor.
LINK_RE = re.compile(r"\[[^\]]*\]\((?!https?://|mailto:|#)([^)\s]+?)(#[^)\s]*)?\)")
HEADING_RE = re.compile(r"^#{1,6}\s+(.+?)\s*$", re.MULTILINE)
FENCE_RE = re.compile(r"^\s*(```|~~~)")


def strip_fences(text: str) -> str:
    """Blank out fenced code blocks, preserving line count for reporting."""
    out, in_fence = [], False
    for line in text.splitlines():
        if FENCE_RE.match(line):
            in_fence = not in_fence
            out.append("")
            continue
        out.append("" if in_fence else line)
    return "\n".join(out)


def slug(heading: str) -> str:
    """GitHub's heading-anchor slug: lowercase, drop punctuation, spaces to -."""
    s = heading.strip().lower()
    s = re.sub(r"[^\w\s-]", "", s)
    return re.sub(r"\s+", "-", s)


def anchors(path: Path) -> set[str]:
    return {slug(h) for h in HEADING_RE.findall(path.read_text(encoding="utf-8"))}


def markdown_files(root: Path) -> list[Path]:
    return sorted(
        p for p in root.rglob("*.md")
        if not any(part in SKIP_DIRS for part in p.relative_to(root).parts)
    )


def check(root: Path) -> list[str]:
    errors: list[str] = []
    for md in markdown_files(root):
        body = strip_fences(md.read_text(encoding="utf-8"))
        for m in LINK_RE.finditer(body):
            target, anchor = m.group(1), (m.group(2) or "")[1:]
            rel = md.relative_to(root).as_posix()
            dest = (md.parent / target).resolve()
            if not dest.exists():
                errors.append(f"{rel}: link target does not exist: {target}")
                continue
            if anchor and dest.suffix == ".md" and slug(anchor) not in anchors(dest):
                errors.append(f"{rel}: {target} has no heading anchor #{anchor}")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser(description="Check internal markdown links.")
    ap.add_argument(
        "--root",
        default=str(Path(__file__).resolve().parent.parent),
        help="repository root to scan (default: this repo)",
    )
    args = ap.parse_args()
    root = Path(args.root).resolve()

    errors = check(root)
    print(f"checked {len(markdown_files(root))} markdown file(s) under {root}\n")
    for e in errors:
        print(f"ERROR {e}")
    if errors:
        print(f"\nFAILED: {len(errors)} broken link(s).")
        return 1
    print("OK: every internal link and anchor resolves.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
