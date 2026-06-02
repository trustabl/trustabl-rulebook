---
policy_id: claude_sdk_repo_hygiene
category: claude_sdk
topic: repo_hygiene
rules:
  - id: CSDK-203
    severity: low
    confidence: 0.9
    scope: repo
    fix_type: config
references: [LLM06]
---

# Policy Rationale: Repository Hygiene

**Policy ID:** `claude_sdk_repo_hygiene`  
**File:** `claude_sdk/repo_hygiene.yaml`  
**Rules:** CSDK-203  
**Severities:** low  
**Fix types:** config  
**References:** LLM06

> This is the canonical repo-hygiene rationale. The OpenAI (OAI-202) and Google
> ADK (ADK-201) "missing CLAUDE.md" rules cross-reference this document.

---

## What this policy covers

A repo-scoped check: the repository uses the Claude Agent SDK in code
(`repo_has_sdk_in_code: [claude_agent_sdk]`) but ships no top-level CLAUDE.md
(`not repo_component_present: [claude_md]`). It fires once per scan.

---

## Why a missing CLAUDE.md is a distinct concern in agent projects

CLAUDE.md is the in-repo contract an agent reads before it acts. A human
maintainer onboards from a README, a wiki, and tribal knowledge; an agent has
only what is in the tree. When a repo that ships agent-SDK code has no CLAUDE.md,
any Claude session that opens it has no project-specific guidance — the build and
test commands, the lint scripts, the commit conventions, and the "do not touch"
boundaries are all absent. The agent infers them from source on every session and
frequently guesses wrong: bypassing the project's lint, running the wrong test
command, or violating commit conventions that were never written where it could
read them. The cost compounds, because each new contributor — human or agent —
reinvents the same wrong assumptions.

It is a low-severity *hygiene* signal, not a security defect: nothing is exploited
by the absence of a CLAUDE.md. But for an SDK whose own convention is to read one,
shipping agent code without it is a self-inflicted reliability tax, which is why it
anchors loosely to OWASP LLM06 (Excessive Agency) — the agent acts with less
guidance than the project could have given it.

---

## Rule-by-rule defense

### CSDK-203 — Repo ships Claude Agent SDK code without a CLAUDE.md (Severity: low, Confidence: 0.9, Fix type: config)

**What we detect:**
The inventory observes Claude Agent SDK usage in code, and no `claude_md`
component is present anywhere in the scanned tree.

**Why it is flaggable:**
An SDK whose convention is to read CLAUDE.md is being used in a repo that provides
none, so every agent session starts without project guidance.

**Real-world consequence:**
A contributor points Claude at the repo; with no CLAUDE.md it runs `pytest`
when the project uses `make test`, or edits a generated file it should not touch,
because nothing in-tree told it the rules.

**Why severity is low and not medium:**
It degrades reliability and onboarding, not security; a single well-formed
CLAUDE.md fully resolves it. High *confidence* (0.9) because the check is a direct
presence test, but low *impact*.

**Fix type — config:**
Add a CLAUDE.md at the repo root — a documentation/config artifact, no source
change.

**Confidence 0.9:**
The only realistic false positive is a repo that deliberately keeps its agent
guidance elsewhere (an unusual choice); the presence check is otherwise
unambiguous.

---

## What this policy does not cover

- The *quality* of a CLAUDE.md that is present — an empty or stale file satisfies
  the rule without guiding anything.
- Per-directory CLAUDE.md files for monorepos where a root file is intentionally
  absent (could be a false positive depending on layout).
- Whether the agent actually reads the CLAUDE.md (that is the harness's behavior,
  not the repo's).

---

## Recommendations beyond the fix

Add a root `CLAUDE.md` documenting, concretely:

1. How to build, test, and lint the project (exact commands).
2. The coding conventions Claude must respect, and the directories/files it must
   not modify.
3. Any project-specific safety rules (required guardrails, sandboxing, secrets
   handling).

Keep it short and imperative so an editing agent can act on it without
re-deriving the rules each session.
