---
policy_id: langchain_repo_hygiene
category: langchain
topic: repo_hygiene
rules:
  - id: LC-201
    severity: low
    confidence: 0.9
    scope: repo
    fix_type: config
references: [LLM06]
---

# Policy Rationale: LangChain Repo Hygiene

**Policy ID:** `langchain_repo_hygiene`
**File:** `langchain/repo_hygiene.yaml`
**Rules:** LC-201
**Severities:** low
**Fix types:** config
**References:** LLM06 (Excessive Agency)

> This rule is one of the cross-SDK "missing agent-guidance doc" family. See
> [openai_sdk/repo_hygiene.md](../openai_sdk/repo_hygiene.md) and
> [google_adk/repo_hygiene.md](../google_adk/repo_hygiene.md) for the shared
> rationale; this document covers the LangChain-specific framing.

---

## What this policy covers

A repo that uses LangChain / LangGraph in code (`SDKLangChain` observed in the
inventory) but ships no agent-guidance doc — neither `AGENTS.md` (the cross-vendor
convention) nor `CLAUDE.md` — at any depth. Fires once per scan
(`repo_has_sdk_in_code: [langchain]` AND NOT `repo_component_present: [agents_md,
claude_md]`). It carries no `language` field, so it fires for both Python and
TypeScript LangChain repos.

---

## Why a missing guidance doc matters for a LangChain repo

An editing coding agent reads `AGENTS.md` before it acts. With neither file present,
any agent that opens this repo has no project-specific guidance on the choices that
make LangChain code safe or unsafe, and LangChain offers an unusually wide menu of
those choices:

- which agent constructor to use — `create_react_agent` (deprecated), the v1
  `create_agent`, the legacy `AgentExecutor`, or a raw `StateGraph`;
- how tools must be defined (typed `args_schema`, descriptions) and guarded;
- whether the REPL/shell built-ins (`PythonREPLTool`, `ShellTool`) are permitted at
  all, and behind what sandbox/approval;
- the local test, lint, and build commands.

Without that guidance, a generative agent reaches for the most-documented pattern —
often the deprecated one, or a REPL tool — and produces code that violates the
project's tool and agent contracts. That is a slow-acting excessive-agency risk
(LLM06): nothing in-tree teaches the next agent the local rules.

---

## Rule-by-rule defense

### LC-201 — LangChain project ships no agent-guidance doc (Severity: low, Confidence: 0.9, Fix type: config)

**What we detect:** `SDKLangChain` in `SDKsDetected` and no `agents_md` or
`claude_md` component anywhere in the repo.

**Why it is flaggable:** the absence is the signal; it is a hygiene gap, not a
runtime vulnerability.

**Severity low:** advisory. **Confidence 0.9:** the check is a near-deterministic
file-presence test; the small residual is a repo that documents agent guidance under
a non-standard filename the component scan does not recognize.

**Fix type — config:** adding a doc file is a repo-config change, not a code edit.

---

## What this policy does not cover

The *quality* of a present `AGENTS.md`/`CLAUDE.md` (any such file silences the
rule), guidance docs under non-standard names, and whether the documented
conventions are actually followed in code.

---

## Recommendations beyond the fix

Add an `AGENTS.md` at the repo root (a `CLAUDE.md` also satisfies the rule). State
which LangChain agent constructors the project uses and why, how tools must be
defined and guarded, whether the REPL/shell built-ins are permitted and behind what
gate, and the exact test, lint, and build commands. Keep it short and concrete so an
editing agent can act on it without re-deriving the conventions.
