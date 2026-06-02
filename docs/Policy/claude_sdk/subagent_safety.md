---
policy_id: claude_sdk_subagent_safety
category: claude_sdk
topic: subagent_safety
rules:
  - id: CSDK-110
    severity: high
    confidence: 0.9
    scope: subagent
    fix_type: config
  - id: CSDK-111
    severity: high
    confidence: 0.85
    scope: subagent
    fix_type: config
references: [LLM06, LLM01]
---

# Policy Rationale: Subagent Frontmatter Safety

**Policy ID:** `claude_sdk_subagent_safety`  
**File:** `claude_sdk/subagent_safety.yaml`  
**Rules:** CSDK-110, CSDK-111  
**Severities:** high, high  
**Fix types:** config, config  
**References:** LLM06, LLM01

> Related: [agent_safety.md](agent_safety.md) covers the same over-granting threat
> for in-code `AgentDefinition` subagents. This document covers the markdown
> (`.claude/agents/*.md`) subagent surface.

---

## What this policy covers

`.claude/agents/*.md` subagent declarations — the markdown-frontmatter form of a
Claude Code subagent — whose `tools:` list grants a dangerous built-in. These fire
per subagent file (scope: subagent), matched at any path depth, via the
`subagent_grants_tool` predicate: CSDK-110 grants `Bash`; CSDK-111 grants a
filesystem-write (`Write`/`Edit`) or `WebFetch` built-in. Because the surface is
markdown frontmatter, these rules carry no `language:` field and fire regardless of
the surrounding codebase — including on flat subagent collections that ship no SDK
code at all.

---

## Why subagent frontmatter is a distinct concern in agent tools

A markdown subagent is dispatched autonomously, the same as an in-code
`AgentDefinition` (see [agent_safety.md](agent_safety.md) for the shared
autonomous-dispatch threat model), but it has two properties that make the
frontmatter grant especially worth flagging. First, the `tools:` list in
frontmatter is the subagent's entire privilege grant — there is no code review
around it, just a YAML list that is easy to copy-paste over-broadly from an example.
Second, these files spread: subagent collections are shared and forked across repos,
so an over-granted `Bash` subagent template propagates its blast radius wherever it
is reused.

A narrowly-scoped subagent — a search specialist, a doc summarizer — rarely needs
shell, write, or fetch. Granting them widens what a compromised or misdirected
subagent can do: `Bash` is arbitrary command execution (OWASP LLM06, excessive
agency); write built-ins let it modify source, config, or the `.claude/` settings
that govern it (also LLM06); `WebFetch` pulls attacker-controllable URL content back
into the loop (OWASP LLM01, prompt injection) and is an SSRF surface besides.

---

## Rule-by-rule defense

### CSDK-110 — Subagent granted the built-in Bash tool (Severity: high, Confidence: 0.9, Fix type: config)

**What we detect:** A `.claude/agents/*.md` subagent whose frontmatter `tools:`
list contains `Bash` (`subagent_grants_tool: [Bash]`, matching parsed grants so
`Bash(...)` parametered forms count too).

**Why it is flaggable:** `Bash` is arbitrary shell execution granted to an
autonomously-dispatched subagent, declared in an easily-overcopied YAML list.

**Real-world consequence:** A read-only "code reviewer" subagent template that ships
with `tools: [Read, Grep, Bash]` lets any repo that adopts it run model-chosen shell
commands during an autonomous review.

**Why severity is high and not medium:** Shell access is maximal agency; the markdown
form spreads by copy. Not critical because a trigger is still required.

**Fix type — config:** Remove `Bash` from the `tools:` list (a frontmatter edit);
for read-only roles prefer `Read`, `Grep`, `Glob`.

**Confidence 0.9:** The grant is read directly from frontmatter, so the match is
unambiguous; the gap is the genuinely shell-needing subagent (a build/test runner).

### CSDK-111 — Subagent granted filesystem-write or web-fetch built-ins (Severity: high, Confidence: 0.85, Fix type: config)

**What we detect:** A subagent whose frontmatter `tools:` grants `Write`, `Edit`,
or `WebFetch`.

**Why it is flaggable:** Write built-ins let the subagent modify source, config, or
its own `.claude/` controls; `WebFetch` pulls attacker-controllable content into the
loop and can be aimed at internal addresses.

**Real-world consequence:** A summarizer subagent granted `WebFetch` is steered to
fetch an attacker page (instructions re-enter the loop) or an internal metadata URL;
a "formatter" granted `Edit` rewrites files beyond its remit.

**Why severity is high and not medium:** Write is self-amplifying and `WebFetch`
combines injection and SSRF; both are ungated in frontmatter. Not critical pending a
trigger.

**Fix type — config:** Remove `Write`/`Edit`/`WebFetch` from `tools:` unless the
role needs them; gate fetching with a PreToolUse host allowlist.

**Confidence 0.85:** Slightly below CSDK-110 because editor and fetcher roles more
often have a legitimate need than a pure shell grant does.

---

## What this policy does not cover

- Whether the grant is justified by the subagent's real role — these are review
  prompts, not verdicts.
- Built-ins beyond the matched names, and custom/MCP tools (`mcp__server__tool`)
  that may be equally dangerous.
- A PreToolUse hook that already gates the granted tool (invisible to the static
  frontmatter check — a false positive).
- The subagent's `permissionMode` frontmatter and whether the dispatching parent
  validates the task it passes down.

---

## Recommendations beyond the fix

```markdown
---
name: code-reviewer
description: Read-only review of code and docs. Cannot run commands or edit files.
tools: Read, Grep, Glob
---

Review the requested files and report findings. You have no shell, write, or
fetch access.
```

1. Default subagent templates to read-only tool sets (`Read`, `Grep`, `Glob`); add a
   privileged built-in only when the role demonstrably needs it.
2. Audit shared/forked subagent collections before adopting them — an over-granted
   template carries its blast radius into your repo.
3. Where a privileged built-in is required, pair it with a PreToolUse hook that
   allowlists exact commands, paths, or hosts.
