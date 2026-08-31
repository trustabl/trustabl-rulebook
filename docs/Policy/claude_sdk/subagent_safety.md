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
  - id: CSDK-112
    severity: medium
    confidence: 0.8
    scope: subagent
    fix_type: config
  - id: CSDK-113
    severity: critical
    confidence: 0.9
    scope: subagent
    fix_type: config
references: [LLM06, LLM01]
---

# Policy Rationale: Subagent Frontmatter Safety

**Policy ID:** `claude_sdk_subagent_safety`  
**File:** `claude_sdk/subagent_safety.yaml`  
**Rules:** CSDK-110, CSDK-111, CSDK-112, CSDK-113  
**Severities:** high, high, medium, critical  
**Fix types:** config, config, config, config  
**References:** LLM06, LLM01

> Related: [agent_safety.md](agent_safety.md) covers the same over-granting threat
> for in-code `AgentDefinition` subagents. This document covers the markdown
> (`.claude/agents/*.md`) subagent surface.

---

## What this policy covers

`.claude/agents/*.md` subagent declarations — the markdown-frontmatter form of a
Claude Code subagent — whose frontmatter either grants a dangerous built-in or
switches off approval prompting outright. These fire per subagent file (scope:
subagent), matched at any path depth. Three rules read the `tools:` list via the
`subagent_grants_tool` predicate: CSDK-110 grants `Bash`; CSDK-111 grants a
filesystem-write (`Write`/`Edit`/`MultiEdit`/`NotebookEdit`) or `WebFetch`
built-in; CSDK-112 grants `WebSearch`. CSDK-113 reads the `permissionMode:`
field via the `subagent_permission_mode_is` predicate and fires when it is
`bypassPermissions`. Because the surface is markdown
frontmatter, these rules carry no `language:` field and fire regardless of the
surrounding codebase — including on flat subagent collections that ship no SDK
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

The frontmatter carries the subagent's approval posture as well as its grants,
and the posture field is the more dangerous of the two. `permissionMode:
bypassPermissions` removes the permission prompt for every tool the subagent
runs, for the whole time it is dispatched — the `tools:` list stops being a list
of things the subagent may ask to do and becomes a list of things it will do
unsupervised. This is the same posture CSDK-201 flags in
`.claude/settings.json` and CSDK-202 flags on `ClaudeAgentOptions(...)`,
declared on the surface where it is hardest to notice: a subagent is dispatched
autonomously by a lead agent in response to a model-generated task description,
so nobody is reading this file — or approving anything — at the moment the
bypass takes effect.

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
`MultiEdit`, `NotebookEdit`, or `WebFetch`. The multi-file and notebook editors
are matched alongside `Write`/`Edit` because they reach the same write surface —
omitting them would let a `tools: [MultiEdit]` grant escape the check while an
equivalent `Edit` grant fires.

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

### CSDK-112 — Subagent granted the WebSearch tool (Severity: medium, Confidence: 0.8, Fix type: config)

**What we detect:** A subagent whose frontmatter `tools:` grants `WebSearch`
(`subagent_grants_tool: [WebSearch]`). This is the subagent-scope analogue of the
agent-scope CSDK-102 check on in-code `AgentDefinition` grants — before this rule,
the same grant declared in markdown frontmatter was unaudited.

**Why it is flaggable:** Search results are attacker-reachable text: anyone can
publish a page that ranks for a query the subagent is likely to make, so the grant
opens a prompt-injection channel (OWASP LLM01) into an autonomously-dispatched
worker whose output the parent loop usually trusts.

**Real-world consequence:** A research subagent granted `WebSearch` retrieves an
attacker-planted page whose content instructs it to misreport findings or to steer
the parent toward a malicious dependency; the injected conclusion flows back to the
parent as the subagent's answer.

**Why severity is medium and not high:** Matching CSDK-102's calibration — search
returns provider-mediated snippets rather than raw page content, so the injection
surface is narrower than `WebFetch`, and the tool itself has no write or execution
reach. The risk compounds only when paired with side-effecting grants, which
CSDK-110/111 flag separately.

**Fix type — config:** Remove `WebSearch` from the `tools:` list unless the role is
genuinely research-oriented (a frontmatter edit).

**Confidence 0.8:** The grant is unambiguous in frontmatter; the gap is the
legitimately research-oriented subagent, which is a more common role than a
shell-needing one.

### CSDK-113 — Subagent frontmatter bypasses permission prompts (Severity: critical, Confidence: 0.9, Fix type: config)

**What we detect:** A subagent whose frontmatter sets `permissionMode:
bypassPermissions` (`subagent_permission_mode_is: [bypassPermissions]`). The
predicate reads the parsed `permissionMode` field off the `SubagentDef` and
matches the listed value exactly and case-sensitively, as Claude Code's own
mode values are; only the full-bypass value fires — `default` and `acceptEdits`
do not.

**Why it is flaggable:** The permission prompt is the one in-band
human-in-the-loop control between a model-chosen tool call and its effect on
the host. This setting removes it for every tool the subagent runs, for the
whole time it is dispatched, so the grant list stops describing what the
subagent may ask to do and starts describing what it will do unsupervised. The
frontmatter form activates with no human present: the subagent is dispatched
autonomously by a lead agent in response to a model-generated task description,
so a prompt injection that reaches the lead agent reaches the subagent's tools
with the approval gate already removed. And a subagent that omits `tools:`
entirely inherits the parent's full tool set — bypass plus the default grant is
everything, unprompted.

**Real-world consequence:**
- A "deploy helper" subagent with `permissionMode: bypassPermissions` and
  `Bash` in `tools:` is dispatched to summarize a README carrying injected
  instructions; the injected `curl | sh` executes without a prompt ever being
  shown to anyone.
- A forked subagent collection carries the bypass in one file; every repo that
  adopts it runs that subagent's writes and commands unprompted, and no adopter
  reads the frontmatter at dispatch time.

**Why severity is critical and not high:** This matches the calibration of the
rest of the bypassPermissions family — CSDK-103/120 for in-code
`AgentDefinition`s, CSDK-201 for the project, CSDK-202 for the session. The
grant rules above stay at high because the approval prompt still stands between
a granted tool and its effect; this rule flags the removal of that prompt
itself, and no partial mitigation exists inside the flagged file: narrowing the
grant list shrinks what runs unsupervised but restores approval for none of it,
and a PreToolUse hook that might compensate lives elsewhere and is implied by
nothing here. Within the family, this is the surface where the bypass is
hardest to catch — the project and session forms at least take effect where a
human started a session, while a subagent bypass takes effect on
model-initiated dispatch, with nobody watching even at activation.

**Fix type — config:** Delete the `permissionMode` line so the subagent
inherits the session's mode and its tool calls prompt, or set it to `default` —
a one-line frontmatter edit, no code.

**Confidence 0.9:** The value is read directly from parsed frontmatter, so the
match itself is essentially exact. The gap covers the file that is present but
never dispatched (an example or vendored collection) and the subagent whose
grant list is genuinely read-only, where most granted calls would auto-approve
anyway and the bypass changes little — though it still silences prompts for
anything later added to that list.

---

## What this policy does not cover

- Whether the grant is justified by the subagent's real role — these are review
  prompts, not verdicts.
- Built-ins beyond the matched names, and custom/MCP tools (`mcp__server__tool`)
  that may be equally dangerous.
- A PreToolUse hook that already gates the granted tool (invisible to the static
  frontmatter check — a false positive for the grant rules, and a compensating
  control CSDK-113 cannot see either).
- Whether the dispatching parent validates the task it passes down to the
  subagent.
- Permission modes short of full bypass: `permissionMode: acceptEdits`
  auto-approves file edits without firing CSDK-113. The match is exact and
  case-sensitive, so a miscased value escapes the rule — though Claude Code
  would not honor it either.
- A bypass declared outside frontmatter: in-code `AgentDefinition`
  `permissionMode` is CSDK-103/120's job (see
  [agent_safety.md](agent_safety.md)), and project/session-level bypass is
  CSDK-201/202's (see [repo.md](repo.md)).
- CSDK-113 fires at critical even when the subagent's grants are read-only
  (`Read`, `Grep`, `Glob`) — a configuration with a small unsupervised surface
  today, though the bypass silently extends to any grant added later.

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
4. Never set `permissionMode: bypassPermissions` in a shared subagent file. If
   a subagent genuinely must run unattended, keep its `tools:` list to the
   minimum the job needs and gate the dangerous ones with a PreToolUse hook —
   an unattended subagent with a wide grant list is the combination CSDK-113
   exists to prevent.
