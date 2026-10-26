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
  - id: CSDK-115
    severity: high
    confidence: 0.75
    scope: subagent
    fix_type: config
references: [LLM06, LLM01]
---

# Policy Rationale: Subagent Frontmatter Safety

**Policy ID:** `claude_sdk_subagent_safety`  
**File:** `claude_sdk/subagent_safety.yaml`  
**Rules:** CSDK-110, CSDK-111, CSDK-112, CSDK-115  
**Severities:** high, high, medium, high  
**Fix types:** config, config, config, config  
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
filesystem-write (`Write`/`Edit`/`MultiEdit`/`NotebookEdit`) or `WebFetch`
built-in; CSDK-112 grants `WebSearch`. Because the surface is markdown
frontmatter, these rules carry no `language:` field and fire regardless of the
surrounding codebase — including on flat subagent collections that ship no SDK
code at all.

CSDK-115 covers the subagent that declares no grant at all: a subagent file in a
`.claude/agents/` directory whose frontmatter has no `tools:` key and no
`disallowedTools:` entries. The match is a single predicate,
`subagent_inherits_all_tools: true`. Unlike the three grant rules, CSDK-115 does
not check markdown files found outside `.claude/agents/`, such as plugin
`agents/` directories and flat collections.

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

When the `tools:` key is absent, there is no list to review. Claude Code's
subagents documentation states that a subagent with `tools` omitted inherits all
tools available to subagents: the built-in tools and MCP tools available in the
main conversation, narrowed by one filter that removes a short list of tools
from all subagents and a second that reduces the built-in tools of a subagent
running in the background. The built-in tools it lists as kept in the background
include `Bash`, `Write`, `Edit` and `WebFetch`, and a background subagent keeps
its MCP tools. The same documentation states that `disallowedTools` removes
tools from the inherited or specified list. The pack's explanation says such a
subagent therefore gets whichever of Bash, file-write, web-fetch and MCP tools
the main conversation has, whatever its description says its job is. Claude
Code's documentation also states that Claude decides when to delegate to a
subagent and composes the delegation message the subagent works from. If
instructions that steer the main conversation reach that message, they can
reach the subagent and the tools it inherited.

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

### CSDK-115 — Subagent omits tools and inherits the full subagent tool pool (Severity: high, Confidence: 0.75, Fix type: config)

**What we detect:** A subagent file in a `.claude/agents/` directory whose
frontmatter has no `tools:` key and no `disallowedTools:` entries
(`subagent_inherits_all_tools: true`).

**Why it is flaggable:** The mechanism is the one stated
[above](#why-subagent-frontmatter-is-a-distinct-concern-in-agent-tools): a
subagent with `tools` omitted inherits all tools available to subagents, and the
pack's explanation says it gets whichever of Bash, file-write, web-fetch and MCP
tools the main conversation has, whatever its description says its job is.

**Real-world consequence:** If a review subagent's frontmatter sets `name` and
`description` and nothing else, and the main conversation has `Bash` and a
connected MCP server, the review subagent can run shell commands and call that
server's tools. If instructions that steer the main conversation reach the
delegation message Claude composes for it, the subagent can act on them with
those tools.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Fix type — config:** The pack's fix is a frontmatter edit. Add a `tools:` list
naming the tools the role needs, for example `tools: Read, Grep, Glob` for a
review or search role. If the subagent needs most of the pool, keep `tools`
omitted and add a `disallowedTools:` list for the tools it must not reach, such
as `Bash`, `Write`, `Edit` or `mcp__*`.

**Confidence 0.75:** The pack sets 0.75 and states these limits of the check. The
rule reads the frontmatter alone and cannot see which tools the main conversation
has, so it cannot tell how wide the inherited pool is. A `tools:` key with an
empty or null value counts as declared and stays silent. Any `disallowedTools:`
entry silences the rule, whatever it removes. Markdown files found outside
`.claude/agents/` (plugin `agents/` directories, flat collections) are not
checked. In-code `AgentDefinition` subagents are covered by CSDK-103 and CSDK-120
when they also set `bypassPermissions`, and are not checked here.

---

## What this policy does not cover

For CSDK-110, CSDK-111 and CSDK-112:

- Whether the grant is justified by the subagent's real role — these are review
  prompts, not verdicts.
- Built-ins beyond the matched names, and custom/MCP tools (`mcp__server__tool`)
  that may be equally dangerous.
- A PreToolUse hook that already gates the granted tool (invisible to the static
  frontmatter check — a false positive).
- The subagent's `permissionMode` frontmatter and whether the dispatching parent
  validates the task it passes down.

For CSDK-115:

- **How wide the inherited pool is.** The rule reads the frontmatter alone and
  cannot see which tools the main conversation has.
- **An empty or null `tools:` value.** A `tools:` key with an empty or null value
  counts as declared and stays silent.
- **What a `disallowedTools:` list removes.** Any `disallowedTools:` entry
  silences the rule, whatever it removes.
- **Subagent files outside `.claude/agents/`.** Plugin `agents/` directories and
  flat collections are not checked.
- **In-code `AgentDefinition` subagents.** CSDK-103 and CSDK-120 cover them when
  they also set `bypassPermissions` (see [agent_safety.md](agent_safety.md)), and
  CSDK-115 does not check them.
- **Files the engine does not parse as subagents.** A `.claude/agents/` file with
  no frontmatter, with frontmatter that is not valid YAML, or with no `name:`
  yields no subagent, so CSDK-115 does not fire on it.
- The pack states no other limits for this rule.

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

The example above declares `tools:` and is silent for CSDK-115. A subagent that
needs most of the pool can keep `tools` omitted and name what it must not reach
in `disallowedTools:`. This example is silent for CSDK-115:

```markdown
---
name: doc-editor
description: Edits Markdown docs in this repo. Has no shell, web fetch or web search.
disallowedTools: Bash, WebFetch, WebSearch
---

Edit the requested Markdown files. You have no shell, web fetch or web search
access.
```

It still inherits the rest of the pool, including the MCP tools of the main
conversation. The pack's fix names `mcp__*` as a `disallowedTools:` entry for a
subagent that must not reach MCP tools.

1. Default subagent templates to read-only tool sets (`Read`, `Grep`, `Glob`); add a
   privileged built-in only when the role demonstrably needs it.
2. Audit shared/forked subagent collections before adopting them — an over-granted
   template carries its blast radius into your repo.
3. Where a privileged built-in is required, pair it with a PreToolUse hook that
   allowlists exact commands, paths, or hosts.
4. Give subagent templates a `tools:` list, or a `disallowedTools:` list when the
   role needs most of the pool, so a copied template does not inherit the tool
   pool of the conversation that adopts it.
