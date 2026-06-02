---
policy_id: openai_sdk_approvals
category: openai_sdk
topic: approvals
rules:
  - id: OAI-014
    severity: high
    confidence: 0.7
    scope: tool
    fix_type: config
  - id: OAI-111
    severity: high
    confidence: 0.75
    scope: agent
    fix_type: config
references: [LLM06]
---

# Policy Rationale: Tool Approval Gates

**Policy ID:** `openai_sdk_approvals`  
**File:** `openai_sdk/approvals.yaml`  
**Rules:** OAI-014, OAI-111  
**Severities:** high, high  
**Fix types:** config, config  
**References:** LLM06

---

## What this policy covers

The OpenAI Agents SDK's human-in-the-loop `needs_approval` gate on sensitive tool
calls — and the fact that its default is `False` everywhere. OAI-014 (tool scope)
fires when a `@function_tool` that shells out, executes code, or writes the
filesystem sets no `needs_approval` kwarg. OAI-111 (agent scope) fires when an
agent wires a privileged *hosted* tool (`ShellTool`, `LocalShellTool`,
`CodeInterpreterTool`, `ApplyPatchTool`) without `needs_approval=True` on it.
Together they cover both the custom-tool and hosted-tool sides of the same missing
checkpoint.

---

## Why approval gating is a distinct concern in agent tools

A privileged tool — one that runs a command, executes code, or mutates files — is
exactly the kind of action that warrants a human confirmation before it fires,
because its effects are real and hard to undo. The OpenAI Agents SDK provides that
confirmation as a first-class mechanism: `needs_approval`, which pauses the run and
emits an approval item the application can accept or reject. The catch is that it
defaults to `False`. So a privileged tool ships *un-gated* unless the author opts
in — the safe behavior is the one you have to remember to ask for.

In an agentic loop the tool's arguments are model-generated and the dispatch is
autonomous, so "the model decided to run this command" is not a human decision. An
un-gated privileged tool means attacker-influenced model output reaches a shell,
an interpreter, or the filesystem with no checkpoint. This is OWASP LLM06
(Excessive Agency) in its most literal form: the agent can take a high-impact
action with no human in the loop. These rules complement the capability checks
(OAI-012 subprocess, OAI-013 code-exec, OAI-006 path) — those flag the dangerous
operation; these flag the missing gate around it.

Both fixes are *config*: `needs_approval` is a decorator/constructor keyword
argument, set without changing tool logic.

---

## Rule-by-rule defense

### OAI-014 — Privileged tool has no needs_approval gate (Severity: high, Confidence: 0.7, Fix type: config)

**What we detect:** a `@function_tool` whose body shells out, runs `eval`/`exec`/
`compile`, or writes the filesystem (`has_shell_call` / `has_code_exec_call` /
`has_write_call`) and has no `needs_approval` kwarg.

**Why it is flaggable:** the privileged operation executes model-chosen input with
no human checkpoint, because `needs_approval` defaults to `False`.

**Real-world consequence:** a `run_shell(cmd)` tool fires whatever the model
produced — there is no approval prompt to catch an injected `rm -rf` or an
exfiltration command.

**Why severity is high and not medium:** it leaves a high-impact, hard-to-undo
operation ungated; the missing gate is the difference between "model proposed" and
"system executed."

**Fix type — config:** add `needs_approval=True` and handle approval items in the
run loop, or gate the tool with `input_guardrails` at the agent level.

**Confidence 0.7:** a tool may be deliberately auto-approved behind an
agent-level guardrail or run in a trusted sandbox, which the tool-local check
cannot see — hence 0.7 rather than higher.

### OAI-111 — Agent wires a privileged hosted tool without needs_approval (Severity: high, Confidence: 0.75, Fix type: config)

**What we detect:** an agent whose `tools` include `ShellTool`, `LocalShellTool`,
`CodeInterpreterTool`, or `ApplyPatchTool` without `needs_approval=True` set on
that hosted tool (`agent_uses_hosted_tool_class` + `not
agent_hosted_tool_kwarg_value … "True"`).

**Why it is flaggable:** the SDK's own privileged hosted tools default
`needs_approval=False`, so the model runs commands, code, or file edits unattended
unless the author opts in.

**Real-world consequence:** an agent wired with `CodeInterpreterTool()` (no
approval) executes model-written code directly; one prompt-injection becomes
arbitrary code execution.

**Why severity is high and not medium:** identical exposure to OAI-014 but on the
SDK's built-in privileged tools, which are easy to add with a single constructor
and easy to forget to gate.

**Fix type — config:** construct the hosted tool with `needs_approval=True` (and
handle approval items), or front the agent with `input_guardrails`; prefer
`SandboxAgent` to bound what the tool can reach.

**Confidence 0.75:** an agent-level guardrail or sandbox may make auto-approval a
deliberate, safe choice the rule cannot detect.

---

## What this policy does not cover

- Tools made safe by an agent-level `input_guardrail` rather than `needs_approval` —
  a deliberate alternative the rule reads as ungated (false positive).
- Privileged operations performed through libraries the capability predicates do not
  match (async spawn, `os.exec*`, non-listed hosted tools).
- Whether an approval handler, once wired, actually presents the action meaningfully
  to a human or rubber-stamps it.
- `needs_approval` set dynamically from a variable the scanner cannot resolve.

---

## Recommendations beyond the fix

```python
from agents import Agent, function_tool
from agents.tools import CodeInterpreterTool

@function_tool(needs_approval=True)
def run_migration(name: str) -> dict:
    """Run a named database migration. Requires human approval."""
    ...

agent = Agent(
    name="ops",
    tools=[run_migration, CodeInterpreterTool(needs_approval=True)],
)
```

1. Set `needs_approval=True` on every tool that runs commands, executes code, or
   mutates state, and implement the approval-item handling in your run loop.
2. Where approval must be automated, replace the human gate with an
   `input_guardrail` that screens what can reach the tool, and document why.
3. Run privileged tools under a `SandboxAgent` so an approved-but-malicious action
   is still bounded.
