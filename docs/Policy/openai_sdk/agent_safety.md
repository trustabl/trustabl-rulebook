---
policy_id: openai_sdk_agent_safety
category: openai_sdk
topic: agent_safety
rules:
  - id: OAI-101
    severity: high
    confidence: 0.85
    scope: agent
    fix_type: config
  - id: OAI-102
    severity: high
    confidence: 0.95
    scope: agent
    fix_type: config
  - id: OAI-103
    severity: high
    confidence: 0.95
    scope: agent
    fix_type: config
  - id: OAI-104
    severity: medium
    confidence: 0.75
    scope: agent
    fix_type: config
  - id: OAI-109
    severity: high
    confidence: 0.85
    scope: agent
    fix_type: config
  - id: OAI-110
    severity: high
    confidence: 0.6
    scope: agent
    fix_type: config
references: [LLM01, LLM06]
---

# Policy Rationale: Agent Wiring Safety

**Policy ID:** `openai_sdk_agent_safety`  
**File:** `openai_sdk/agent_safety.yaml`  
**Rules:** OAI-101, OAI-102, OAI-103, OAI-104, OAI-109, OAI-110  
**Severities:** high, high, high, medium, high, high  
**Fix types:** config, config, config, config, config, config  
**References:** LLM01, LLM06

---

## What this policy covers

How an OpenAI Agents SDK `Agent(...)` / `SandboxAgent(...)` is wired — its
guardrails, its tool-loop controls, its class choice, and the hosted tools it
mounts. These fire per agent (scope: agent) on the constructor kwargs and the
resolved tool graph: OAI-101 (no `input_guardrails` while wiring shell/filesystem
tools), OAI-102 (`tool_use_behavior="stop_on_first_tool"`), OAI-103
(`tool_choice="required"` + `reset_tool_choice=False`), OAI-104 (raw `Agent`, not
`SandboxAgent`, with shell/filesystem tools), OAI-109 (`WebSearchTool` without
`input_guardrails`), OAI-110 (a content-fetching hosted tool without
`output_guardrails`).

---

## Why agent wiring is a distinct concern in agent tools

A tool's safety is necessary but not sufficient; the *agent* decides which tools to
call, in what loop, and with what screening around them. The OpenAI Agents SDK
gives authors the controls to make those decisions safe — `input_guardrails` /
`output_guardrails` to screen ingress and egress, `SandboxAgent` to confine
privileged tools, sane defaults for the tool loop — but each can be omitted or
overridden into an unsafe shape. These rules detect the unsafe wirings.

Two threat lines run through them. The **prompt-injection** line (OWASP LLM01):
an agent that wires shell/filesystem tools (OAI-101), web search (OAI-109), or a
content-fetching tool (OAI-110) is ingesting or acting on untrusted input, and the
SDK's guardrails are the primary screen — missing them leaves the model's
instruction and egress channels unprotected. The **excessive-agency / loop-control**
line (OWASP LLM06): `stop_on_first_tool` (OAI-102) makes a raw, possibly
attacker-controlled tool output the final response with no model post-processing;
`tool_choice="required"` with `reset_tool_choice=False` (OAI-103) is the SDK's
documented infinite-tool-loop footgun; a raw `Agent` instead of `SandboxAgent`
(OAI-104) surfaces the host to privileged tools directly.

All six fixes are *config* — guardrail lists, a kwarg, or a class swap on the agent
constructor, not tool-code changes.

---

## Rule-by-rule defense

### OAI-101 — No input_guardrails while wiring shell/filesystem tools (Severity: high, Confidence: 0.85, Fix type: config)

**What we detect:** an agent with an empty `input_guardrails` whose resolved tools
include a shell- or filesystem-touching tool (`agent_kwarg_list_empty` +
`agent_uses_tool_kind: [shell_invocation]`).

**Why it is flaggable:** a prompt-injected input can reach a privileged tool with no
pre-execution screen — guardrails are the SDK's primary injection defense.

**Real-world consequence:** a user message crafted to trigger a file-deleting tool
reaches it unchecked.

**Why high not medium:** it leaves the main injection-defense surface empty on an
agent that holds dangerous tools.

**Fix type — config:** add an `@input_guardrail` and wire it via
`input_guardrails=[...]`.

**Confidence 0.85:** the agent may screen input by another mechanism the rule cannot
see (uncommon).

### OAI-102 — tool_use_behavior="stop_on_first_tool" (Severity: high, Confidence: 0.95, Fix type: config)

**What we detect:** `tool_use_behavior="stop_on_first_tool"` (`agent_kwarg_value`).

**Why it is flaggable:** the first tool's raw output becomes the final response with
no model post-processing — if that output is attacker-controlled (web/file/MCP
data), it is rendered to the user verbatim.

**Real-world consequence:** a search tool returns an attacker page's text and it is
shown to the user as the agent's answer — an exfiltration/injection vector.

**Why high not medium:** it removes the model's mediation of tool output entirely.

**Fix type — config:** drop the kwarg (default `run_llm_again` is safe) or constrain
via `StopAtTools(...)` listing only tools whose output you control.

**Confidence 0.95:** the literal value is read directly.

### OAI-103 — tool_choice="required" + reset_tool_choice=False (Severity: high, Confidence: 0.95, Fix type: config)

**What we detect:** `model_settings.tool_choice="required"` AND
`reset_tool_choice=False` (two `agent_kwarg_value` checks).

**Why it is flaggable:** the model is forced to call a tool every turn and the choice
is never reset — the SDK's documented infinite-loop pattern.

**Real-world consequence:** the agent loops indefinitely, exhausting the turn budget
and incurring cost, never terminating.

**Why high not medium:** it is a denial-of-progress footgun with a deterministic
trigger.

**Fix type — config:** drop `reset_tool_choice=False` (default `True` breaks the
loop) or set `tool_choice="auto"`; if forced tool use is intended, ensure a tool
terminates via `tool_use_behavior=StopAtTools(...)`.

**Confidence 0.95:** both literals are read directly.

### OAI-104 — Raw Agent (not SandboxAgent) with shell/filesystem tools (Severity: medium, Confidence: 0.75, Fix type: config)

**What we detect:** `agent_class: [Agent]` with a resolved shell/filesystem tool.

**Why it is flaggable:** the SDK ships `SandboxAgent` to confine privileged tools;
a plain `Agent` surfaces the host environment directly.

**Real-world consequence:** a file or shell tool on a raw `Agent` operates against
the real host filesystem rather than an isolated workspace.

**Why medium not high:** sandboxing is defense-in-depth; the tools may already be
individually guarded, so the missing sandbox is a weakened posture rather than an
open hole.

**Fix type — config:** switch to `SandboxAgent(...)` with a `Manifest` restricting
paths/commands.

**Confidence 0.75:** the privileged tools might be safe in context, or sandboxed by
other means — hence the lower confidence and medium severity.

### OAI-109 — WebSearchTool without input_guardrails (Severity: high, Confidence: 0.85, Fix type: config)

**What we detect:** `agent_uses_hosted_tool_class: [WebSearchTool]` with empty
`input_guardrails`.

**Why it is flaggable:** web search returns untrusted external content that can carry
prompt-injection payloads, with no pre-screen.

**Real-world consequence:** the agent searches an attacker-controlled page; its
injected instructions hijack subsequent behavior.

**Why high not medium:** untrusted-content intake with no guardrail is a primary
injection path.

**Fix type — config:** add an `@input_guardrail` that validates queries before they
reach `WebSearchTool`.

**Confidence 0.85:** the agent might screen by another route the rule cannot see.

### OAI-110 — Content-fetching tool without output_guardrails (Severity: high, Confidence: 0.6, Fix type: config)

**What we detect:** empty `output_guardrails` while the agent wires `WebSearchTool`,
`FileSearchTool`, or `CodeInterpreterTool`.

**Why it is flaggable:** these pull untrusted content in; output guardrails are the
SDK's egress screen on the final response. Without them a prompt-injected tool result
can drive an exfiltrating or unsafe answer with nothing inspecting what leaves.

**Real-world consequence:** injected content in a fetched document steers the final
response to leak data, unscreened.

**Why high not medium:** egress screening is the last line before the user/caller, and
it is absent on an agent that ingests untrusted content.

**Fix type — config:** add an `@output_guardrail` and wire `output_guardrails=[...]`.

**Confidence 0.6:** the lower confidence reflects that many content-fetching agents
are low-risk (public data, no sensitive egress), so the missing output guardrail is
often acceptable — a review prompt more than a defect.

---

## What this policy does not cover

- The *quality* of guardrails that are present — a no-op `input_guardrail` /
  `output_guardrail` satisfies OAI-101/106/109/110 without screening anything.
- Shell/filesystem capability delivered via a `@function_tool` (a `KindOpenAITool`)
  or hosted shell tool rather than a bare shell-invoking function — OAI-101/104's
  `agent_uses_tool_kind: [shell_invocation]` matches only the bare-function shape, a
  known coverage gap.
- Handoff targets: an agent that hands off to a less-guarded sub-agent (a graph-level
  concern this per-agent rule does not traverse).
- Guardrails or sandboxing applied by a wrapper/factory the static check cannot see.

---

## Recommendations beyond the fix

```python
from agents import Agent, SandboxAgent, input_guardrail, output_guardrail

agent = SandboxAgent(
    name="research",
    tools=[web_search, read_file],
    input_guardrails=[screen_user_input],     # OAI-101/109
    output_guardrails=[screen_final_output],  # OAI-110
    # no stop_on_first_tool; tool_choice left "auto"  -> OAI-102/103
)
```

1. Wire both `input_guardrails` and `output_guardrails` on any agent that touches
   untrusted content or privileged tools; make them real screens, not stubs.
2. Leave the tool-loop defaults alone — avoid `stop_on_first_tool` and the
   `tool_choice="required"` + `reset_tool_choice=False` pairing unless a tool
   deterministically terminates the loop.
3. Prefer `SandboxAgent` with a restrictive `Manifest` for any agent holding
   shell/filesystem tools, and screen handoff targets for at-least-equal guarding.
