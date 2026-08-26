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
  - id: OAI-105
    severity: high
    confidence: 0.8
    scope: agent
    fix_type: config
  - id: OAI-110
    severity: medium
    confidence: 0.6
    scope: agent
    fix_type: config
  - id: OAI-112
    severity: low
    confidence: 0.6
    scope: agent
    fix_type: config
references: [LLM01, LLM06, LLM10]
---

# Policy Rationale: Agent Wiring Safety

**Policy ID:** `openai_sdk_agent_safety`  
**File:** `openai_sdk/agent_safety.yaml`  
**Rules:** OAI-101, OAI-102, OAI-103, OAI-104, OAI-105, OAI-109, OAI-110, OAI-112  
**Severities:** high, high, high, medium, high, high, medium, low  
**Fix types:** config, config, config, config, config, config, config, config  
**References:** LLM01, LLM06, LLM10

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
`output_guardrails`). A further rule, OAI-112, is different in kind: it does not
read the constructor at all, but correlates this agent's construction site to the
`Runner.run`/`run_sync`/`run_streamed` call(s) that execute it and fires when none
of them sets `max_turns` — an execution-limit / reliability concern (LLM10,
Unbounded Consumption), distinct from the prompt-injection and excessive-agency
framing of the rules above it.

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

A third line, independent of both, runs through OAI-112 alone and is not a threat
to injected content or agent capability at all: it is an execution-limit /
reliability concern (OWASP LLM10, Unbounded Consumption). The `Runner.run` family
is what actually drives an agent's tool loop to completion, and if none of the
calls that execute this agent sets `max_turns`, the run proceeds to whatever
ceiling the SDK's own `DEFAULT_MAX_TURNS` applies rather than to a bound sized for
the task. A model that loops or oscillates keeps consuming turns, tokens, and tool
side effects — including from any of the tools OAI-101/104/109/110 are already
screening — until that implicit ceiling intervenes, and the ceiling itself is an
SDK implementation detail that can shift between releases with no change on the
project's side. This is the same shape as CrewAI's CREW-110 (`max_iter`) and the
Claude Agent SDK's CSDK-204 (`max_turns` on `ClaudeAgentOptions`): a generic
default already bounds the worst case, so the risk is real but modest — which is
why it sits at low severity.

All six wiring fixes above are *config* — guardrail lists, a kwarg, or a class
swap on the agent constructor, not tool-code changes. OAI-112's fix is config
too, but at a different site: the `Runner.run(...)` call that executes the
agent, not the `Agent(...)`/`SandboxAgent(...)` constructor — the first fix in
this policy that reaches past the constructor to the call that actually runs it.

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

### OAI-105 — TypeScript agent wires a content-fetching hosted tool without inputGuardrails (Severity: high, Confidence: 0.8, Fix type: config)

**What we detect:**
A TypeScript OpenAI Agents SDK `Agent({...})` that wires a content-fetching hosted
tool — `webSearchTool`, `fileSearchTool`, or `hostedMcpTool` (the camelCase TS
factory classes, read off `HostedToolRefs`) — AND has an empty `inputGuardrails`
(`agent_uses_hosted_tool_class: [webSearchTool, fileSearchTool, hostedMcpTool]` AND
`agent_kwarg_list_empty: [inputGuardrails]`). Because the first clause requires a
*resolved* hosted-tool reference, an agent whose options object is opaque
(non-literal) cannot trip the rule on the empty-list clause alone — it must have a
recognized hosted tool. This is the TypeScript analogue of the Python sibling
[OAI-109](#oai-109--websearchtool-without-input_guardrails-severity-high-confidence-085-fix-type-config),
widened to file search and hosted MCP and using the TS camelCase factory names and
`inputGuardrails` kwarg spelling.

**Why it is flaggable:**
These tools pull untrusted external content into the model — web pages, indexed
files, or MCP-advertised tool output — that can carry prompt-injection payloads.
With no `inputGuardrails` screening what reaches the model, injected instructions
can hijack the agent into exfiltrating data or invoking other tools. Input
guardrails are the SDK's primary ingress screen.

**Real-world consequence:**
A TS research agent wiring `webSearchTool()` with no `inputGuardrails` retrieves an
attacker-seeded page whose "ignore previous instructions…" content becomes context
and steers the next action; a `hostedMcpTool` pointed at an untrusted MCP endpoint
returns tool output that does the same.

**Why severity is high and not medium:**
Untrusted-content intake with the primary ingress screen empty is a direct
prompt-injection path, exactly as for the Python OAI-109 — high.

**Fix type — config:**
Adding a guardrail built with `defineInputGuardrail(...)` and wiring it via
`inputGuardrails: [...]` on the `Agent({...})` constructor is a wiring change, not a
tool-code edit. Pinning `hostedMcpTool` to trusted endpoints is likewise config.

**Confidence 0.8:**
A notch below the Python OAI-109's 0.85. The resolved-hosted-tool requirement
removes the dominant false positive (an agent with no content-fetching tool cannot
fire), but the gap remains that the agent may screen ingress by a mechanism the
rule cannot see — a wrapper/factory that injects guardrails, or a guardrail list
built from a non-literal value that the static read records as empty. The wider tool
set (three classes, including `hostedMcpTool` whose risk depends on the MCP
endpoint's trust) also admits more context-dependent legitimate use than OAI-109's
single `WebSearchTool`, which is why it sits at 0.8 rather than 0.85.

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

### OAI-110 — Content-fetching tool without output_guardrails (Severity: medium, Confidence: 0.6, Fix type: config)

**What we detect:** empty `output_guardrails` while the agent wires `WebSearchTool`,
`FileSearchTool`, or `CodeInterpreterTool`.

**Why it is flaggable:** these pull untrusted content in; output guardrails are the
SDK's egress screen on the final response. Without them a prompt-injected tool result
can drive an exfiltrating or unsafe answer with nothing inspecting what leaves.

**Real-world consequence:** injected content in a fetched document steers the final
response to leak data, unscreened.

**Why severity is medium:** output guardrails are far from universally adopted, and
many content-fetching agents handle only low-risk public data, so a missing egress
screen is often acceptable (see the 0.6 confidence). It stays above low because, on
an agent that ingests untrusted content and can act on it, the absent screen is the
last line before the user/caller.

**Fix type — config:** add an `@output_guardrail` and wire `output_guardrails=[...]`.

**Confidence 0.6:** the lower confidence reflects that many content-fetching agents
are low-risk (public data, no sensitive egress), so the missing output guardrail is
often acceptable — a review prompt more than a defect.

### OAI-112 — OpenAI Agents SDK agent has no explicit max_turns limit (Severity: low, Confidence: 0.6, Fix type: config)

**What we detect:** this agent has at least one resolvable `Runner.run` /
`run_sync` / `run_streamed` call that executes it — found by a second,
independent discovery pass that matches the call's callee object to exactly
`Runner` (or a dotted path ending in `.Runner`) and its first positional
argument to this agent's `VarName`, in the same file — and none of those calls
sets `max_turns` (predicate `agent_run_call_max_turns_missing`). Unlike every
other rule in this policy, which reads kwargs off a single constructor call,
OAI-112 correlates two separately discovered structures — the agent's
`AgentDef` and one or more `AgentRunCallDef`s — by same-file variable name. A
call whose first argument is not a plain identifier (a call expression, a
keyword arg) is skipped as unresolvable, and an agent with no matching run
call at all never fires: no resolvable execution site is not evidence that one
is missing a cap.

**Why it is flaggable:** with no `max_turns` on any call that runs it, the
agent's loop runs to whatever ceiling the SDK's `DEFAULT_MAX_TURNS` applies
rather than to a bound sized for this task. A model that loops or oscillates —
retrying a failing tool, re-reading the same file, ping-ponging between two
steps — keeps consuming turns, tokens, and tool side effects until that
implicit ceiling is reached, and an implicit ceiling can shift between SDK
versions without any change on your side.

**Real-world consequence:** an agent wired with a flaky tool is run via
`Runner.run(agent, user_input)` with no `max_turns`; a transient failure sends
it into a retry-and-fail loop that burns turns, tokens, and tool side effects
until the SDK's own default finally intervenes — a slow, silent cost overrun
rather than a clean stop at a bound the team chose.

**Why severity is low and not medium:** the SDK's own `DEFAULT_MAX_TURNS`
bounds the worst case, so this is not an unbounded-loop finding — it is a
missing *explicit, task-sized* bound. That places it alongside CrewAI's
CREW-110 (`max_iter`) and the Claude Agent SDK's CSDK-204 (`max_turns` on
`ClaudeAgentOptions`): a generic ceiling already limits the damage, so the
finding is real but modest.

**Fix type — config:** pass `max_turns=` to `Runner.run(...)` (or
`run_sync`/`run_streamed`), sized to the work this agent actually does. Unlike
every other fix in this policy, this one is not a constructor kwarg — it lands
on the call that executes the agent, a different site entirely. Treat hitting
the cap as a signal to surface and handle rather than to raise it: if a task
legitimately needs many turns, split it into bounded sub-runs instead of
removing the bound.

**Confidence 0.6:** lower than every kwarg-presence/absence rule above because
the predicate does something none of them do — it correlates two separately
discovered structures, `AgentDef` and `AgentRunCallDef`, by same-file variable
name, rather than reading kwargs off one call. That correlation has two real
gaps. Cross-file correlation is not attempted at all: an agent constructed in
one file and run via `Runner.run(...)` in another is invisible to this rule
and never fires — a false negative the rule does not attempt to close. And
because the check only asks whether *any* matching run call sets `max_turns`,
an agent run multiple times with inconsistent settings — one call sizing
`max_turns`, another leaving it off — goes completely silent on the strength
of the one compliant call, even though the uncapped call still executes the
same agent unbounded. The remaining gaps mirror CSDK-204's own 0.6: a call
built with `**` unpacking is skipped as unresolvable (`Opaque: true`), a cap
enforced by a wrapper or retry harness outside the call itself is invisible,
and a `max_turns` value passed via a variable the scanner cannot resolve to a
literal reads as absent.

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
- For OAI-105: a TypeScript agent whose options object (and therefore its hosted-tool
  list) is opaque to the static read fires nothing — the rule requires a *resolved*
  `webSearchTool`/`fileSearchTool`/`hostedMcpTool` reference, so a content-fetching
  tool wired through a non-literal value is a false negative; and an
  `inputGuardrails` list built from a non-literal value reads as empty even when a
  guardrail is present (false positive).
- For OAI-112: an agent constructed in one file and executed via
  `Runner.run(...)` in another — the `AgentDef`-to-`AgentRunCallDef`
  correlation is same-file-VarName only, so a cross-file execution site is
  invisible and the rule stays silent. An agent run multiple times where only
  one call sets `max_turns` also escapes detection: any single matching call
  that sets it silences the finding entirely, even if other calls that execute
  the same agent leave it uncapped. The SDK's actual `DEFAULT_MAX_TURNS`
  behavior is not independently verified for this doc beyond the language
  already present in the shipped rule's own explanation text.

---

## Recommendations beyond the fix

```python
from agents import Agent, SandboxAgent, Runner, input_guardrail, output_guardrail

agent = SandboxAgent(
    name="research",
    tools=[web_search, read_file],
    input_guardrails=[screen_user_input],     # OAI-101/109
    output_guardrails=[screen_final_output],  # OAI-110
    # no stop_on_first_tool; tool_choice left "auto"  -> OAI-102/103
)

result = Runner.run_sync(agent, user_input, max_turns=8)  # OAI-112: sized to this agent's task
```

1. Wire both `input_guardrails` and `output_guardrails` on any agent that touches
   untrusted content or privileged tools; make them real screens, not stubs.
2. Leave the tool-loop defaults alone — avoid `stop_on_first_tool` and the
   `tool_choice="required"` + `reset_tool_choice=False` pairing unless a tool
   deterministically terminates the loop.
3. Prefer `SandboxAgent` with a restrictive `Manifest` for any agent holding
   shell/filesystem tools, and screen handoff targets for at-least-equal guarding.
4. Pass `max_turns=` on whichever `Runner.run`/`run_sync`/`run_streamed` call
   executes the agent, sized to the task rather than left at the SDK default,
   and keep it consistent across every call site that runs the same agent.
