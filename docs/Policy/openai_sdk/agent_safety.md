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
  - id: OAI-107
    severity: high
    confidence: 0.85
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
    severity: high
    confidence: 0.6
    scope: agent
    fix_type: config
  - id: OAI-113
    severity: medium
    confidence: 0.6
    scope: agent
    fix_type: config
references: [LLM01, LLM06]
---

# Policy Rationale: Agent Wiring Safety

**Policy ID:** `openai_sdk_agent_safety`  
**File:** `openai_sdk/agent_safety.yaml`  
**Rules:** OAI-101, OAI-102, OAI-103, OAI-104, OAI-107, OAI-105, OAI-109, OAI-110, OAI-112, OAI-113  
**Severities:** high, high, high, medium, high, high, high, medium  
**Fix types:** config, config, config, config, config, config, config, config  
**References:** LLM01, LLM06

---

## What this policy covers

How an OpenAI Agents SDK `Agent(...)` / `SandboxAgent(...)` is wired — its
guardrails, its tool-loop controls, its class choice, and the hosted tools it
mounts. These fire per agent (scope: agent) on the constructor kwargs and the
resolved tool graph: OAI-101 (no `input_guardrails` while wiring shell/filesystem
tools), OAI-102 (`tool_use_behavior="stop_on_first_tool"`), OAI-103
(`tool_choice="required"` + `reset_tool_choice=False`), OAI-104 (raw `Agent`, not
`SandboxAgent`, with shell/filesystem tools), OAI-107 (a handoff *target* that
wires shell/filesystem tools, so a delegated turn reaches the shell with no
guardrail screening it), OAI-109 (`WebSearchTool` without `input_guardrails`),
OAI-110 (a content-fetching hosted tool without `output_guardrails`).

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

### OAI-107 — Handoff-target agent wires shell/filesystem tools (Severity: high, Confidence: 0.85, Fix type: config)

**What we detect:** an agent that is a resolved handoff target — it appears in
another agent's `handoffs=[...]` (`agent_is_subagent_of_any`) — and wires a
shell- or filesystem-touching tool (`agent_uses_tool_kind: [shell_invocation]`,
which also covers the hosted `ShellTool`/`LocalShellTool`/`CodeInterpreterTool`/
`ApplyPatchTool` and a decorated tool whose body shells out). The rule does *not*
require the child's `input_guardrails` to be empty — see below.

**Why it is flaggable:** in the Agents SDK, `input_guardrails` run only on the
agent that first receives the user input; a handoff target never runs its own
input guardrails on the handed-off turn. A parent can therefore route around its
own guardrails by delegating to this child and asking it to run the
shell-touching tool the parent would have screened. This is the OpenAI analogue
of ADK-103 (sub-agent granted `BashTool`): delegation crossing a guardrail
boundary onto a shell-capable child.

**Real-world consequence:** the model hands off to the sub-agent and asks it to
run a command the parent's `@input_guardrail` would have blocked; the child
executes it on input no guardrail ever inspected.

**Why high not medium:** it nullifies the parent's primary injection-defense
surface for any work the model chooses to delegate — a guardrail blind spot that
is structural to the SDK, not merely an omitted control. It mirrors ADK-103's
high severity for the same delegation-bypass shape.

**Why not gated on the child's guardrails:** because the child's
`input_guardrails` do not run on a handoff turn, even a child that declares
guardrails is exposed. Requiring an empty `input_guardrails` would miss exactly
the cases that *look* defended but are not — so the shell exposure on a handoff
target is the hazard regardless.

**Fix type — config:** remove the shell/filesystem tools from the handoff target,
or move them up to the top-level agent that receives user input (where its
guardrails run); if the handoff must stay, screen the handoff payload (an
`@input_guardrail` on the parent plus an `input_filter` on the handoff).

**Confidence 0.85:** the handoff edge and the tool grant are read directly from
the resolved graph (only *resolved* handoffs match, so the relationship is real);
a notch below ADK-103's 0.9 because the shell signal includes the heuristic
`shells_out` fact on decorated tools and the broader hosted-class set, slightly
wider than ADK's single explicit `BashTool`.

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

---

### OAI-112 — Guarded agent transitively wields shell through its handoff chain (Severity: high, Confidence: 0.6, Fix type: config)

**What we detect:**
An agent that declares `input_guardrails` AND whose composition closure
includes `shell` while its own tools provide none
(`transitive_capability_exceeds_direct: [shell]`, schema v14). The closure is
the engine's multi-agent composition analysis: the union of capability tokens
over the agent's own tools plus every agent reachable through *resolved*
handoff edges (`analysis.ComputeComposition`). An agent with an empty closure
— unanalyzed, or wielding nothing — structurally cannot fire.

**Why it is flaggable:**
`input_guardrails` run only on the agent that first receives user input; a
handoff target never runs its own on the delegated turn (the same SDK
semantics OAI-107 defends, seen from the parent's side). Declaring guardrails
here while the shell-executing turn happens downstream creates false
confidence: the dangerous turn runs on a payload the handoff may have
transformed, with no guardrail in front of it.

**Real-world consequence:**
A support triage agent guards its input, then hands "technical problems" to an
escalation agent that runs a diagnostics binary via `subprocess`. A crafted
ticket phrase steers the triage model into the handoff; the injected host
argument reaches the shell tool without any guardrail having seen the payload
in its delegated form.

**Why severity is high:**
Same delegated-shell exposure class as OAI-107 (high). The finding fires on
the agent where the trust decision lives — the guarded entry point whose
authors believe input is screened.

**Fix type — config:**
Move the shell work up to the guarded agent, strip the downstream shell tools,
or constrain the handoff (`input_filter`) — wiring changes, not tool-body
rewrites.

**Confidence 0.6:**
Deliberately below OAI-107's 0.85: the closure inherits every conservatism of
edge resolution (external and ambiguous edges stop the walk — under-reporting,
never over-reporting) but also its blind spots, and the capability derivation
is fact-based (a shell reached through a wrapper the facts miss will not
fire; a tool whose subprocess use is defensive still counts as shell). On the
corpus orchestrator examples the rule fires exactly once, on the seeded
guarded-triage → shell-escalation chain, with zero fires elsewhere. Raise
with corpus evidence.

### OAI-113 — Unguarded agent's handoff chain reaches shell execution (Severity: medium, Confidence: 0.6, Fix type: config)

**What we detect:**
The complement of OAI-112: an agent with NO `input_guardrails` whose closure
includes `shell` that its own tools do not provide. The two rules partition
the transitive-shell space by guardrail presence, so an agent never fires
both.

**Why it is flaggable:**
If this agent is where user input enters, nothing screens that input anywhere
on a delegation path that ends in shell execution — guardrails do not exist at
the entry, and handoff targets never run their own on delegated turns. Each
agent looks harmless in isolation; the exposure only appears at the chain
level, which is exactly what per-agent review misses.

**Real-world consequence:**
A front-desk agent forwards incident text to a dispatcher, which hands off to
a remediation agent that shells out. No guardrail exists anywhere on the
path, so prompt-injected incident text can steer the chain into arbitrary
command construction three agents away from where it entered.

**Why severity is medium and not high:**
The downstream agent's own shell wiring already fires the direct rules
(OAI-101/104/107) at their severities; this finding adds the chain-level
view on an agent that holds no dangerous tools itself. Attribution is one
step removed from the capability, so it ranks below the direct findings it
complements.

**Fix type — config:**
Add `input_guardrails` at this entry point and reconsider the downstream
shell grant — wiring changes.

**Confidence 0.6:**
Same closure-inheritance argument as OAI-112. Additionally, an agent that is
itself only ever a handoff *target* (never an entry point) still fires when
unguarded with transitive shell — defensible, since its guardrails would not
run on delegated turns anyway, but it is attribution noise the static scan
cannot fully resolve without entrypoint (Runner.run) discovery. Zero fires
across the corpus today (the seeded unguarded chains reach filesystem, not
shell). Raise with corpus evidence.

## What this policy does not cover

- The *quality* of guardrails that are present — a no-op `input_guardrail` /
  `output_guardrail` satisfies OAI-101/106/109/110 without screening anything.
- Pure *filesystem-touching* capability that is not shell reach — a `@function_tool`
  that calls `open()` / `pathlib` without shelling out. OAI-101/104/107's
  `agent_uses_tool_kind: [shell_invocation]` keys on shell reach (a bare
  shell-invoking function, a hosted shell tool, or a decorated tool whose body
  shells out), not on plain filesystem access, so the "filesystem-touching" half of
  those rule titles is only partially covered.
- Handoff *guardrail downgrades beyond shell reach*: OAI-107 flags a handoff target
  that wires shell/filesystem tools, but it does not compare guardrail coverage
  between parent and child. A handoff to a sub-agent that is less-guarded for reasons
  other than shell capability (e.g. fewer `output_guardrails`, a weaker model) is not
  flagged — that broader graph-level comparison is out of scope for this per-agent
  rule.
- Guardrails or sandboxing applied by a wrapper/factory the static check cannot see.
- For OAI-105: a TypeScript agent whose options object (and therefore its hosted-tool
  list) is opaque to the static read fires nothing — the rule requires a *resolved*
  `webSearchTool`/`fileSearchTool`/`hostedMcpTool` reference, so a content-fetching
  tool wired through a non-literal value is a false negative; and an
  `inputGuardrails` list built from a non-literal value reads as empty even when a
  guardrail is present (false positive).

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
