---
policy_id: google_adk_agent_safety
category: google_adk
topic: agent_safety
rules:
  - id: ADK-101
    severity: medium
    confidence: 0.85
    scope: agent
    fix_type: config
  - id: ADK-102
    severity: high
    confidence: 0.85
    scope: agent
    fix_type: config
  - id: ADK-103
    severity: high
    confidence: 0.9
    scope: agent
    fix_type: config
  - id: ADK-104
    severity: medium
    confidence: 0.75
    scope: agent
    fix_type: config
  - id: ADK-105
    severity: high
    confidence: 0.85
    scope: agent
    fix_type: config
  - id: ADK-106
    severity: high
    confidence: 0.8
    scope: agent
    fix_type: config
  - id: ADK-107
    severity: high
    confidence: 0.7
    scope: agent
    fix_type: config
  - id: ADK-108
    severity: medium
    confidence: 0.7
    scope: agent
    fix_type: config
  - id: ADK-110
    severity: medium
    confidence: 0.7
    scope: agent
    fix_type: config
references: [LLM01, LLM06]
---

# Policy Rationale: ADK Agent Safety

**Policy ID:** `google_adk_agent_safety`  
**File:** `google_adk/agent_safety.yaml`  
**Rules:** ADK-101, ADK-102, ADK-103, ADK-104, ADK-105, ADK-106, ADK-107, ADK-108, ADK-110  
**Severities:** medium, high, high, medium, high, high, high, medium, medium  
**Fix types:** config, config, config, config, config, config, config, config, config  
**References:** LLM01, LLM06

---

## What this policy covers

How a Google ADK agent is wired: its delegation `description`, its Gemini
`safety_settings`, the interception callbacks that gate tool and model calls, the
sub-agent/AgentTool delegation graph, and loop bounds. These fire per agent (scope:
agent) on the constructor kwargs and the resolved tool/sub-agent graph. The rules
cluster around ADK's two synchronous interception points —
`before_tool_callback` (sees a tool call before it runs) and
`before_model_callback` (sees the assembled request before the model runs) — which
are ADK's analog of the OpenAI SDK's guardrails.

---

## Why agent wiring is a distinct concern in agent tools

ADK has no guardrail object; its safety controls are *callbacks* and *config
fields* on the agent, and most default to absent or off. So the safe shape is
something the author has to add, and these rules detect where it is missing. Two
threat lines run through them.

The **excessive-agency / loss-of-mediation** line (OWASP LLM06):
`before_tool_callback` is the only synchronous gate over a tool call, so an agent
with a dangerous tool (`BashTool`, web search, `UrlContextTool`/`LoadWebPage`,
`AgentTool`) and no callback (ADK-102/105/107/110) executes model-chosen
invocations with nothing able to deny them. A code_executor is gated only by
`before_model_callback`, since emitted code blocks are not tool calls (ADK-106). A
sub-agent granted `BashTool` (ADK-103) routes around the parent's callback entirely.
A `LoopAgent` with no `max_iterations` (ADK-108) can spin unbounded. And a missing
`description` (ADK-101) breaks delegation routing, the substrate the whole graph
depends on.

The **untrusted-content / injection** line (OWASP LLM01): web search and page-fetch
tools (ADK-105/110) pull attacker-controllable content into the loop, and absent
`safety_settings` (ADK-104) leaves Gemini's content filters off — so harmful or
injected content is neither screened on the way in nor filtered on the way out.

All nine fixes are *config* — a callback, a kwarg, or a graph restructure on the
agent constructor, not tool-body code.

---

## Rule-by-rule defense

### ADK-101 — LlmAgent has no description (Severity: medium, Confidence: 0.85, Fix type: config)
**What we detect:** an `LlmAgent` with `description` missing. **Why flaggable:** ADK
routes delegation on each child's `description`; with none, the parent's model has no
signal to pick this agent. **Real-world consequence:** the agent sits in the
`sub_agents` tree but is never delegated to — a silent routing bug. **Why medium:**
a reliability/routing defect, not a direct breach. **Fix type — config:** add a
one-sentence `description=`. **Confidence 0.85:** an agent never used as a delegation
target does not need one (false positive).

### ADK-102 — Agent with BashTool has no before_tool_callback (Severity: high, Confidence: 0.85, Fix type: config)
**What we detect:** `LlmAgent` + `BashTool` + no `before_tool_callback`. **Why
flaggable:** `before_tool_callback` is the only synchronous gate over a shell call;
absent it, the model's command runs unmediated. **Real-world consequence:** an
injected instruction runs `rm`/`curl` with nothing to deny it. **Why high:** unmediated
shell execution. **Fix type — config:** add a `before_tool_callback` that allow-lists
commands and returns a refusal `Content` to block. **Confidence 0.85:** safety may
live in a restrictive `BashToolPolicy` instead (ADK-008) — possible false positive.

### ADK-103 — Sub-agent is granted BashTool (Severity: high, Confidence: 0.9, Fix type: config)
**What we detect:** an `LlmAgent` that is a delegation target (`agent_is_subagent_of_any`)
and holds `BashTool`. **Why flaggable:** a delegated child's tool calls are not mediated
by the parent's callback, so shell access on the child defeats the parent's policy.
**Real-world consequence:** the model hands off to the sub-agent and asks it to run the
command the parent would have blocked. **Why high:** it nullifies the parent's gate.
**Fix type — config:** remove `BashTool` from the sub-agent, or make the shell-capable
agent the top-level orchestrator. **Confidence 0.9:** the graph relationship + grant are
read directly.

### ADK-104 — Agent has no safety_settings (Severity: medium, Confidence: 0.75, Fix type: config)
**What we detect:** `LlmAgent` with no `generate_content_config.safety_settings`. **Why
flaggable:** Gemini's content filters default OFF when unset, so DANGEROUS_CONTENT,
HATE_SPEECH, etc. are unfiltered. **Real-world consequence:** an unfiltered harmful
output drives a downstream tool call. **Why medium:** a content-safety gap whose impact
depends on what the outputs drive. **Fix type — config:** pass `safety_settings` in
`generate_content_config=` with explicit thresholds. **Confidence 0.75:** some
deployments filter at a different layer (false positive).

### ADK-105 — Web search built-in without before_tool_callback (Severity: high, Confidence: 0.85, Fix type: config)
**What we detect:** `LlmAgent` with `google_search` / `GoogleSearchTool` /
`VertexAiSearchTool` and no `before_tool_callback`. **Why flaggable:** search returns
untrusted external content that can carry injection payloads, with no gate. **Real-world
consequence:** an attacker-seeded result injects instructions that redirect the agent.
**Why high:** untrusted-content intake with no interception. **Fix type — config:** add a
`before_tool_callback` that validates queries; pair with `safety_settings`. **Confidence
0.85:** screening may exist elsewhere (uncommon).

### ADK-106 — code_executor but no before_model_callback (Severity: high, Confidence: 0.8, Fix type: config)
**What we detect:** `LlmAgent` with `code_executor` set and no `before_model_callback`.
**Why flaggable:** an `UnsafeLocalCodeExecutor` runs model-emitted code in-process, and
the *only* gate over emitted code is `before_model_callback` (code blocks are not tool
calls, so `before_tool_callback` never fires). **Real-world consequence:** the model emits
and runs arbitrary code with nothing inspecting it. **Why high:** unmediated code
execution. **Fix type — config:** add a `before_model_callback` and prefer a sandboxed
executor (Container/VertexAi) over the unsafe local one. **Confidence 0.8:** a sandboxed
executor lowers but does not remove the concern; the rule flags the missing gate.

### ADK-107 — AgentTool but no before_tool_callback (Severity: high, Confidence: 0.7, Fix type: config)
**What we detect:** `LlmAgent` wrapping another agent via `AgentTool` with no
`before_tool_callback`. **Why flaggable:** the wrapped agent's calls are not mediated by
this agent's callbacks, and ADK does not transitively analyze it; the only gate on the
delegation is `before_tool_callback`. **Real-world consequence:** work is routed into the
delegated agent with no policy on the handoff. **Why high:** an unmediated delegation
boundary. **Fix type — config:** add a `before_tool_callback` over `AgentTool`
invocations and ensure the wrapped agent carries its own guardrails. **Confidence 0.7:**
the wrapped agent may be fully self-guarded (false positive).

### ADK-108 — LoopAgent has no max_iterations (Severity: medium, Confidence: 0.7, Fix type: config)
**What we detect:** a `LoopAgent` with no `max_iterations`. **Why flaggable:** the loop
runs until a sub-agent escalates; with no cap, a model that never escalates spins
forever. **Real-world consequence:** unbounded token/wall-clock burn — a cost and
availability footgun (and it re-fires any non-idempotent tool each iteration; see
ADK-006). **Why medium:** denial-of-budget rather than a breach. **Fix type — config:**
set `max_iterations=` as a defensive cap even when escalation is expected. **Confidence
0.7:** an externally-bounded loop may make the cap redundant.

### ADK-110 — UrlContextTool/LoadWebPage without before_tool_callback (Severity: medium, Confidence: 0.7, Fix type: config)
**What we detect:** `LlmAgent` with `UrlContextTool` / `LoadWebPage` and no
`before_tool_callback`. **Why flaggable:** these fetch model-chosen URLs whose content
re-enters the loop — a prompt-injection vector and an SSRF surface — with no gate.
**Real-world consequence:** the model fetches an attacker page (injection) or an internal
metadata URL (SSRF). **Why medium:** real but often lower-impact than search, and
fetching is frequently legitimate. **Fix type — config:** add a `before_tool_callback`
that allow-lists hosts and blocks internal ranges. **Confidence 0.7:** legitimate fetch
use is common; a review prompt.

---

## What this policy does not cover

- The *quality* of a callback that is present — a `before_tool_callback` that always
  returns `None` satisfies the rule while gating nothing.
- Safety enforced by a mechanism the rule does not read (a restrictive `BashToolPolicy`
  for ADK-102, an external content filter for ADK-104).
- The wrapped agent behind `AgentTool` — ADK does not transitively analyze it, so its
  tools/guardrails are out of scope.
- Callbacks or config supplied via variables the scanner cannot resolve to the
  constructor.

---

## Recommendations beyond the fix

```python
from google.adk.agents import LlmAgent
from google.genai import types

agent = LlmAgent(
    name="researcher",
    description="Searches the web and summarizes results for the orchestrator.",
    tools=[GoogleSearchTool()],
    before_tool_callback=validate_tool_call,          # ADK-102/105/107/110
    before_model_callback=screen_model_request,       # ADK-106
    generate_content_config=types.GenerateContentConfig(
        safety_settings=[...],                        # ADK-104
    ),
)
```

1. Give every agent a clear `description` (ADK-101) and Gemini `safety_settings`
   (ADK-104) as baseline hygiene.
2. Add a `before_tool_callback` to any agent holding a shell, search, fetch, or
   AgentTool capability, and a `before_model_callback` to any agent with a
   `code_executor` — and make the callbacks real gates, not stubs.
3. Keep shell/privileged capability at the orchestrator, never on a delegated
   sub-agent (ADK-103); bound every `LoopAgent` with `max_iterations` (ADK-108).
