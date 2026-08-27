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
  - id: ADK-109
    severity: medium
    confidence: 0.85
    scope: agent
    fix_type: config
  - id: ADK-110
    severity: medium
    confidence: 0.7
    scope: agent
    fix_type: config
  - id: ADK-111
    severity: high
    confidence: 0.75
    scope: agent
    fix_type: config
references: [LLM01, LLM06]
---

# Policy Rationale: ADK Agent Safety

**Policy ID:** `google_adk_agent_safety`  
**File:** `google_adk/agent_safety.yaml`  
**Rules:** ADK-101, ADK-102, ADK-103, ADK-104, ADK-105, ADK-106, ADK-107, ADK-108, ADK-109, ADK-110, ADK-111  
**Severities:** medium, high, high, medium, high, high, high, medium, medium, medium, high  
**Fix types:** config, config, config, config, config, config, config, config, config, config, config  
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
are ADK's analog of the OpenAI SDK's guardrails. ADK-111 is different in kind from
the rest: it is a hosted-tool-surface / access-control concern — whether the
`tool_filter=` allow-list narrows an `MCPToolset` down from the remote server's
full tool catalog — not a missing interception callback.

---

## Why agent wiring is a distinct concern in agent tools

ADK has no guardrail object; its safety controls are *callbacks* and *config
fields* on the agent, and most default to absent or off. So the safe shape is
something the author has to add, and these rules detect where it is missing. Two
threat lines run through them.

The **excessive-agency / loss-of-mediation** line (OWASP LLM06):
`before_tool_callback` is the only synchronous gate over a tool call, so an agent
with a dangerous tool (the bash tool — `ExecuteBashTool`, `BashTool` in
earlier google-adk — web search, `UrlContextTool`/`LoadWebPage`,
`AgentTool`) and no callback (ADK-102/105/107/110) executes model-chosen
invocations with nothing able to deny them. A code_executor is gated only by
`before_model_callback`, since emitted code blocks are not tool calls (ADK-106). A
sub-agent granted the bash tool (ADK-103) routes around the parent's callback entirely.
A `LoopAgent` with no `max_iterations` (ADK-108) can spin unbounded. And a missing
`description` (ADK-101) breaks delegation routing, the substrate the whole graph
depends on.

The **untrusted-content / injection** line (OWASP LLM01): web search and page-fetch
tools (ADK-105/110) pull attacker-controllable content into the loop, and absent
`safety_settings` (ADK-104) leaves Gemini's content filters off — so harmful or
injected content is neither screened on the way in nor filtered on the way out.

A third, narrower line is **tool-access scoping** (ADK-111), and it sits apart from
the other nine rules structurally, not just thematically. Every other tool-related
rule in this file (ADK-102/103/105/106/107/110) concerns a *fixed, locally-defined*
tool — a specific built-in class the agent's source names directly, whose behavior
is knowable ahead of time and whose only open question is whether a callback gates
it. `MCPToolset` is not that shape: it hands the agent every tool a remote MCP
server currently exposes, a catalog the agent's source never enumerates and that
can grow or change behavior the moment the server is redeployed, entirely outside
this codebase's control. `tool_filter=` is ADK's only static mechanism for
narrowing that catalog to a named allow-list — it is the access-control primitive
for a hosted, third-party tool surface, not a mediation callback for a known one.
That makes ADK-111's detection mechanism different too:
`agent_uses_hosted_tool_class: [MCPToolset]` finds the wiring, and
`agent_hosted_tool_kwarg_present` (negated) checks for the allow-list kwarg on
that specific hosted-tool ref — the same predicate family that reads
`before_tool_callback`/`before_model_callback` presence elsewhere in this file,
here pointed at a kwarg instead of a callback.

All eleven fixes are *config* — a callback, a kwarg, or a graph restructure on the
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

### ADK-102 — Agent with the bash tool has no before_tool_callback (Severity: high, Confidence: 0.85, Fix type: config)
**What we detect:** `LlmAgent` + the bash tool (`ExecuteBashTool`, the current
google-adk class name, or the earlier `BashTool`) + no `before_tool_callback`. **Why
flaggable:** `before_tool_callback` is the only synchronous gate over a shell call;
absent it, the model's command runs unmediated. **Real-world consequence:** an
injected instruction runs `rm`/`curl` with nothing to deny it. **Why high:** unmediated
shell execution. **Fix type — config:** add a `before_tool_callback` that allow-lists
commands and returns a refusal `Content` to block. **Confidence 0.85:** safety may
live in a restrictive `BashToolPolicy` instead (ADK-008) — possible false positive.

### ADK-103 — Sub-agent is granted the bash tool (Severity: high, Confidence: 0.9, Fix type: config)
**What we detect:** an `LlmAgent` that is a delegation target (`agent_is_subagent_of_any`)
and holds the bash tool (`ExecuteBashTool`/`BashTool`). **Why flaggable:** a delegated child's tool calls are not mediated
by the parent's callback, so shell access on the child defeats the parent's policy.
**Real-world consequence:** the model hands off to the sub-agent and asks it to run the
command the parent would have blocked. **Why high:** it nullifies the parent's gate.
**Fix type — config:** remove the bash tool from the sub-agent, or make the shell-capable
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

### ADK-109 — TypeScript LlmAgent has no description (Severity: medium, Confidence: 0.85, Fix type: config)
**What we detect:** a TypeScript `new LlmAgent({...})` with `description` missing
(`agent_class: [LlmAgent]` AND `agent_kwarg_missing: [description]`). Same predicate
pair as the Python sibling
[ADK-101](#adk-101--llmagent-has-no-description-severity-medium-confidence-085-fix-type-config),
applied to the TS constructor. **Why flaggable:** ADK routes delegation on each
child's `description`; when a parent decides whether to hand off to a child in its
`subAgents` tree the model sees only that string, so a child with none is
effectively unreachable through delegation. **Real-world consequence:** the agent
sits in the `subAgents` tree but is never delegated to — a silent routing bug.
**Why medium:** a reliability/routing defect, not a direct breach — identical
framing to ADK-101. **Fix type — config:** add a one-sentence `description` to the
`new LlmAgent({...})` options; a constructor-wiring change, not tool-body code.
**Confidence 0.85:** matches the Python sibling's 0.85 — an agent never used as a
delegation target does not need a `description`, so a top-level/standalone TS
`LlmAgent` with none is the dominant false positive; a `description` supplied
through a non-literal value the static read cannot resolve is the residual false
negative.

### ADK-110 — UrlContextTool/LoadWebPage without before_tool_callback (Severity: medium, Confidence: 0.7, Fix type: config)
**What we detect:** `LlmAgent` with a URL/page-fetch built-in — the idiomatic
`url_context` instance or `load_web_page` function reference (matched as bare
name grants), or a directly-constructed `UrlContextTool` — and no
`before_tool_callback`. **Why flaggable:** these fetch model-chosen URLs whose content
re-enters the loop — a prompt-injection vector and an SSRF surface — with no gate.
**Real-world consequence:** the model fetches an attacker page (injection) or an internal
metadata URL (SSRF). **Why medium:** real but often lower-impact than search, and
fetching is frequently legitimate. **Fix type — config:** add a `before_tool_callback`
that allow-lists hosts and blocks internal ranges. **Confidence 0.7:** legitimate fetch
use is common; a review prompt.

### ADK-111 — Agent wires an MCPToolset with no tool_filter (Severity: high, Confidence: 0.75, Fix type: config)
**What we detect:** an `LlmAgent` that uses an `MCPToolset` (`agent_uses_hosted_tool_class:
[MCPToolset]`) with no `tool_filter` kwarg present on that ref
(`agent_hosted_tool_kwarg_present`, negated). **Why flaggable:** unlike an explicit
`tools=[FunctionTool(...), ...]` list, `MCPToolset` connects the agent to every tool the
remote MCP server currently exposes — a surface that is not enumerable from the agent's
source, can grow or change behavior whenever the server is updated, and is entirely
outside this codebase's control. `tool_filter=` is ADK's only mechanism for narrowing
that catalog to a named allow-list; without it, the agent inherits the server's full, and
potentially server-operator-controlled, tool set with no static boundary a code reviewer
can check. **Real-world consequence:** the MCP server operator adds a destructive or
data-exfiltrating tool to the catalog and the agent gains it silently, with no code change
on the agent side to review. **Why high:** an unbounded, remotely-controlled tool grant.
**Fix type — config:** pass `tool_filter=[...]` to the `MCPToolset` constructor naming the
specific tool names this agent is allowed to call, e.g. `MCPToolset(connection_params=...,
tool_filter=["read_file", "list_directory"])`; re-review the filter whenever the agent's
task changes. **Confidence 0.75:** two independent gaps sit below this rule's view. A
`tool_filter` value assembled elsewhere and passed via `**kwargs` splat, rather than as a
literal `tool_filter=` keyword at the `MCPToolset(...)` call site, is invisible to the
kwarg lookup and reads as absent — a false negative. And the rule only checks whether a
filter is *declared*, not what the server actually exposes: an MCP server that the
operator has already scoped to a minimal, safe tool set looks identical, from the client
source, to one exposing a dangerous unbounded catalog — a false positive this rule cannot
resolve from the client side. A third gap sits alongside these: the predicate checks
whether the `tool_filter` kwarg is *present*, not what it evaluates to — an explicit
`tool_filter=None` or `tool_filter=[]` reads as present and satisfies the rule, even
though neither value actually narrows the tool catalog.

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
- What tools the remote MCP server behind an `MCPToolset` actually exposes (ADK-111)
  — only whether `tool_filter=` is declared. A server already scoped by its operator to
  a minimal, safe tool set is indistinguishable, at this rule's level, from a server
  exposing a dangerous, unbounded catalog.

---

## Recommendations beyond the fix

```python
from google.adk.agents import LlmAgent
from google.adk.tools.mcp_tool import MCPToolset
from google.genai import types

agent = LlmAgent(
    name="researcher",
    description="Searches the web and summarizes results for the orchestrator.",
    tools=[
        GoogleSearchTool(),
        MCPToolset(
            connection_params=...,
            tool_filter=["read_file", "list_directory"],   # ADK-111
        ),
    ],
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
4. Name an explicit `tool_filter=[...]` on every `MCPToolset` (ADK-111), and
   re-review it whenever the agent's task changes — treat any server tool not in the
   list as excluded by default, since the server's full catalog is otherwise outside
   this codebase's control.
