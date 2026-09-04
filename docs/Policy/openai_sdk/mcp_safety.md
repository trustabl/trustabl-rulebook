---
policy_id: openai_sdk_mcp_safety
category: openai_sdk
topic: mcp_safety
rules:
  - id: OAI-106
    severity: high
    confidence: 0.9
    scope: agent
    fix_type: config
  - id: OAI-115
    severity: high
    confidence: 0.7
    scope: agent
    fix_type: config
references: [LLM01, LLM06]
---

# Policy Rationale: MCP Integration Safety

**Policy ID:** `openai_sdk_mcp_safety`  
**File:** `openai_sdk/mcp_safety.yaml`  
**Rules:** OAI-106, OAI-115  
**Severities:** high  
**Fix types:** config  
**References:** LLM01, LLM06

---

## What this policy covers

Two related but distinct gaps in how an OpenAI Agents SDK agent wires MCP:

- **OAI-106** — agents that import tools from one or more MCP servers via
  `mcp_servers=` (present and non-empty — an empty `mcp_servers=[]` wires
  nothing and does not fire) but configure no `input_guardrails`. The match is
  `agent_kwarg_present: [mcp_servers]` AND NOT `agent_kwarg_list_empty:
  [mcp_servers]` AND `agent_kwarg_list_empty: [input_guardrails]` — it fires
  only when MCP is actually wired, so non-MCP agents are unaffected.
- **OAI-115** — agents that wire a `HostedMCPTool(tool_config={...})` (the
  SDK's hosted, Responses-API-mediated MCP integration, a separate mechanism
  from `mcp_servers=`) whose `tool_config` sets no `allowed_tools`. The match
  is `agent_uses_hosted_tool_class: [HostedMCPTool]` AND NOT
  `agent_hosted_tool_kwarg_present: {class: HostedMCPTool, kwarg:
  tool_config.allowed_tools}` — the same `not: <hosted-kwarg-present>` shape
  Google ADK's `ADK-111` uses for `MCPToolset`/`tool_filter`.

---

## Why MCP integration is a distinct concern in agent tools

The Model Context Protocol lets an agent import a tool catalog advertised by an
external MCP server. The crucial property is the trust boundary: the tool *names
and descriptions* the model sees are supplied by the MCP server, not the agent
author. Those descriptions are part of the model's prompt — they tell it when and
how to call each tool — so a malicious or compromised MCP server can craft
descriptions that bait the model into harmful actions, exfiltrate data through tool
arguments, or shadow a legitimate tool with a poisoned one. This is the documented
"tool poisoning" / "rug pull" class of MCP attack, and it is a direct instance of
OWASP LLM01 (Prompt Injection): untrusted text from across a trust boundary enters
the model's instruction context.

The agent author cannot review descriptions that are fetched at runtime from a
third party, so the defense has to be an active screen: an `input_guardrail` that
inspects the user input *and* the resolved tool list before the model is invoked.
Without one there is no pre-execution checkpoint between a poisoned MCP catalog and
the model acting on it. The fix is *config* — adding a guardrail to the agent
constructor, not changing any tool's code.

`HostedMCPTool` is a second, structurally different way the same SDK reaches
MCP: instead of the agent process connecting to the server directly
(`mcp_servers=`, screened by OAI-106), `tool_config` hands a remote MCP
server's URL to OpenAI's Responses API, which lists and calls that server's
tools on the agent's behalf. There is no `input_guardrails` gate here at
all — guardrails run over the agent's own turn, not inside the hosted
tool-call loop the Responses API executes remotely. The only static control
the SDK exposes is `tool_config["allowed_tools"]`, an allow-list of tool
names; without it the agent inherits the server's entire catalog, sized and
composed however the server operator (or an attacker who compromises that
server) chooses, on a boundary this codebase does not control. This is the
same **excessive-agency / loss-of-mediation** shape (OWASP LLM06) that
Google ADK's `ADK-111` documents for `MCPToolset`/`tool_filter` — a remote
party, not the agent author, deciding the agent's tool surface — layered with
the LLM01 tool-poisoning exposure OAI-106 already covers for the
directly-connected case: every tool in an unfiltered catalog is a tool
description the model reads unfiltered too.

---

## Rule-by-rule defense

### OAI-106 — Agent wires MCP servers without input_guardrails (Severity: high, Confidence: 0.9, Fix type: config)

**What we detect:** an agent with `mcp_servers=` set and an empty/absent
`input_guardrails`.

**Why it is flaggable:** the agent ingests tool descriptions from an external trust
boundary with no screen between them and the model.

**Real-world consequence:** a compromised MCP server advertises a `read_file` tool
whose description instructs the model to also send file contents to an attacker
endpoint; with no guardrail the model follows it.

**Why severity is high and not medium:** the attack reaches the model's instruction
channel directly and requires only that the MCP server (a separate party) be
malicious or compromised. Not critical because it still depends on the MCP server
being hostile and on a follow-on capability.

**Fix type — config:** add an `input_guardrail` to the agent and pin MCP servers to
known-trusted URLs/checksums.

**Confidence 0.9:** the configuration is read directly — MCP wired, guardrails empty.
The small gap is an agent that screens MCP content through some other mechanism the
rule cannot see.

### OAI-115 — Agent wires a HostedMCPTool with no allowed_tools allow-list (Severity: high, Confidence: 0.7, Fix type: config)

**What we detect:** an agent whose `HostedToolRefs` include a resolved
`HostedMCPTool` (`agent_uses_hosted_tool_class: [HostedMCPTool]`) where
`tool_config.allowed_tools` is not present on that constructor's captured
kwargs (`not: agent_hosted_tool_kwarg_present {class: HostedMCPTool, kwarg:
tool_config.allowed_tools}`). `tool_config` is a Python dict literal;
discovery recurses into dict literals the same way it recurses into a nested
constructor call, so the dotted path reaches `allowed_tools` inside it. A
`HostedMCPTool()` with no `tool_config` kwarg at all — and so no
`allowed_tools` — also fires, correctly: no kwargs is the same absence of a
boundary as a `tool_config` that omits the key.

**Why it is flaggable:** every other tool in an agent's `tools=` list is
enumerable by reading the source — a function, a hosted-tool class with fixed
behavior. `HostedMCPTool` is not: it hands a URL to the Responses API and
inherits whatever tools that server currently advertises, a set decided by
the server operator, invisible from this codebase, and free to grow or change
meaning on the next server deploy with no diff in the agent's repo.
`allowed_tools` is the SDK's only static mechanism for pinning that inherited
set to a named allow-list; without it there is no boundary a reviewer, a
diff, or this scanner can check.

**Real-world consequence:** an agent wired to a hosted MCP server "for
documentation lookups" inherits a `run_query` or `write_file` tool the moment
the server ships one — no code change on the agent side, nothing for review
to catch. The `require_approval` default (`"always"`) means a human is asked
before each *individual* call, but that per-call prompt approves whatever the
server currently calls the tool, not a reviewed allow-list — and the corpus
example this rule was built against (`testdata/corpus/openai-hosted-mcp/simple.py`)
sets `require_approval: "never"`, removing even that runtime backstop while
still setting no `allowed_tools`.

**Why severity is high and not critical (or medium):** parity with ADK-111's
reasoning for the structurally identical `MCPToolset`/`tool_filter` gap: not
critical, because the finding proves inherited breadth, not inherited
danger — whether the catalog contains anything destructive depends on the
server. Not medium, because the boundary is delegated to a remote party and
can move without any change in the scanned code, converting every server
update into an ungated capability grant.

**Fix type — config:** add `allowed_tools` to the `tool_config` dict on the
`HostedMCPTool(...)` call — wiring, not tool-body code.

**Confidence 0.7 — one notch below ADK-111's 0.75:** the mechanism and
consequence are the same as ADK-111, but OpenAI's `tool_config` shape carries
one benign-fire path ADK's `MCPToolset` does not: `require_approval` defaults
to `"always"`, so an agent that never sets it retains a runtime human-in-the-
loop check per call even with no static `allowed_tools` — a real, if weaker,
mitigation this rule cannot see. The false-positive/false-negative gaps
otherwise mirror ADK-111's: a `tool_config` built from a variable or
`**kwargs` spread rather than a literal dict is not captured, so the rule
fires on a case that may in fact set `allowed_tools` dynamically; and
`allowed_tools: []` or `allowed_tools: None` both read as *present* (the
underlying presence check is `node.Value != nil`, the same tri-state gap
CSDK-204/CSDK-205 carry for their own missing-kwarg checks), silencing the
rule on an empty or explicitly-disabled allow-list that is functionally
identical to having none.

---

## What this policy does not cover

- The *quality* of an `input_guardrail` that is present (OAI-106) — a no-op
  guardrail satisfies the rule without screening anything.
- The trustworthiness of the MCP server itself (pinning, auth, checksums) — both
  rules check for the control's presence, not the server's provenance.
- Tool poisoning that survives an `input_guardrail` (OAI-106) or an
  `allowed_tools` list that itself names a poisoned or too-broad tool
  (OAI-115) — a description crafted to pass the specific checks in place, or
  an allow-list padded wider than the task needs.
- `output_guardrails` gaps for MCP-fetched content (an egress concern; see
  agent_safety OAI-110 for the content-fetch output-guardrail rule).
- OAI-115 does not evaluate `require_approval` at all — a `HostedMCPTool`
  with `require_approval: "never"` and no `allowed_tools` is the most exposed
  combination this policy can see, and it fires the same as any other missing
  `allowed_tools` case rather than at elevated severity. A dedicated
  `require_approval` rule is a natural follow-up, not yet built.
- TypeScript agents that call the `@openai/agents` `hostedMcpTool(...)`
  factory are undetected by OAI-115 — TS discovery recognizes the factory
  call but does not currently capture its arguments onto the resulting
  `HostedToolDef`, so no OpenAI Agents TS pack rule can inspect
  `tool_config` yet.

---

## Recommendations beyond the fix

```python
from agents import Agent, input_guardrail, GuardrailFunctionOutput

@input_guardrail
def screen_mcp(ctx, agent, user_input) -> GuardrailFunctionOutput:
    # Inspect user_input AND the resolved tool list for poisoned descriptions.
    if _looks_poisoned(agent.tools):
        return GuardrailFunctionOutput(tripwire_triggered=True,
                                       output_info="suspicious MCP tool description")
    return GuardrailFunctionOutput(tripwire_triggered=False, output_info="")

agent = Agent(name="research", mcp_servers=[trusted_server],
              input_guardrails=[screen_mcp])
```

1. Add an `input_guardrail` that screens both the user input and the resolved MCP
   tool list before the model runs.
2. Pin MCP servers to known-trusted URLs and verify checksums/signatures where the
   transport allows; treat an unpinned remote MCP server as untrusted input.
3. Pair with `output_guardrails` so data the model tries to send back out through an
   MCP tool argument is inspected before egress.

For the hosted path (`HostedMCPTool`), pin the inherited catalog to a named
allow-list instead:

```python
from agents import Agent, HostedMCPTool

agent = Agent(
    name="research",
    tools=[
        HostedMCPTool(
            tool_config={
                "type": "mcp",
                "server_label": "deepwiki",
                "server_url": "https://mcp.deepwiki.com/mcp",
                "allowed_tools": ["ask_question"],
            }
        )
    ],
)
```

4. Add `allowed_tools` to every `HostedMCPTool`'s `tool_config`, naming only
   the tools this agent's task actually needs; re-review the list whenever
   the task changes.
5. Keep `require_approval` at its SDK default (`"always"`) for anything
   side-effecting, rather than `"never"` — the allow-list bounds *which*
   tools are reachable, `require_approval` bounds *whether each call*
   executes without a human in the loop; the two are complementary, not
   substitutes for each other.
