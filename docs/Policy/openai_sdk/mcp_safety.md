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
references: [LLM01]
---

# Policy Rationale: MCP Integration Safety

**Policy ID:** `openai_sdk_mcp_safety`  
**File:** `openai_sdk/mcp_safety.yaml`  
**Rules:** OAI-106  
**Severities:** high  
**Fix types:** config  
**References:** LLM01

---

## What this policy covers

OpenAI Agents SDK agents that import tools from one or more MCP servers
(`mcp_servers=` present) but configure no `input_guardrails`. The match is
`agent_kwarg_present: [mcp_servers]` AND `agent_kwarg_list_empty:
[input_guardrails]` — it fires only when MCP is actually wired, so non-MCP agents
are unaffected.

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

---

## What this policy does not cover

- The *quality* of an `input_guardrail` that is present — a no-op guardrail
  satisfies the rule without screening anything.
- The trustworthiness of the MCP server itself (pinning, auth, checksums) — the rule
  checks for the screen, not the server's provenance.
- Tool poisoning that survives the guardrail (a description crafted to pass the
  specific checks the guardrail performs).
- `output_guardrails` gaps for MCP-fetched content (an egress concern; see
  agent_safety OAI-110 for the content-fetch output-guardrail rule).

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
