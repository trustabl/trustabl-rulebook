---
policy_id: google_adk_tool_definition
category: google_adk
topic: tool_definition
rules:
  - id: ADK-001
    severity: low
    confidence: 0.8
    scope: tool
    fix_type: code
  - id: ADK-002
    severity: medium
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: ADK-007
    severity: low
    confidence: 0.9
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: Tool Definition Hygiene

**Policy ID:** `google_adk_tool_definition`  
**File:** `google_adk/tool_definition.yaml`  
**Rules:** ADK-001, ADK-002, ADK-007  
**Severities:** low, medium, low  
**Fix types:** code, code, code  
**References:** LLM06

> **Read [claude_sdk/tool_definition.md](../claude_sdk/tool_definition.md) for the full threat model.**
> This document covers Google ADK–specific differences only.

---

## What this policy covers

Google ADK `FunctionTool`-wrapped functions whose model-facing interface is
underspecified: ADK-001 fires on a missing docstring, ADK-002 on no
type-annotated parameters, ADK-007 on a vague name. Same predicates and routing
rationale as the Claude tool-definition policy.

---

## Why tool-definition hygiene is a distinct concern in agent tools

Identical to the Claude case — the model routes on the tool's name, description,
and parameter schema, and gaps cause mis-selection or fabricated arguments. See
[claude_sdk/tool_definition.md](../claude_sdk/tool_definition.md#why-tool-definition-hygiene-is-a-distinct-concern-in-agent-tools).

ADK-specific note: ADK builds the tool schema from the wrapped function's
signature and uses the docstring as the description the Gemini model reads.
The same `description` discipline also governs *agent* delegation in ADK (see
agent_safety, ADK-101) — so docstring/description hygiene matters at both the tool
and the agent layer in this SDK.

---

## Rule-by-rule defense

### ADK-001 — FunctionTool-wrapped function has no docstring (Severity: low, Confidence: 0.8, Fix type: code)
**What we detect:** a `FunctionTool`-wrapped function with no docstring. **Why
flaggable:** the docstring is the model-facing description; without it the model
routes on the name alone. **Real-world consequence:** two similar tools become
indistinguishable to the router. **Why low not medium:** degrades selection,
rarely direct harm. **Fix type — code:** add a docstring. **Confidence 0.8:**
slightly lower than the OpenAI/Claude equivalents because ADK tools are sometimes
described via the agent/instruction layer rather than the docstring.

### ADK-002 — FunctionTool-wrapped function has no type-annotated parameters (Severity: medium, Confidence: 0.85, Fix type: code)
**What we detect:** a wrapped function with parameters, none annotated. **Why
flaggable:** the type hints become the schema the model fills; without them it
fabricates loosely-typed values. **Real-world consequence:** `transfer(amount,
to)` runs with malformed `amount`. **Why medium not low:** wrong-argument
execution. **Fix type — code:** annotate the parameters. **Confidence 0.85:** a
tool whose schema comes from a Pydantic model elsewhere may be a false positive.

### ADK-007 — Ambiguous tool name (Severity: low, Confidence: 0.9, Fix type: code)
**What we detect:** a name in the vague-verb set. **Why flaggable:** carries no
routing signal. **Real-world consequence:** `run`/`process` are a coin-flip for
the router. **Why low not medium:** a clear docstring compensates. **Fix type —
code:** rename to verb-noun. **Confidence 0.9:** curated name list.

---

## What this policy does not cover

Same gaps as [claude_sdk/tool_definition.md](../claude_sdk/tool_definition.md#what-this-policy-does-not-cover):
present-but-misleading descriptions, too-loose types, overlapping purposes, and
descriptions supplied outside the docstring.

---

## Recommendations beyond the fix

The safe pattern — a router-oriented docstring, narrow parameter types, and
distinct verb-noun names — is in
[claude_sdk/tool_definition.md](../claude_sdk/tool_definition.md#recommendations-beyond-the-fix).
For ADK, give every `LlmAgent` a clear `description=` too (ADK-101), since the
same routing logic governs delegation between agents.
