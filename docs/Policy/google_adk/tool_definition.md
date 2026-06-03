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
  - id: ADK-009
    severity: low
    confidence: 0.7
    scope: tool
    fix_type: code
  - id: ADK-013
    severity: low
    confidence: 0.8
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: Tool Definition Hygiene

**Policy ID:** `google_adk_tool_definition`  
**File:** `google_adk/tool_definition.yaml`  
**Rules:** ADK-001, ADK-002, ADK-007, ADK-009, ADK-013  
**Severities:** low, medium, low, low, low  
**Fix types:** code, code, code, code, code  
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

### ADK-009 — FunctionTool body prints to stdout (Severity: low, Confidence: 0.7, Fix type: code)

**What we detect:** a `FunctionTool`-wrapped body that calls the bare `print`
builtin, detected by the structured `has_print_call` predicate (an AST walk for a
bare `print` callee — `pprint`, `sys.stdout.write`, and a `print` in a comment or
string do not fire it).

**Why it is flaggable:** ADK tools share the runtime's stdout, so `print` debug
tracing leaks raw arguments (paths, IDs, decoded blobs) into the structured-log
stream, mangles JSON log lines, and can echo secrets from `tool_context.state`
into scrollback or log shippers. The output is also invisible to the model —
`print` writes go to the process, not the tool response.

**Real-world consequence:** a debug `print(user_record)` left in a shipped tool
writes PII into the container logs on every call.

**Why severity is low and not medium:** an observability/hygiene leak, not a
direct breach; impact depends on what is printed.

**Fix type — code:** delete the `print`, or replace it with a module logger
(`logging.getLogger(__name__).debug(...)`); if the data is for the model, return
it in the tool's structured result.

**Confidence 0.7:** the structured `has_print_call` match keys on the bare `print`
callee, so it does not false-positive on `print(` in a string literal or comment,
nor on `pprint`. False negatives: a non-`print` stdout write (e.g.
`sys.stdout.write`, `logging` at a too-low level) is not seen.

---

### ADK-013 — TypeScript FunctionTool has no description (Severity: low, Confidence: 0.8, Fix type: code)

**What we detect:**
A TypeScript `new FunctionTool({...})` whose `description` option is empty
(`has_docstring: false`). Discovery sets the tool's `Description` only when the
`description` key's value is a string literal (`ExprLiteralString`); `PredHasDocstring`
is `TrimSpace(Description) != ""`. So an omitted/empty `description` **and** one
built from a non-literal expression are both captured as empty and fire. Unlike
Python ADK, which derives the description from the function docstring, the
TypeScript SDK takes it as an explicit option.

**Why it is flaggable:**
ADK exposes the FunctionTool to the Gemini model using this `description`, read
verbatim to decide whether and how to call the tool. Empty, the model has no signal
about the tool's purpose and under-calls it or calls it with wrong arguments — the
same routing mechanism as the Python sibling
[ADK-001](#adk-001--functiontool-wrapped-function-has-no-docstring-severity-low-confidence-08-fix-type-code).

**Real-world consequence:**
A `new FunctionTool({ name: "fetchOrder", description: "", ... })` sits next to a
described sibling; the model cannot tell them apart and routes wrong under an
ambiguous prompt.

**Why severity is low and not medium:**
Like ADK-001 it degrades selection but rarely causes direct harm; the tool name
partially compensates.

**Fix type — code:**
Supplying the `description` in the `new FunctionTool({...})` options is a
tool-source edit.

**Confidence 0.8:**
Matches the Python sibling's 0.8 — the same "described via the agent/instruction
layer rather than the tool option" false positive applies, plus the TS-specific
case of a `description` assembled from a non-literal expression that is real text
the model sees yet captured as empty here.

---

## What this policy does not cover

Same gaps as [claude_sdk/tool_definition.md](../claude_sdk/tool_definition.md#what-this-policy-does-not-cover):
present-but-misleading descriptions, too-loose types, overlapping purposes, and
descriptions supplied outside the docstring. For ADK-013 specifically: a TypeScript
`description` assembled from a non-literal expression is real text the model reads,
but the literal-only capture records it as empty and fires anyway.

---

## Recommendations beyond the fix

The safe pattern — a router-oriented docstring, narrow parameter types, and
distinct verb-noun names — is in
[claude_sdk/tool_definition.md](../claude_sdk/tool_definition.md#recommendations-beyond-the-fix).
For ADK, give every `LlmAgent` a clear `description=` too (ADK-101), since the
same routing logic governs delegation between agents.
