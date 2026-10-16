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
  - id: ADK-018
    severity: low
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: ADK-019
    severity: low
    confidence: 0.8
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: Tool Definition Hygiene

**Policy ID:** `google_adk_tool_definition`  
**File:** `google_adk/tool_definition.yaml`  
**Rules:** ADK-001, ADK-002, ADK-007, ADK-009, ADK-013, ADK-018, ADK-019  
**Severities:** low, medium, low, low, low, low, low  
**Fix types:** code, code, code, code, code, code, code  
**References:** LLM06

> **Read [claude_sdk/tool_definition.md](../claude_sdk/tool_definition.md) for the full threat model.**
> This document covers Google ADK–specific differences only.

---

## What this policy covers

Google ADK `FunctionTool`-wrapped functions whose model-facing interface is
underspecified: ADK-001 fires on a missing docstring, ADK-002 on no
type-annotated parameters, ADK-007 on a vague name. Same predicates and routing
rationale as the Claude tool-definition policy. ADK-009 fires on a `print` call
in the tool body, and ADK-013 on a TypeScript `FunctionTool` with no
`description`. **ADK-018** and **ADK-019** check what a present docstring says:
ADK-018 fires when it matches one of six listed markers (predicate
`has_description_text`), and ADK-019 when it is under 40 characters
(predicates `has_docstring: true` AND `description_length_lt: 40`).

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

A docstring can pass ADK-001 and still carry no real content. ADK builds the
declaration's description from the docstring. The pack's explanation says a
stub like "TODO: describe this tool" is functionally indistinguishable from no
docstring at all and the model still has to guess from the function name, and
that a docstring this short has no room for parameter descriptions, so the
arguments reach the model undescribed as well. The declaration also carries the
tool name and the parameter schema. ADK-018 and ADK-019 cover these gaps; both
rely on this mechanism.

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

### ADK-018 — FunctionTool description is a placeholder (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:**
A Python `FunctionTool`-wrapped function whose docstring matches one of six
listed markers — `todo`, `tbd`, `fixme`, `placeholder`, `no description`,
`does stuff` — predicate `has_description_text`. The docstring passes ADK-001's
has-a-docstring check; this rule looks at what it says.

**Why it is flaggable:**
The mechanism is the one stated
[above](#why-tool-definition-hygiene-is-a-distinct-concern-in-agent-tools):
ADK builds the declaration's description from the docstring. The pack's
explanation says a placeholder leaves the model to guess from the function name,
as it would with no docstring at all.

**Real-world consequence:**
A tool whose docstring is "TODO: describe this tool" has that text as its
declaration description, beside neighboring tools that have real ones. Under an
ambiguous prompt the model can pick it for the wrong job or pass over it.

**Why severity is low:**
The pack sets low, the same as ADK-001, and states no reasoning for it. The
pack's explanation puts a placeholder in the same state as no docstring at all,
which is the state ADK-001 covers.

**Fix type — code:**
Replace the placeholder with a real description covering what the tool does,
what it returns, and when the model should call it rather than a neighboring
tool. ADK builds the declaration's description from the docstring, so document
each parameter in the docstring. Both are edits to the wrapped function's
docstring.

**Confidence 0.85:**
The pack sets 0.85 for this rule and names no false positives, false
negatives, or other limits for it.

---

### ADK-019 — FunctionTool description is too short to guide model selection (Severity: low, Confidence: 0.8, Fix type: code)

**What we detect:**
A Python `FunctionTool`-wrapped function that has a docstring
(`has_docstring: true`) under 40 characters (`description_length_lt: 40`),
both under `all:`. Because ADK-001 matches `has_docstring: false`, the two
rules do not fire on the same function.

**Why it is flaggable:**
The mechanism is the one stated
[above](#why-tool-definition-hygiene-is-a-distinct-concern-in-agent-tools).
The rule treats a docstring under 40 characters as too short to convey what a
tool does, what it returns, and when to call it rather than a similarly named
neighbor. The pack's explanation says a stub like "Gets data." leaves scope and
preconditions to guesswork, and that a docstring this short has no room for
parameter descriptions, so the arguments reach the model undescribed as well.
It adds that a `before_tool_callback`, the gate ADK-102 and ADK-107 ask for,
can block a call it recognizes as wrong but cannot supply the judgment the
description was meant to provide.

**Real-world consequence:**
A tool described as "Gets data." sits beside a similarly named neighbor. Under
an ambiguous prompt the model can pick the wrong one or miss the call.

**Why severity is low:**
The pack sets low, the same as ADK-001 and ADK-018, and states no reasoning
for it. The costs the explanation names are scope and preconditions left to
guesswork, and arguments that reach the model undescribed.

**Fix type — code:**
Expand the docstring to at least a full sentence covering inputs, outputs, and
the situation in which this tool should be used over the alternatives. ADK
builds the declaration's description from the docstring, so document each
parameter in the docstring.

**Confidence 0.8:**
The pack sets 0.8 for this rule and names no false positives, false
negatives, or other limits for it.

---

## What this policy does not cover

Same gaps as [claude_sdk/tool_definition.md](../claude_sdk/tool_definition.md#what-this-policy-does-not-cover):
present-but-misleading descriptions, too-loose types, overlapping purposes, and
descriptions supplied outside the docstring. For ADK-013 specifically: a TypeScript
`description` assembled from a non-literal expression is real text the model reads,
but the literal-only capture records it as empty and fires anyway.

Description quality beyond the two checks: ADK-018 matches the six listed
markers, so a placeholder worded any other way is not matched, and a
docstring of 40 characters or more passes ADK-019 whatever it says. The pack
states no other limits for either rule. Both are declared for `language:
python`; a TypeScript `FunctionTool` is checked by ADK-013's empty-`description`
rule, not by these two.

---

## Recommendations beyond the fix

The safe pattern — a router-oriented docstring, narrow parameter types, and
distinct verb-noun names — is in
[claude_sdk/tool_definition.md](../claude_sdk/tool_definition.md#recommendations-beyond-the-fix).
For ADK, give every `LlmAgent` a clear `description=` too (ADK-101), since the
same routing logic governs delegation between agents.

A docstring that passes ADK-001, ADK-018 and ADK-019:

```python
from google.adk.tools import FunctionTool

ORDER_STATUSES: dict[str, str] = {"A-1001": "shipped", "A-1002": "pending"}


def get_order_status(order_id: str) -> dict[str, str]:
    """Look up the fulfillment status of one customer order by its id.

    Call this when the user asks where an order is or whether it has shipped;
    use the invoice tools for billing questions instead.

    Args:
        order_id: The order identifier printed on the receipt, e.g. "A-1001".

    Returns:
        A dict with the "order_id" that was looked up and its "status":
        "pending", "shipped", "delivered", or "unknown".
    """
    return {"order_id": order_id, "status": ORDER_STATUSES.get(order_id, "unknown")}


order_status_tool = FunctionTool(get_order_status)
```

Say in the docstring when the model should call the tool rather than the
alternatives, and not just what it does, and document each parameter there.
