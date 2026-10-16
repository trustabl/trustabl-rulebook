---
policy_id: openai_sdk_tool_definition
category: openai_sdk
topic: tool_definition
rules:
  - id: OAI-001
    severity: low
    confidence: 0.9
    scope: tool
    fix_type: code
  - id: OAI-002
    severity: medium
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: OAI-007
    severity: low
    confidence: 0.9
    scope: tool
    fix_type: code
  - id: OAI-022
    severity: low
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: OAI-025
    severity: low
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: OAI-026
    severity: low
    confidence: 0.8
    scope: tool
    fix_type: code
  - id: OAI-027
    severity: low
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: OAI-028
    severity: low
    confidence: 0.8
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: Tool Definition Hygiene

**Policy ID:** `openai_sdk_tool_definition`  
**File:** `openai_sdk/tool_definition.yaml`  
**Rules:** OAI-001, OAI-002, OAI-007, OAI-022, OAI-025, OAI-026, OAI-027, OAI-028  
**Severities:** low, medium, low, low, low, low, low, low  
**Fix types:** code, code, code, code, code, code, code, code  
**References:** LLM06

> **Read [claude_sdk/tool_definition.md](../claude_sdk/tool_definition.md) for the full threat model.**
> This document covers OpenAI Agents SDK–specific differences only.

---

## What this policy covers

OpenAI Agents SDK tools whose model-facing interface is underspecified. For
Python `@function_tool`-decorated functions: OAI-001 fires on a missing
docstring (`has_docstring: false`), OAI-002 on no type-annotated parameters
(`has_typed_params: false`), OAI-007 on a vague name (`name_in`), OAI-025 when
the docstring matches one of six listed markers (`has_description_text`), and
OAI-026 when the description is under 40 characters (`has_docstring: true` AND
`description_length_lt: 40`). For TypeScript `tool({...})` definitions: OAI-022
fires on an empty or missing `description` (`has_docstring: false`), and
OAI-027 and OAI-028 apply the same marker and length predicates as OAI-025 and
OAI-026. OAI-001, OAI-002 and OAI-007 use the same predicates and the same
routing rationale as the Claude tool-definition policy.

---

## Why tool-definition hygiene is a distinct concern in agent tools

The mechanism is identical to the Claude case — the model routes on the tool's
name, description, and parameter schema, and gaps cause mis-selection or
fabricated arguments. See
[claude_sdk/tool_definition.md](../claude_sdk/tool_definition.md#why-tool-definition-hygiene-is-a-distinct-concern-in-agent-tools).

OpenAI-specific note: `@function_tool` builds the tool's JSON schema from the
type hints and docstring automatically, and by default enforces it in
`strict_mode`. So untyped parameters (OAI-002) not only loosen the model's
guidance, they weaken the very schema strict-mode would otherwise enforce — this
policy pairs with `decorator_config` (OAI-003, which flags `strict_mode=False`).

A description can be present and still carry little. In Python the SDK uses
the docstring as the description sent to the model. For a docstring that passes
OAI-001 but carries a placeholder marker, the pack's explanation says a stub
like "TODO: describe this tool" is functionally indistinguishable from no
description at all, and that the model still has to guess from the function
name. For TypeScript, the pack's explanation calls the description the model's
primary routing signal alongside the name, and says "TODO: describe this tool"
carries no signal the name did not already. OAI-025 and OAI-026 cover the
Python side, OAI-027 and OAI-028 the TypeScript side; all four rely on the
pack's explanations above.

---

## Rule-by-rule defense

### OAI-001 — Tool function has no docstring (Severity: low, Confidence: 0.9, Fix type: code)
**What we detect:** A `@function_tool` with no docstring. **Why it is flaggable:**
the SDK uses the docstring as the model-facing description; without it the model
routes on the name alone. **Real-world consequence:** two similar tools become
indistinguishable to the router, so the wrong one fires under an ambiguous
prompt. **Why low not medium:** degrades selection, rarely direct harm.
**Fix type — code:** add a docstring. **Confidence 0.9:** rare false positive
where the description is set via a decorator kwarg.

### OAI-002 — Tool has no type-annotated parameters (Severity: medium, Confidence: 0.85, Fix type: code)
**What we detect:** a tool with parameters, none annotated. **Why it is
flaggable:** the type hints become the enforced JSON schema; without them the
model fabricates loosely-typed arguments. **Real-world consequence:**
`transfer(amount, to)` runs with `amount="a lot"`. **Why medium not low:**
wrong-argument execution, not just mis-selection. **Fix type — code:** annotate
the parameters. **Confidence 0.85:** a tool whose schema comes from a Pydantic
model elsewhere can be a false positive.

### OAI-007 — Ambiguous tool name (Severity: low, Confidence: 0.9, Fix type: code)
**What we detect:** a name in the vague-verb set (`process`, `run`, `handle`, …).
**Why it is flaggable:** a generic name carries no routing signal. **Real-world
consequence:** `run` and `process` are a coin-flip for the router. **Why low not
medium:** a clear docstring compensates. **Fix type — code:** rename to
verb-noun. **Confidence 0.9:** curated name list, deliberate matches.

### OAI-022 — TypeScript tool has no description (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:**
A TypeScript `tool({...})` whose `description` option is empty
(`has_docstring: false`). Discovery sets the tool's `Description` only when the
`description` key's value is a string literal (`ExprLiteralString`); `PredHasDocstring`
is `TrimSpace(Description) != ""`. So an omitted/empty `description` **and** a
`description` built from a non-literal expression (a template string, an
identifier, a concatenation) are both captured as empty and fire. Unlike the
Python sibling OAI-001, which reads the docstring, the TypeScript factory takes the
description as an explicit option.

**Why it is flaggable:**
The SDK sends this `description` to the model as the basis for deciding whether to
call the tool. Empty, the model routes on the tool name alone — the same
mis-selection mechanism as the Python sibling
[OAI-001](#oai-001--tool-function-has-no-docstring-severity-low-confidence-09-fix-type-code).

**Real-world consequence:**
A `tool({ name: "lookup", description: "" , ...})` next to a described `search`
tool is a coin-flip for the router under an ambiguous prompt — the wrong tool
fires.

**Why severity is low and not medium:**
Like OAI-001 it degrades selection but rarely causes direct harm, and the tool name
partially compensates.

**Fix type — code:**
Adding the `description` string in the `tool({...})` options is a tool-source edit.

**Confidence 0.85:**
Matches the Python sibling's 0.85. The firing is mechanically exact, but a
`description` assembled at runtime from a non-literal expression is real text the
model sees yet captured as empty here — the false-positive case the literal-only
capture cannot rule out, which the YAML explanation calls out explicitly.

### OAI-025 — Tool description is a placeholder (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:** a Python `@function_tool` whose docstring matches one of six
listed markers — `todo`, `tbd`, `fixme`, `placeholder`, `no description`,
`does stuff` — predicate `has_description_text`. The docstring passes OAI-001's
has-a-description check; this rule looks at what it says.

**Why it is flaggable:** the mechanism is the one stated
[above](#why-tool-definition-hygiene-is-a-distinct-concern-in-agent-tools). The
pack's explanation says a stub like "TODO: describe this tool" is functionally
indistinguishable from no description at all, and that the model still has to
guess from the function name. It also says strict schemas do not compensate:
OAI-003's `strict_mode` constrains the shape of the arguments, never whether
calling this tool was the right move.

**Real-world consequence:** a docstring such as "TODO: describe this tool"
can produce a well-formed call to the wrong tool. Each
mis-selection also spends a turn against the `max_turns` budget that
[OAI-112](agent_safety.md) asks for. The pack's explanation adds that nothing
in a trace attributes the wasted turn to the description that caused it; that
sentence is the pack's, and this doc has not checked it against the SDK's
tracing.

**Why severity is low:** the pack sets low, the same as OAI-001, and states no
reasoning for it. The explanation puts a placeholder in the same state as no
description at all, which is the state OAI-001 covers.

**Fix type — code:** replace the placeholder with a real description covering
what the tool does, what it returns, and when the model should call it rather
than a neighboring tool. The pack also names an explicit `description_override`
on `@function_tool` as the alternative to the docstring where the function name
cannot carry that. Both are edits to the tool source.

**Confidence 0.85:** the pack sets 0.85 for this rule and states no false
positives, false negatives, or other limits for it.

### OAI-026 — Tool description is too short to guide model selection (Severity: low, Confidence: 0.8, Fix type: code)

**What we detect:** a Python `@function_tool` that has a docstring
(`has_docstring: true`) whose description is under 40 characters
(`description_length_lt: 40`), both under `all:`. Because OAI-001 matches
`has_docstring: false`, the two rules do not fire on the same tool.

**Why it is flaggable:** the mechanism is the one stated
[above](#why-tool-definition-hygiene-is-a-distinct-concern-in-agent-tools). The
rule treats a description under 40 characters as too short to convey what a
tool does, what it returns, and when to call it rather than a similarly named
neighbor. A stub like "Gets data." leaves scope and preconditions to guesswork.

**Real-world consequence:** a tool described as "Gets data." sits beside a
similarly named neighbor and the model picks between them on a guess. The pack
states that an agent with handoffs picks between its own tools and its peers'
on the strength of these strings, so a thin description can route the whole
conversation to the wrong agent rather than cause one wrong call. The handoff
claim is the pack's; this doc has not checked it against the SDK.

**Why severity is low:** the pack sets low, the same as OAI-001 and OAI-025,
and states no reasoning for it. The cost the explanation names is guesswork at
selection time and, with handoffs, a conversation routed to the wrong agent.

**Fix type — code:** expand the description to at least a full sentence
covering inputs, outputs, and the situation in which this tool should be used
over the alternatives. Where two tools are easy to confuse, say in each which
one the other case belongs to.

**Confidence 0.8:** the pack sets 0.8 for this rule and states no false
positives, false negatives, or other limits for it.

### OAI-027 — TypeScript tool description is a placeholder (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:** a TypeScript `tool({...})` whose `description` matches one
of the same six listed markers as OAI-025 (`has_description_text`). The tool
sets a description, so it passes OAI-022; this rule looks at what the
description says.

**Why it is flaggable:** the mechanism is the TypeScript one stated
[above](#why-tool-definition-hygiene-is-a-distinct-concern-in-agent-tools). The
pack's explanation says the description is the model's primary routing signal
alongside the name, and that "TODO: describe this tool" carries no signal the
name did not already. It also says the Zod parameters schema does not
compensate: it constrains the shape of the arguments once the model has decided
to call this tool, never whether that decision was right.

**Real-world consequence:** a placeholder description can yield a well-formed
call to the wrong tool. The pack states that with handoffs the reach is wider:
an agent picks between its own tools and its peers' from these strings, so the
stub can route the conversation to the wrong agent rather than merely the
wrong function. The handoff claim is the pack's; this doc has not checked it
against the SDK.

**Why severity is low:** the pack sets low, the same as OAI-022, and states no
reasoning for it. The explanation puts a placeholder in the state OAI-022
covers.

**Fix type — code:** replace the placeholder in the `tool({...})` options with
a real description covering what the tool does, what it returns, and when the
model should call it rather than a neighboring tool. The SDK uses the string as
the tool's description, so write it for the model rather than a human
maintainer.

**Confidence 0.85:** the pack sets 0.85 for this rule and states no false
positives, false negatives, or other limits for it.

### OAI-028 — TypeScript tool description is too short to guide model selection (Severity: low, Confidence: 0.8, Fix type: code)

**What we detect:** the same predicates as OAI-026 (`has_docstring: true` and
`description_length_lt: 40`, both under `all:`), on a TypeScript `tool({...})`.
Because OAI-022 matches `has_docstring: false`, the two rules do not fire on the
same tool.

**Why it is flaggable:** the mechanism is the TypeScript one stated
[above](#why-tool-definition-hygiene-is-a-distinct-concern-in-agent-tools). The
rule treats a description under 40 characters as too short to convey what a
tool does, what it returns, and when to call it rather than a similarly named
neighbor. The pack's explanation calls the description the model's primary
routing signal alongside the tool name. It also says a stub like "Gets data."
leaves scope and preconditions to guesswork.

**Real-world consequence:** the pack's explanation says each resulting
mis-selection spends a turn against the agent's max turns budget, and that
nothing in a trace attributes the wasted turn to the description that caused
it, so the run just looks slow or confused. These statements are the pack's;
this doc has not checked them against the SDK's tracing.

**Why severity is low:** the pack sets low, the same as OAI-022 and OAI-027,
and states no reasoning for it. The cost the explanation names is turns spent
on mis-selected calls.

**Fix type — code:** expand the `description` to at least a full sentence
covering inputs, outputs, and the situation in which this tool should be used
over the alternatives. Where two tools are easy to confuse, say in each which
one the other case belongs to.

**Confidence 0.8:** the pack sets 0.8 for this rule and states no false
positives, false negatives, or other limits for it.

---

## What this policy does not cover

Same gaps as [claude_sdk/tool_definition.md](../claude_sdk/tool_definition.md#what-this-policy-does-not-cover):
present-but-misleading descriptions, present-but-too-loose types (`x: Any`),
overlapping tool purposes, and descriptions supplied via decorator kwargs. For
OAI-022 specifically: a TypeScript `description` assembled from a non-literal
expression is real text the model reads, but the literal-only capture records it as
empty and fires anyway.

Description quality beyond the marker and length checks: OAI-025 and OAI-027
match the six listed markers only, so a placeholder worded any other way is not
matched, and a description of 40 characters or more passes OAI-026 and OAI-028
whatever it says. The pack states no other limits for these four rules.

---

## Recommendations beyond the fix

The safe pattern — a router-oriented docstring, narrow parameter types, and
distinct verb-noun names — is in
[claude_sdk/tool_definition.md](../claude_sdk/tool_definition.md#recommendations-beyond-the-fix).
For the OpenAI SDK, keep `strict_mode` at its default `True` (see OAI-003) so the
type hints you add are actually enforced at runtime.

```python
from agents import RunContextWrapper, function_tool

INVOICES = {"inv_10423": {"id": "inv_10423", "customer": "cus_77", "total_cents": 129900}}


def invoice_lookup_error(ctx: RunContextWrapper, error: Exception) -> str:
    return "invoice_lookup_failed: pass an existing invoice ID such as inv_10423."


@function_tool(failure_error_function=invoice_lookup_error)
def fetch_invoice(invoice_id: str) -> dict:
    """Fetch one invoice by its ID and return its customer and total in cents.

    Use this when the user names a specific invoice ID. It does not search;
    use search_invoices to find invoices by customer, date or amount.

    Args:
        invoice_id: The invoice ID, for example "inv_10423".
    """
    return INVOICES[invoice_id]
```

The TypeScript form, where the description is a `tool({...})` option:

```typescript
import { tool } from "@openai/agents";
import { z } from "zod";

const INVOICES: Record<string, { id: string; customer: string; totalCents: number }> = {
  inv_10423: { id: "inv_10423", customer: "cus_77", totalCents: 129900 },
};

export const fetchInvoice = tool({
  name: "fetch_invoice",
  description: "Fetch one invoice by its ID and return its customer and total in cents. Use this when the user names a specific invoice ID. It does not search; use search_invoices to find invoices by customer, date or amount.",
  parameters: z.object({ invoiceId: z.string().regex(/^inv_\d+$/) }),
  execute: async ({ invoiceId }) => {
    const invoice = INVOICES[invoiceId];
    if (!invoice) {
      return { ok: false, error: "invoice_not_found" };
    }
    return { ok: true, invoice };
  },
});
```

1. Write the description for the model: what the tool does, what it returns,
   and when to call it rather than a neighboring tool. Where two tools are easy
   to confuse, say in each which one the other case belongs to.
2. In Python, where the function name cannot carry that, the pack suggests an
   explicit `description_override` on `@function_tool` instead of relying on
   the docstring.
3. In TypeScript, write the `description` as a single string literal. OAI-022
   captures a description built from a non-literal expression as empty and
   fires on it.
