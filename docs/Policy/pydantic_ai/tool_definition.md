---
policy_id: pydantic_ai_tool_definition
category: pydantic_ai
topic: tool_definition
rules:
  - id: PYD-001
    severity: low
    confidence: 0.9
    scope: tool
    fix_type: code
  - id: PYD-002
    severity: medium
    confidence: 0.85
    scope: tool
    fix_type: code
references: [LLM05, LLM06]
---

# Policy Rationale: Pydantic AI Tool Definition Hygiene

**Policy ID:** `pydantic_ai_tool_definition`  
**File:** `pydantic_ai/tool_definition.yaml`  
**Rules:** PYD-001, PYD-002  
**Severities:** low, medium  
**Fix types:** code, code  
**References:** LLM05 (Improper Output Handling), LLM06 (Excessive Agency)

---

## What this policy covers

Authoring hygiene for Pydantic AI tools defined with the `@agent.tool` /
`@agent.tool_plain` decorators or the `Tool(...)` factory. **PYD-001** fires when
the tool function has no docstring (predicate `has_docstring: false`). **PYD-002**
fires when the function takes parameters but none carry type annotations
(predicates `has_params: true` AND `has_typed_params: false`). Pydantic AI builds
the tool's description from the docstring and its JSON argument schema from the
parameter type hints, so a missing docstring or untyped parameters degrade exactly
what the model sees.

---

## Why definition quality is a distinct concern in Pydantic AI tools

The model selects which tool to call and what arguments to pass from the description
and argument schema Pydantic AI derives from the function — it never sees the
implementation. Pydantic AI leans on the docstring harder than most frameworks: it
becomes the tool description *and* it is where the framework extracts
per-parameter descriptions (it parses Google/NumPy/Sphinx docstring styles). So an
absent docstring strips both the tool-level and the argument-level guidance at once,
and the tool reaches the model as a bare name it cannot reason about. Untyped
parameters are the other half: Pydantic AI builds the JSON argument schema from the
type hints, so a tool with no annotations produces an underspecified schema, the
model emits wrongly-shaped arguments, and Pydantic rejects them at validation time
— a silent reliability tax, and on a retrying agent a source of wasted turns. This
is the framing-quality side of LLM05 (Improper Output Handling): a degradation of
the contract the model routes against rather than a remote-execution hole. It has
an excessive-agency edge too (LLM06) — an underspecified schema widens the tool's
input surface, so wrong-shaped model-supplied values that slip past validation
reach the tool body the author never anticipated.

---

## Rule-by-rule defense

### PYD-001 — Tool has no description (Severity: low, Confidence: 0.9, Fix type: code)

**What we detect:** a Pydantic AI tool function with no docstring (predicate
`has_docstring`).

**Why it is flaggable:** Pydantic AI turns the docstring into the tool description
and parses its parameter sections into per-argument descriptions; with none, both
the tool- and argument-level guidance are gone and the tool is a bare name.

**Real-world consequence:** a `lookup` tool with no docstring is never selected when
the user asks a question it could answer, or is called with a nonsense argument
because the model has neither a tool description nor parameter hints to go on.

**Why severity is low and not medium:** it is a routing-quality defect with no
direct security impact, and the failure mode (a skipped or mis-called tool) is
visible and recoverable. **Fix type — code:** adding a docstring is a tool-source
edit. **Confidence 0.9:** docstring presence is unambiguous; the small gap covers a
description supplied another way (e.g. a `Tool(..., description=...)` factory
argument) the docstring-only predicate does not model.

### PYD-002 — Tool parameters are not type-annotated (Severity: medium, Confidence: 0.85, Fix type: code)

**What we detect:** a Pydantic AI tool function that has parameters but no type
annotations on any of them (predicates `has_params` + `not has_typed_params`).

**Why it is flaggable:** Pydantic AI builds the JSON argument schema from the type
hints; without them the model gets no shape guidance and emits wrongly-typed
arguments that fail validation, wasting turns on a retrying agent.

**Real-world consequence:** a `create_invoice(amount, customer)` tool with untyped
params lets the model pass `amount="twelve dollars"`; Pydantic rejects it, the call
retries, and turns are wasted before it succeeds.

**Why severity is medium and not low:** unlike a missing description, a mis-shaped
argument can reach the tool body with the wrong value and cause an incorrect side
effect, not just a skipped call — so the impact exceeds PYD-001. **Fix type —
code:** annotating parameters is a source edit. **Confidence 0.85:** there is a
specific Pydantic-AI false-negative the number accounts for — a context tool's
leading `ctx: RunContext[...]` parameter is itself typed, so an `@agent.tool` whose
*business* parameters are untyped but whose `ctx` is annotated may not be flagged
(a false negative, never a false positive). `@agent.tool_plain` tools and no-arg
tools are unaffected.

---

## What this policy does not cover

- **The RunContext false negative:** an `@agent.tool` whose only typed parameter is
  its leading `ctx: RunContext[...]` may pass PYD-002 even though its business
  parameters are untyped — the presence of the typed `ctx` satisfies the
  "has a typed param" check. This is a deliberate false negative (never a false
  positive); review context tools by hand for untyped business parameters.
- A *partially* typed tool (some business parameters annotated, some not) does not
  fire — PYD-002 requires that no parameter carries a type.
- A description supplied through a `Tool(..., description=...)` factory argument
  rather than a docstring may still be flagged by PYD-001's docstring-only
  predicate.
- The *quality* of a docstring or a type: a one-word docstring or a bare `dict`
  annotation satisfies the rules but barely helps the model.
- Whether the schema the model sees actually matches the tool's real behavior — a
  misleading-but-present docstring passes.

---

## Recommendations beyond the fix

```python
from pydantic_ai import Agent, RunContext

agent = Agent("openai:gpt-4o", deps_type=Deps)

@agent.tool
def create_invoice(ctx: RunContext[Deps], amount_cents: int, customer_id: str) -> str:
    """Create a draft invoice for a customer.

    Args:
        amount_cents: Invoice total in integer cents (e.g. 1299 for $12.99).
        customer_id: The customer's opaque ID, e.g. "cus_abc123".
    Returns: the new invoice ID.
    """
    ...   # every business parameter is typed, not just ctx
```

1. Write the docstring for the model: state what the tool does, its inputs, and its
   return value, using a parsed style (Google/NumPy/Sphinx) so Pydantic AI extracts
   per-parameter descriptions.
2. Annotate **every business parameter** with a concrete type — do not rely on the
   typed `ctx: RunContext[...]` to satisfy the schema; the model needs shapes for
   the arguments it actually supplies.
3. Use an `Enum` or `Literal` for closed-set arguments, or a nested Pydantic model
   for structured input, so validation rejects out-of-range values.
4. Keep the description and the implementation in sync — an overstated docstring is
   its own correctness hazard.
