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
  - id: PYD-010
    severity: low
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: PYD-011
    severity: low
    confidence: 0.8
    scope: tool
    fix_type: code
  - id: PYD-013
    severity: low
    confidence: 0.9
    scope: tool
    fix_type: code
references: [LLM05, LLM06]
---

# Policy Rationale: Pydantic AI Tool Definition Hygiene

**Policy ID:** `pydantic_ai_tool_definition`  
**File:** `pydantic_ai/tool_definition.yaml`  
**Rules:** PYD-001, PYD-002, PYD-010, PYD-011, PYD-013  
**Severities:** low, medium, low, low, low  
**Fix types:** code, code, code, code, code  
**References:** LLM05 (Improper Output Handling), LLM06 (Excessive Agency)

---

## What this policy covers

Authoring hygiene for Pydantic AI tools defined with the `@agent.tool` /
`@agent.tool_plain` decorators or the `Tool(...)` factory. **PYD-001** fires when
the tool function has no docstring (predicate `has_docstring: false`). **PYD-002**
fires when the function takes parameters but none carry type annotations
(predicates `has_params: true` AND `has_typed_params: false`). **PYD-010** and
**PYD-011** check what a present docstring says: PYD-010 fires when it matches
one of six listed markers (predicate `has_description_text`), and PYD-011 when
it is under 40 characters (predicates `has_docstring: true` AND
`description_length_lt: 40`). **PYD-013** fires when the tool name is one of ten
listed names (`process`, `handle`, `run`, …) via predicate `name_in`. Pydantic AI
builds the tool's description from the docstring and its JSON argument schema
from the parameter type hints, so a missing docstring or untyped parameters
degrade exactly what the model sees, and it derives the tool name from the
function name unless one is passed explicitly.

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

A docstring can pass PYD-001 and still carry no real content. Pydantic AI
forwards the docstring text to the model as the tool's selection signal, so a
placeholder such as "TODO: describe this tool" is functionally
indistinguishable from no description at all, and the model still has to guess
from the function name. The name sits directly beside the description in what
the model sees, so it is part of the selection signal, and because Pydantic AI
derives the tool name from the function name unless one is passed explicitly, a
generically named function silently becomes a generically named tool. PYD-010,
PYD-011 and PYD-013 cover these gaps; all three rely on this mechanism.

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

### PYD-010 — Pydantic AI tool description is a placeholder (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:** a tool whose docstring matches one of six listed markers —
`todo`, `tbd`, `fixme`, `placeholder`, `no description`, `does stuff` —
predicate `has_description_text`. The docstring passes PYD-001's
has-a-description check; this rule looks at what it says.

**Why it is flaggable:** the mechanism is the one stated
[above](#why-definition-quality-is-a-distinct-concern-in-pydantic-ai-tools): a
placeholder is functionally indistinguishable from no description at all, so
the model still has to guess from the function name.

**Real-world consequence:** a tool whose docstring is "TODO: describe this
tool" reaches the model with no account of what it does. The model guesses from
the function name, and the example docstring has no parameter section for
Pydantic AI to read into the argument schema.

**Why severity is low:** the pack sets low, the same as PYD-001. The
explanation puts a placeholder in the same state as no description at all,
which is the state PYD-001 covers.

**Fix type — code:** replace the placeholder with a real description covering
what the tool does, what it returns, and when the model should call it, and add
the parameter section (Google, NumPy, or Sphinx style) that Pydantic AI reads
into the argument schema. Both are edits to the tool function's docstring.

**Confidence 0.85:** the pack sets 0.85 for this rule and states no false
positives, false negatives, or other limits for it.

### PYD-011 — Pydantic AI tool description is too short to guide model selection (Severity: low, Confidence: 0.8, Fix type: code)

**What we detect:** a tool that has a docstring (`has_docstring: true`) whose
description is under 40 characters (`description_length_lt: 40`), both under
`all:`. Because PYD-001 matches `has_docstring: false`, the two rules do not
fire on the same tool.

**Why it is flaggable:** the mechanism is the one stated
[above](#why-definition-quality-is-a-distinct-concern-in-pydantic-ai-tools). The
rule treats a description under 40 characters as too short to convey what a
tool does, what it returns, and when to call it rather than a similarly named
neighbor. A stub like "Gets data." leaves scope and preconditions to guesswork,
and a docstring this short has no room for the parameter section Pydantic AI
parses into the argument schema, so the arguments reach the model undescribed
as well.

**Real-world consequence:** a tool described as "Gets data." sits beside a
similarly named neighbor. Under an ambiguous prompt the model mis-selects it or
misses the call.

**Why severity is low:** the pack sets low, the same as PYD-001 and PYD-010.
The cost the explanation names is mis-selection or missed calls, and arguments
that reach the model undescribed.

**Fix type — code:** expand the description to at least a full sentence
covering inputs, outputs, and when this tool should be used over the
alternatives, and document each parameter in a section Pydantic AI can parse
into the argument schema.

**Confidence 0.8:** the pack sets 0.8 for this rule and states no false
positives, false negatives, or other limits for it.

### PYD-013 — Ambiguous Pydantic AI tool name (Severity: low, Confidence: 0.9, Fix type: code)

**What we detect:** a tool whose name is one of ten listed names — `process`,
`handle`, `run`, `do`, `execute`, `perform`, `work`, `go`, `thing`, `stuff` —
predicate `name_in`.

**Why it is flaggable:** the mechanism is the one stated
[above](#why-definition-quality-is-a-distinct-concern-in-pydantic-ai-tools). A
generic verb says nothing about what the tool acts on, so a name like `process`
or `handle` spends its part of the selection signal on nothing.

**Real-world consequence:** a function named `process` registered with
`@agent.tool` becomes a tool named `process`. The model either calls it for the
wrong job or passes over it entirely.

**Why severity is low:** the pack sets low and states no reasoning for it. The
consequence the explanation names is a tool called for the wrong job or passed
over.

**Fix type — code:** rename to a verb-object form that names the thing acted
on (`summarize_invoice`, `refund_charge`, `fetch_order_status`). Keep the
description for the detail and let the name carry the subject. Renaming is an
edit to the tool source.

**Confidence 0.9:** the pack sets 0.9 for this rule and states no false
positives, false negatives, or other limits for it.

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
- The *quality* of a type: a bare `dict` annotation satisfies PYD-002 but barely
  helps the model.
- Description quality beyond the two checks: PYD-010 matches the six listed
  markers only, so a placeholder worded any other way is not matched, and a
  docstring of 40 characters or more passes PYD-011 whatever it says. The pack
  states no other limits for either rule.
- Name quality beyond the list: PYD-013 matches the ten listed names only, so a
  generic name not on the list is not matched. The pack states no other limits
  for it.
- Whether the schema the model sees actually matches the tool's real behavior — a
  misleading docstring of 40 characters or more with no listed marker passes.

---

## Recommendations beyond the fix

```python
from pydantic_ai import Agent, RunContext

agent = Agent("openai:gpt-4o", deps_type=Deps)

@agent.tool
def create_invoice(ctx: RunContext[Deps], amount_cents: int, customer_id: str) -> str:
    """Create a draft invoice for a customer account.

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
5. Say in the docstring when the model should call the tool rather than the
   alternatives, not only what it does.
6. Name the tool in verb-object form (`create_invoice`, not `process` /
   `handle`) so the name carries the subject and the description carries the
   detail.
