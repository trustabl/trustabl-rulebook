---
policy_id: crewai_tool_definition
category: crewai
topic: tool_definition
rules:
  - id: CREW-001
    severity: low
    confidence: 0.9
    scope: tool
    fix_type: code
  - id: CREW-002
    severity: medium
    confidence: 0.85
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: CrewAI Tool Definition Hygiene

**Policy ID:** `crewai_tool_definition`  
**File:** `crewai/tool_definition.yaml`  
**Rules:** CREW-001, CREW-002  
**Severities:** low, medium  
**Fix types:** code, code  
**References:** LLM06 (Excessive Agency)

---

## What this policy covers

Authoring hygiene for CrewAI tools defined with the `@tool` decorator from
`crewai.tools`. **CREW-001** fires when the decorated function has no docstring
(predicate `has_docstring: false`). **CREW-002** fires when the function takes
parameters but none carry type annotations (predicates `has_params: true` AND
`has_typed_params: false`). Both read the function signature CrewAI turns into
what the model sees: the docstring becomes the tool's description, the type hints
become its argument schema.

---

## Why definition quality is a distinct concern in CrewAI tools

The model never sees a CrewAI tool's implementation — it sees only the
description and argument schema CrewAI derives from the function. The model
selects which tool to call and what arguments to pass entirely from that derived
surface. A tool with no docstring reaches the model as a bare name: it cannot
tell what the tool does or when to call it, so it skips the tool or invokes it
with the wrong arguments. A tool with untyped parameters produces an
underspecified schema: the model gets no type guidance, emits arguments of the
wrong shape, and Pydantic rejects them at validation time — a silent reliability
tax on every call. There is an excessive-agency edge too (LLM06): an
underspecified schema widens the tool's input surface, so wrong-shaped
model-supplied values that slip past validation reach the tool body the author
never anticipated. The gap is not a remote-execution hole but a degradation of
the contract the model routes against, and it compounds on a retrying agent that
burns turns re-issuing mis-shaped calls.

---

## Rule-by-rule defense

### CREW-001 — Tool has no description (Severity: low, Confidence: 0.9, Fix type: code)

**What we detect:** a `@tool`-decorated function with no docstring (predicate
`has_docstring`).

**Why it is flaggable:** CrewAI passes the docstring to the model verbatim as the
tool's description; with none, the tool is a bare name the model cannot reason
about.

**Real-world consequence:** a `lookup` tool with no docstring is never selected
when the user asks a question it could have answered, or is called with a
nonsense argument because the model is guessing at its purpose.

**Why severity is low and not medium:** it is a routing-quality defect with no
direct security impact, and the failure mode (a skipped or mis-called tool) is
visible and recoverable rather than silent. **Fix type — code:** adding a
docstring is a tool-source edit. **Confidence 0.9:** docstring presence is
unambiguous; the small gap covers a tool whose description is supplied another
way the predicate does not model.

### CREW-002 — Tool parameters are not type-annotated (Severity: medium, Confidence: 0.85, Fix type: code)

**What we detect:** a `@tool` function that has parameters but no type
annotations on any of them (predicates `has_params` + `not has_typed_params`).

**Why it is flaggable:** CrewAI builds the argument schema from the type hints;
without them the model gets no shape guidance and emits wrongly-typed arguments
that fail validation.

**Real-world consequence:** a `create_invoice(amount, customer)` tool with
untyped params lets the model pass `amount="twelve dollars"`; Pydantic rejects
it, the call retries, and turns are wasted before it succeeds — or it silently
coerces to the wrong value.

**Why severity is medium and not low:** unlike a missing description, a
mis-shaped argument can reach `execute` with the wrong value and cause an
incorrect side effect, not just a skipped call — so the impact is higher than
CREW-001. **Fix type — code:** annotating parameters is a source edit.
**Confidence 0.85:** the rule fires only when *no* parameter is typed, so a
partially-typed tool is a false negative; and a tool that documents shapes in the
docstring but omits annotations still fires.

---

## What this policy does not cover

- A *partially* typed tool (some parameters annotated, some not) does not fire —
  CREW-002 requires that no parameter carries a type.
- The *quality* of a docstring or a type: a one-word docstring or an overly broad
  `dict` annotation satisfies the rules but barely helps the model.
- Tools whose description is supplied through a mechanism other than the
  function docstring.
- Whether the schema the model sees actually matches the tool's real behavior —
  a misleading-but-present docstring passes.

---

## Recommendations beyond the fix

```python
from crewai.tools import tool

@tool("create_invoice")
def create_invoice(amount_cents: int, customer_id: str) -> str:
    """Create a draft invoice for a customer.

    Args:
        amount_cents: Invoice total in integer cents (e.g. 1299 for $12.99).
        customer_id: The customer's opaque ID, e.g. "cus_abc123".
    Returns: the new invoice ID.
    """
    ...
```

1. Write the docstring for the model, not a human maintainer: state what the
   tool does, the exact inputs it expects, and what it returns.
2. Annotate every parameter with a concrete type (`int`, `list[str]`, a Pydantic
   model) — prefer precise types (`amount_cents: int`) over loose ones
   (`amount`).
3. Use an `Enum` or `Literal` for closed-set arguments so the model cannot emit
   an out-of-range value.
4. Keep the description and the implementation in sync — a docstring that
   overstates what the tool does is its own correctness hazard.
