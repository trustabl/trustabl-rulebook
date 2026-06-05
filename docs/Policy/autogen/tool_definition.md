---
policy_id: autogen_tool_definition
category: autogen
topic: tool_definition
rules:
  - id: AG2-007
    severity: low
    confidence: 0.9
    scope: tool
    fix_type: code
  - id: AG2-008
    severity: medium
    confidence: 0.85
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: AutoGen Tool Definition Hygiene

**Policy ID:** `autogen_tool_definition`  
**File:** `autogen/tool_definition.yaml`  
**Rules:** AG2-007, AG2-008  
**Severities:** low, medium  
**Fix types:** code, code  
**References:** LLM06 (Excessive Agency)

---

## What this policy covers

Authoring hygiene for AutoGen tools registered via `register_function` or the
`register_for_llm` / `register_for_execution` decorators. **AG2-007** fires when
the registered function has no docstring (predicate `has_docstring: false`).
**AG2-008** fires when the function takes parameters but none carry type
annotations (predicates `has_params: true` AND `has_typed_params: false`).
AutoGen turns the function's docstring into the tool's description and its type
hints into the argument schema the model sees.

---

## Why definition quality is a distinct concern in AutoGen tools

The model never sees an AutoGen tool's implementation — only the description and
argument schema AutoGen derives from the registered function. It selects which
tool to call and what arguments to pass from that derived surface. A tool with
neither a docstring nor an explicit `description=` reaches the model as a bare
name: it cannot tell what the tool does or when to call it, so it skips the tool
or invokes it with the wrong arguments. A tool with untyped parameters produces
an underspecified schema: the model gets no type guidance, emits arguments of the
wrong shape, and the SDK rejects them at validation time — a silent reliability
tax on every call. There is an excessive-agency edge too (LLM06): an
underspecified schema widens the tool's input surface, so wrong-shaped
model-supplied values that slip past validation reach the registered function the
author never anticipated. The gap is not a remote-execution hole but a
degradation of the contract the model routes against, and it compounds across a
multi-agent conversation that burns turns re-issuing mis-shaped calls.

---

## Rule-by-rule defense

### AG2-007 — Tool has no description (Severity: low, Confidence: 0.9, Fix type: code)

**What we detect:** a registered tool function with no docstring (predicate
`has_docstring`).

**Why it is flaggable:** AutoGen derives the tool's description from the
docstring (unless an explicit `description=` is passed at registration); with
neither, the tool is a bare name the model cannot reason about.

**Real-world consequence:** a `lookup` tool with no docstring is never selected
when the user asks a question it could answer, or is called with a nonsense
argument because the model is guessing at its purpose.

**Why severity is low and not medium:** it is a routing-quality defect with no
direct security impact, and the failure mode (a skipped or mis-called tool) is
visible and recoverable. **Fix type — code:** adding a docstring (or a
`description=`) is an authoring change to the tool. **Confidence 0.9:** docstring
presence is unambiguous; the small gap is that a tool registered with an explicit
`description=` but no docstring may still be flagged by the docstring-only
predicate — a possible false positive the number accounts for.

### AG2-008 — Tool parameters are not type-annotated (Severity: medium, Confidence: 0.85, Fix type: code)

**What we detect:** a registered tool function that has parameters but no type
annotations on any of them (predicates `has_params` + `not has_typed_params`).

**Why it is flaggable:** AutoGen builds the argument schema from the type hints;
without them the model gets no shape guidance and emits wrongly-typed arguments
that fail validation.

**Real-world consequence:** a `book_meeting(start, attendees)` tool with untyped
params lets the model pass `start="next tuesdayish"`; the SDK rejects it, the call
retries, and turns are wasted before it succeeds — or it silently coerces to the
wrong value.

**Why severity is medium and not low:** unlike a missing description, a
mis-shaped argument can reach the executor with the wrong value and cause an
incorrect action, not just a skipped call — so the impact exceeds AG2-007. **Fix
type — code:** annotating parameters is a source edit. **Confidence 0.85:** the
rule fires only when *no* parameter is typed, so a partially-typed tool is a false
negative, and `typing.Annotated` descriptions count as types so they correctly
suppress.

---

## What this policy does not cover

- A tool registered with an explicit `description=` argument satisfies the *intent*
  of AG2-007, but the docstring-only predicate may still fire — verify the
  description is set rather than only adding a docstring.
- A *partially* typed tool (some parameters annotated, some not) does not fire —
  AG2-008 requires that no parameter carries a type.
- The *quality* of a docstring or a type: a one-word docstring or a bare `dict`
  annotation satisfies the rules but barely helps the model.
- Whether the schema the model sees actually matches the tool's real behavior — a
  misleading-but-present docstring passes.

---

## Recommendations beyond the fix

```python
from typing import Annotated
from autogen import register_function

def book_meeting(
    start_iso: Annotated[str, "Start time, ISO 8601, e.g. 2026-01-02T15:00:00Z"],
    attendees: Annotated[list[str], "Attendee email addresses"],
) -> str:
    """Book a meeting and return the calendar event ID."""
    ...

register_function(
    book_meeting, caller=assistant, executor=executor,
    description="Book a meeting at a given time with a list of attendees.",
)
```

1. Give every tool a docstring written for the model — or pass an explicit
   `description=` at registration — stating what it does, its inputs, and its
   return value.
2. Annotate every parameter with a concrete type; `typing.Annotated[T, "desc"]`
   adds a per-parameter description AutoGen forwards to the model.
3. Use an `Enum` or `Literal` for closed-set arguments so the model cannot emit
   an out-of-range value.
4. Keep the description and the implementation in sync — an overstated docstring
   is its own correctness hazard.
