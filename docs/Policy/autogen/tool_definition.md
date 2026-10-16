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
  - id: AG2-016
    severity: low
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: AG2-017
    severity: low
    confidence: 0.8
    scope: tool
    fix_type: code
  - id: AG2-019
    severity: low
    confidence: 0.9
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: AutoGen Tool Definition Hygiene

**Policy ID:** `autogen_tool_definition`  
**File:** `autogen/tool_definition.yaml`  
**Rules:** AG2-007, AG2-008, AG2-016, AG2-017, AG2-019  
**Severities:** low, medium, low, low, low  
**Fix types:** code, code, code, code, code  
**References:** LLM06 (Excessive Agency)

---

## What this policy covers

Authoring hygiene for AutoGen tools registered via `register_function` or the
`register_for_llm` / `register_for_execution` decorators. **AG2-007** fires when
the registered function has no docstring (predicate `has_docstring: false`).
**AG2-008** fires when the function takes parameters but none carry type
annotations (predicates `has_params: true` AND `has_typed_params: false`).
**AG2-016** and **AG2-017** check what a present docstring says: AG2-016 fires
when it matches one of six listed markers (predicate `has_description_text`),
and AG2-017 when it is under 40 characters (predicates `has_docstring: true`
AND `description_length_lt: 40`). **AG2-019** fires when the tool name is one of
ten listed names (`process`, `handle`, `run`, …) via predicate `name_in`.
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

A docstring can pass AG2-007 and still carry no real content. AutoGen advertises
the tool to the assistant through this text, so a stub like "TODO: describe this
tool" is functionally indistinguishable from no description at all, and the
assistant has to guess from the function name. The name sits directly beside the
description in what the model sees, so it is part of the selection signal. A
wrong pick costs a full round of the conversation: the assistant proposes, the
executor runs, and the result comes back without answering the assistant's
intent. Rounds spent this way come out of the budget that a group chat's
`max_round` ([AG2-004](agent_safety.md)) or the executor's auto-reply cap
([AG2-006](agent_safety.md)) sets, on a selection problem no error message
points at. AG2-016, AG2-017 and AG2-019 cover these gaps; all three rely on this
mechanism.

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

### AG2-016 — AutoGen tool description is a placeholder (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:** a registered tool whose docstring matches one of six listed
markers — `todo`, `tbd`, `fixme`, `placeholder`, `no description`,
`does stuff` — predicate `has_description_text`. The docstring passes AG2-007's
has-a-description check; this rule looks at what it says.

**Why it is flaggable:** the mechanism is the one stated
[above](#why-definition-quality-is-a-distinct-concern-in-autogen-tools): a
placeholder is functionally indistinguishable from no description at all, so
the assistant has to guess from the function name.

**Real-world consequence:** a tool whose docstring is "TODO: describe this
tool" reaches the assistant with no account of what it does. A wrongly chosen
tool returns something that does not answer the assistant's intent. If the
assistant reads that as an inconclusive step and proposes another call, the
pair trades rounds until AG2-004's `max_round` or AG2-006's auto-reply cap ends
the chat.

**Why severity is low:** the pack sets low, the same as AG2-007. The
explanation puts a placeholder in the same state as no description at all,
which is the state AG2-007 covers. **Fix type — code:** replace the placeholder
with a real description covering what the tool does, what it returns, and when
the assistant should call it rather than a neighboring tool. Passing an
explicit `description=` to `register_for_llm` overrides the docstring, and the
pack calls it the clearer place to say it. Either way the edit is to the tool
source. **Confidence 0.85:** the pack sets 0.85 for this rule and states no
false positives, false negatives, or other limits for it.

### AG2-017 — AutoGen tool description is too short to guide model selection (Severity: low, Confidence: 0.8, Fix type: code)

**What we detect:** a registered tool that has a docstring
(`has_docstring: true`) whose description is under 40 characters
(`description_length_lt: 40`), both under `all:`. Because AG2-007 matches
`has_docstring: false`, the two rules do not fire on the same tool.

**Why it is flaggable:** the mechanism is the one stated
[above](#why-definition-quality-is-a-distinct-concern-in-autogen-tools). The
rule treats a description under 40 characters as too short to convey what a
tool does, what it returns, and when to call it rather than a similarly named
neighbor. A stub like "Gets data." leaves scope and preconditions to guesswork.

**Real-world consequence:** a tool described as "Gets data." sits beside a
similarly named neighbor. Each mis-selected call costs a full round of the
conversation — the assistant proposes, the executor runs, the result comes back
unhelpful — so the thin description spends the round budget (a group chat's
`max_round` or the executor's auto-reply cap) rather than the run producing an
answer.

**Why severity is low:** the pack sets low, the same as AG2-007 and AG2-016.
The cost the explanation names is rounds spent on mis-selected calls. **Fix
type — code:** expand the description to at least a full sentence covering
inputs, outputs, and the situation in which this tool should be used over the
alternatives, either in the docstring or via `register_for_llm`'s
`description=` argument. **Confidence 0.8:** the pack sets 0.8 for this rule
and states no false positives, false negatives, or other limits for it.

### AG2-019 — Ambiguous AutoGen tool name (Severity: low, Confidence: 0.9, Fix type: code)

**What we detect:** a tool whose name is one of ten listed names — `process`,
`handle`, `run`, `do`, `execute`, `perform`, `work`, `go`, `thing`, `stuff` —
predicate `name_in`.

**Why it is flaggable:** the mechanism is the one stated
[above](#why-definition-quality-is-a-distinct-concern-in-autogen-tools). A
generic verb says nothing about what the tool acts on, so a name like `process`
or `handle` spends its part of the selection signal on nothing.

**Real-world consequence:** a tool named `process` is either called for the
wrong job or passed over entirely. Each wrong pick costs a full round of the
conversation — propose, execute, reply — so the ambiguous name spends the round
budget (a group chat's `max_round` or the executor's auto-reply cap) rather than
the chat reaching an answer.

**Why severity is low:** the pack sets low and states no reasoning for it. The
consequence the explanation names is a tool called for the wrong job or passed
over, and rounds spent on it. **Fix type — code:** rename to a verb-object form
that names the thing acted on (`summarize_invoice`, `refund_charge`,
`fetch_order_status`). Keep the description for the detail and let the name
carry the subject. Renaming is an edit to the tool source. **Confidence 0.9:**
the pack sets 0.9 for this rule and states no false positives, false negatives,
or other limits for it.

---

## What this policy does not cover

- A tool registered with an explicit `description=` argument satisfies the *intent*
  of AG2-007, but the docstring-only predicate may still fire — verify the
  description is set rather than only adding a docstring.
- A *partially* typed tool (some parameters annotated, some not) does not fire —
  AG2-008 requires that no parameter carries a type.
- The *quality* of a type: a bare `dict` annotation satisfies AG2-008 but barely
  helps the model.
- Description quality beyond the two checks: AG2-016 matches the six listed
  markers only, so a placeholder worded any other way is not matched, and a
  docstring of 40 characters or more passes AG2-017 whatever it says. The pack
  states no other limits for either rule.
- Name quality beyond the list: AG2-019 matches the ten listed names only, so a
  generic name not on the list is not matched. The pack states no other limits
  for it.
- Whether the schema the model sees actually matches the tool's real behavior — a
  misleading docstring of 40 characters or more with no listed marker passes.

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
5. Say in the docstring or `description=` when the assistant should call the
   tool rather than a neighboring tool, not only what it does.
6. Name the tool in verb-object form (`book_meeting`, not `process` /
   `handle`) so the name carries the subject and the description carries the
   detail.
