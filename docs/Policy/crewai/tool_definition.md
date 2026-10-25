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
  - id: CREW-010
    severity: low
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: CREW-011
    severity: low
    confidence: 0.8
    scope: tool
    fix_type: code
  - id: CREW-013
    severity: low
    confidence: 0.9
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: CrewAI Tool Definition Hygiene

**Policy ID:** `crewai_tool_definition`  
**File:** `crewai/tool_definition.yaml`  
**Rules:** CREW-001, CREW-002, CREW-010, CREW-011, CREW-013  
**Severities:** low, medium, low, low, low  
**Fix types:** code, code, code, code, code  
**References:** LLM06 (Excessive Agency)

---

## What this policy covers

Authoring hygiene for CrewAI tools defined with the `@tool` decorator from
`crewai.tools`. **CREW-001** fires when the decorated function has no docstring
(predicate `has_docstring: false`). **CREW-002** fires when the function takes
parameters but none carry type annotations (predicates `has_params: true` AND
`has_typed_params: false`). **CREW-010** and **CREW-011** check what a present
docstring says: CREW-010 fires when it matches one of six listed markers
(predicate `has_description_text`), and CREW-011 when it is under 40
characters (predicates `has_docstring: true` AND `description_length_lt: 40`).
**CREW-013** fires when the tool name is one of ten listed names (`process`,
`handle`, `run`, …) via predicate `name_in`. All five read what CrewAI turns
into what the model sees: the name, the docstring as the description, and the
type hints as the argument schema.

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

A docstring can pass CREW-001 and still carry no real content. CrewAI puts
the tool description in front of the agent as its basis for choosing between
the tools it holds, so a stub like "TODO: describe this tool" is functionally
indistinguishable from no description at all. The name sits directly beside
the description in what the model sees. In a crew that runs its tasks in
sequence, the consequence of a wrong pick travels: the task output it produces
is threaded forward as context to the tasks behind it, so one undescribed tool
degrades work the agent that owns it never touches. With
[CREW-104](agent_safety.md) delegation, peers can reach the tool on the
strength of the same description and name. CREW-010, CREW-011 and CREW-013
cover these gaps; all three rely on this mechanism.

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

### CREW-010 — CrewAI tool description is a placeholder (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:** a `@tool` function whose docstring matches one of six
listed markers (`todo`, `tbd`, `fixme`, `placeholder`, `no description`,
`does stuff`) via predicate `has_description_text`. The docstring passes
CREW-001's has-a-description check; this rule looks at what it says.

**Why it is flaggable:** the mechanism is the one stated
[above](#why-definition-quality-is-a-distinct-concern-in-crewai-tools): a
placeholder is functionally indistinguishable from no description at all.

**Real-world consequence:** a tool whose docstring is "TODO: describe this
tool" reaches the agent with no account of what it does. In a crew that runs
its tasks in sequence, if the agent picks the wrong tool, the task output it
produces is threaded forward as context to the tasks behind it. A peer that
reaches the tool through [CREW-104](agent_safety.md) delegation chooses it on
the same placeholder.

**Why severity is low:** the pack sets low, the same as CREW-001. The
explanation puts a placeholder in the same state as no description at all,
which is the state CREW-001 covers. **Fix type — code:** replace the
placeholder with a real description covering what the tool does, what it
returns, and when the agent should reach for it rather than a neighboring
tool. That is an edit to the tool's docstring. **Confidence 0.85:** the pack
sets 0.85 for this rule and states no false positives, false negatives, or
other limits for it.

### CREW-011 — CrewAI tool description is too short to guide agent selection (Severity: low, Confidence: 0.8, Fix type: code)

**What we detect:** a `@tool` function that has a docstring
(`has_docstring: true`) whose description is under 40 characters
(`description_length_lt: 40`), both under `all:`. Because CREW-001 matches
`has_docstring: false`, the two rules do not fire on the same tool.

**Why it is flaggable:** the mechanism is the one stated
[above](#why-definition-quality-is-a-distinct-concern-in-crewai-tools). The
rule treats a description under 40 characters as too short to convey what a
tool does, what it returns, and when to call it rather than a similarly named
neighbor. A stub like "Gets data." leaves scope and preconditions to
guesswork.

**Real-world consequence:** a tool described as "Gets data." sits beside a
similarly named neighbor. Each mis-selected call spends one of the agent's
[CREW-110](agent_safety.md) `max_iter` steps, so an agent can hit its
iteration cap and hand the next task a half-finished result rather than an
answer.

**Why severity is low:** the pack sets low, the same as CREW-001 and CREW-010.
The cost the explanation names is guesswork at selection time and `max_iter`
steps spent on mis-selected calls. **Fix type — code:** expand the
description to at least a full sentence covering inputs, outputs, and the
situation in which this tool should be used over the alternatives.
**Confidence 0.8:** the pack sets 0.8 for this rule and states no false
positives, false negatives, or other limits for it.

### CREW-013 — Ambiguous CrewAI tool name (Severity: low, Confidence: 0.9, Fix type: code)

**What we detect:** a tool whose name is one of ten listed names (`process`,
`handle`, `run`, `do`, `execute`, `perform`, `work`, `go`, `thing`, `stuff`)
via predicate `name_in`.

**Why it is flaggable:** the mechanism is the one stated
[above](#why-definition-quality-is-a-distinct-concern-in-crewai-tools). A
generic verb says nothing about what the tool acts on, and the name sits
directly beside the description in what the model sees.

**Real-world consequence:** a tool named `process` can be called for the
wrong job or passed over entirely. In a crew that runs its tasks in sequence,
a wrong pick does not stay local: the task output it produces is threaded
forward as context to the tasks behind it, and peers reaching the tool through
[CREW-104](agent_safety.md) delegation select from the same name.

**Why severity is low:** the pack sets low and states no reasoning for it.
**Fix type — code:** rename to a verb-object form that names the thing acted
on (`summarize_invoice`, `refund_charge`, `fetch_order_status`). Keep the
description for the detail and let the name carry the subject. Renaming is an
edit to the tool source. **Confidence 0.9:** the pack sets 0.9 for this rule
and states no false positives, false negatives, or other limits for it.

---

## What this policy does not cover

- A *partially* typed tool (some parameters annotated, some not) does not fire —
  CREW-002 requires that no parameter carries a type.
- The *quality* of a type: an overly broad `dict` annotation satisfies CREW-002
  but barely helps the model.
- Description quality beyond the two checks: CREW-010 matches the six listed
  markers only, so a placeholder worded any other way is not matched, and a
  description of 40 characters or more passes CREW-011 whatever it says. The
  pack states no other limits for either rule.
- Name quality beyond the list: CREW-013 matches the ten listed names only, so
  a generic name not on the list is not matched. The pack states no other
  limits for it.
- Tools whose description is supplied through a mechanism other than the
  function docstring.
- Whether the schema the model sees actually matches the tool's real behavior —
  a misleading description of 40 characters or more with no listed marker
  passes.

---

## Recommendations beyond the fix

```python
from crewai.tools import tool

@tool("create_invoice")
def create_invoice(amount_cents: int, customer_id: str) -> str:
    """Create a draft invoice for a customer account.

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
5. Say in the docstring when the agent should reach for the tool rather than a
   neighboring tool, not only what it does.
6. Name the tool in verb-object form (`create_invoice`, not `process` /
   `handle`) so the name carries the subject and the description carries the
   detail.
