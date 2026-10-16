---
policy_id: langchain_tool_definition
category: langchain
topic: tool_definition
rules:
  - id: LC-001
    severity: low
    confidence: 0.8
    scope: tool
    fix_type: code
  - id: LC-002
    severity: medium
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: LC-010
    severity: low
    confidence: 0.8
    scope: tool
    fix_type: code
  - id: LC-018
    severity: low
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: LC-019
    severity: low
    confidence: 0.8
    scope: tool
    fix_type: code
  - id: LC-021
    severity: low
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: LC-022
    severity: low
    confidence: 0.8
    scope: tool
    fix_type: code
  - id: LC-024
    severity: low
    confidence: 0.9
    scope: tool
    fix_type: code
references: [LLM06, LLM09]
---

# Policy Rationale: LangChain Tool Definition Hygiene

**Policy ID:** `langchain_tool_definition`
**File:** `langchain/tool_definition.yaml`
**Rules:** LC-001, LC-002, LC-010, LC-018, LC-019, LC-021, LC-022, LC-024
**Severities:** low, medium, low, low, low, low, low, low
**Fix types:** code, code, code, code, code, code, code, code
**References:** LLM06 (Excessive Agency), LLM09 (Misinformation)

---

## What this policy covers

The metadata a model relies on to call a LangChain tool correctly: its
**description** and its **parameter schema**, and, for LC-024, its **name**.
LangChain surfaces the description and the schema to the
model verbatim — the description as the tool's purpose, the schema (Pydantic
`args_schema` or the wrapped function's type hints; in TS the Zod/JSON `schema`)
as the argument contract. When either is missing, the model is choosing and
populating tool calls blind.

Discovery recognizes the `@tool` decorator and the `StructuredTool` / `Tool`
factories (Python), and the `tool()` factory plus `DynamicStructuredTool` /
`DynamicTool` (TypeScript). The `@tool` decorator is shared with the Claude Agent
SDK; Trustabl disambiguates by import, so a langchain-importing file routes `@tool`
to this pack and a Claude-SDK file does not.

LC-018, LC-019, LC-021 and LC-022 check what a present description says.
LC-018 (Python) and LC-021 (TypeScript) fire when the description matches one
of six listed markers (predicate `has_description_text`). LC-019 (Python) and
LC-022 (TypeScript) fire when it is under 40 characters (predicates
`has_docstring: true` AND `description_length_lt: 40`). LC-024 fires when a
Python tool's name is one of ten listed names (`process`, `handle`, `run`, …)
via predicate `name_in`.

---

## Why tool metadata is a reliability and safety concern

A tool the model cannot understand is a tool it calls at the wrong time, with the
wrong arguments, or not at all (LLM09 — the model acts on a wrong understanding of
what the tool does). In an agent loop that compounds: a mis-called tool returns an
error or a wrong result, the model re-plans on bad information, and the loop
either fails or takes an unintended action (LLM06). Description and schema quality
is the cheapest, highest-leverage lever on agent reliability.

A description can pass LC-001 or LC-010 and still carry no real content. A
Python tool takes its description from the docstring unless `description=` is
passed; a LangChain.js tool takes it from the `description` field of its
config. The pack's explanation of LC-018 says a stub such as "TODO: describe
this tool" is functionally indistinguishable from no description at all, so the
model has to guess from the function name. The pack's explanation of LC-024
says the name sits directly beside the description in what the model sees, and
that a name like `process` or `handle` says nothing about what the tool acts
on.

The pack's explanation of LC-018 says mis-selection shows up as wrong answers
and wasted executor iterations rather than as an error anyone can trace back to
the docstring. The explanations of LC-019 and LC-024 (Python)
and LC-021 and LC-022 (TypeScript) say each mis-selected call consumes an
iteration against the `AgentExecutor`'s iteration limit: `max_iterations`,
which [LC-102](agent_safety.md) checks, and `maxIterations`, which
[LC-111](agent_safety.md) checks. These sentences are about `AgentExecutor`, as
the pack's rules are written; this document makes no claim about other agent
constructors. LC-018, LC-019, LC-021, LC-022 and LC-024 rely on this mechanism.

---

## Rule-by-rule defense

### LC-001 — Tool has no description (Severity: low, Confidence: 0.8, Fix type: code)

**What we detect:** a discovered Python LangChain tool whose `ToolDef.Description`
is empty — no `@tool` docstring, no `StructuredTool` `description=`. Predicate
`has_docstring: false`.

**Why it is flaggable:** LangChain defaults a tool's description to the wrapped
function's docstring. With none, the model sees only a bare name. This is the
single highest-leverage authoring fix for tool reliability.

**Real-world consequence:** a tool named `search` with no description is invoked
for the wrong queries, or skipped in favor of a better-described peer; the model
has no basis to choose.

**Severity low:** a missing description degrades reliability but is not itself a
security defect. **Confidence 0.8:** a tool may legitimately be self-describing by
name in trivial cases, so a small false-positive rate is expected.

### LC-002 — Tool parameters are not type-annotated (Severity: medium, Confidence: 0.85, Fix type: code)

**What we detect:** a Python LangChain tool that has parameters but none are
type-annotated and no `args_schema` is supplied. Predicate `all: [has_params:
true, has_typed_params: false]` — gated on `has_params` so a zero-argument tool
does not fire.

**Why it is flaggable:** LangChain derives the argument JSON schema from type hints
(or an `args_schema` model). Untyped parameters produce an underspecified schema;
the model passes wrong-typed arguments that LangChain rejects at validation time —
a silent per-call failure tax.

**Severity medium:** a step above missing description because it breaks tool calls
mechanically, not just stylistically. **Confidence 0.85:** the few false positives
are tools that intend a single free-form string argument.

### LC-010 — TypeScript tool has no description (Severity: low, Confidence: 0.8, Fix type: code)

**What we detect:** a discovered TypeScript LangChain tool whose `description` field
is empty. Same `has_docstring: false` predicate, reading `ToolDef.Description`
populated from the `tool()` / `DynamicStructuredTool` config.

**Why it is flaggable:** LangChain.js takes the description as an explicit config
field with no docstring fallback, so omitting it is a silent gap rather than a
syntax error — the model gets no signal about the tool's purpose.

**Severity low / Confidence 0.8:** same profile as LC-001.

### LC-018 — LangChain tool description is a placeholder (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:** a Python LangChain tool whose description matches one of
six listed markers — `todo`, `tbd`, `fixme`, `placeholder`, `no description`,
`does stuff` — predicate `has_description_text`. The pack's explanation says
the docstring passes the LC-001 has-a-description check but carries a
placeholder marker instead of real content.

**Why it is flaggable:** the mechanism is the one stated
[above](#why-tool-metadata-is-a-reliability-and-safety-concern). The pack's
explanation says a placeholder is functionally indistinguishable from no
description at all, so the model has to guess from the function name.

**Real-world consequence:** if a tool's docstring is "TODO: describe this
tool", the pack's explanation says the model has to guess from the function
name, and a wrong pick can surface as a wrong answer or a wasted executor
iteration rather than as an error that traces back to the docstring.

**Why severity is low:** the pack sets low and states no reasoning for it. The
costs the explanation names are wrong answers and wasted executor iterations.

**Fix type — code:** replace the placeholder with a real description covering
what the tool does, what it returns, and when the model should call it rather
than a neighboring tool. Where the name alone is genuinely ambiguous, pass an
explicit `description=` to the `@tool` decorator instead of relying on the
docstring.

**Confidence 0.85:** the pack sets 0.85 for this rule and names no
false-positive or false-negative scenarios for it.

### LC-019 — LangChain tool description is too short to guide model selection (Severity: low, Confidence: 0.8, Fix type: code)

**What we detect:** a Python LangChain tool that has a docstring
(`has_docstring: true`) whose description is under 40 characters
(`description_length_lt: 40`), both under `all:`. Because LC-001 matches
`has_docstring: false`, the two rules do not fire on the same tool.

**Why it is flaggable:** the mechanism is the one stated
[above](#why-tool-metadata-is-a-reliability-and-safety-concern). The pack's
explanation treats a description under 40 characters as too short to convey
what a tool does, what it returns, and when to call it rather than a similarly
named neighbor, and says a stub like "Gets data." leaves scope and
preconditions to guesswork.

**Real-world consequence:** if a tool described as "Gets data." sits beside a
similarly named neighbor, the pack's explanation says each mis-selected call
consumes an iteration against the `AgentExecutor`'s `max_iterations` budget
(LC-102), so a run can exhaust its steps. This is about `AgentExecutor`.

**Why severity is low:** the pack sets low and states no reasoning for it. The
costs the explanation names are guesswork about scope and preconditions, and
iterations spent on mis-selected calls.

**Fix type — code:** expand the description to at least a full sentence
covering inputs, outputs, and the situation in which this tool should be used
over the alternatives.

**Confidence 0.8:** the pack sets 0.8 for this rule and names no false-positive
or false-negative scenarios for it.

### LC-021 — TypeScript LangChain tool description is a placeholder (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:** the same six markers as LC-018 (`has_description_text`:
`todo`, `tbd`, `fixme`, `placeholder`, `no description`, `does stuff`), on a
TypeScript LangChain tool.

**Why it is flaggable:** the mechanism is the one stated
[above](#why-tool-metadata-is-a-reliability-and-safety-concern). The pack's
explanation says LangChain.js has no docstring to fall back on, so a
description of "TODO: describe this tool" leaves the model guessing from the
tool name, and that the Zod schema does not compensate: it constrains the shape
of the arguments once the model has chosen this tool, not whether choosing it
was right.

**Real-world consequence:** if a tool built with `tool()` has the description
"TODO: describe this tool" and sits beside other tools, the pack's explanation
says each wrong pick consumes an iteration against the `AgentExecutor`'s
`maxIterations` budget, so a run can exhaust its steps. This is about
`AgentExecutor`.

**Why severity is low:** the pack sets low and states no reasoning for it. The
costs the explanation names are mis-selection and iterations spent on it.

**Fix type — code:** replace the placeholder with a real description covering
what the tool does, what it returns, and when the model should call it rather
than a neighboring tool. The pack's fix adds that the string goes to the model,
so it should be written for the model rather than a human maintainer.

**Confidence 0.85:** the pack sets 0.85 for this rule and names no
false-positive or false-negative scenarios for it.

### LC-022 — TypeScript LangChain tool description is too short to guide model selection (Severity: low, Confidence: 0.8, Fix type: code)

**What we detect:** the same predicates as LC-019 (`has_docstring: true` and
`description_length_lt: 40`, both under `all:`), on a TypeScript LangChain
tool. Because LC-010 matches `has_docstring: false`, the two rules do not fire
on the same tool.

**Why it is flaggable:** the mechanism is the one stated
[above](#why-tool-metadata-is-a-reliability-and-safety-concern). The pack's
explanation treats a description under 40 characters as too short to convey
what a tool does, what it returns, and when to call it rather than a similarly
named neighbor, and says that with no docstring fallback in LangChain.js a stub
like "Gets data." leaves scope and preconditions to guesswork.

**Real-world consequence:** if a tool described as "Gets data." sits beside a
similarly named neighbor, the pack's explanation says each mis-selected call
spends an iteration against the `maxIterations` bound that LC-111 checks. This
is about `AgentExecutor`.

**Why severity is low:** the pack sets low and states no reasoning for it. The
costs the explanation names are guesswork about scope and preconditions, and
iterations spent on mis-selected calls.

**Fix type — code:** expand the description to at least a full sentence
covering inputs, outputs, and the situation in which this tool should be used
over the alternatives. Where two tools are easy to confuse, say in each which
one the other case belongs to.

**Confidence 0.8:** the pack sets 0.8 for this rule and names no false-positive
or false-negative scenarios for it.

### LC-024 — Ambiguous LangChain tool name (Severity: low, Confidence: 0.9, Fix type: code)

**What we detect:** a Python LangChain tool whose name is one of ten listed
names — `process`, `handle`, `run`, `do`, `execute`, `perform`, `work`, `go`,
`thing`, `stuff` — predicate `name_in`.

**Why it is flaggable:** the mechanism is the one stated
[above](#why-tool-metadata-is-a-reliability-and-safety-concern). The pack's
explanation says the name is a generic verb that says nothing about what the
tool acts on.

**Real-world consequence:** if a function named `process` is decorated with
`@tool`, the tool's name is `process`. The pack's explanation says the model can
call it for the wrong job or pass over it, and that each wrong pick spends an
iteration against the `AgentExecutor`'s `max_iterations` budget (LC-102). This
is about `AgentExecutor`.

**Why severity is low:** the pack sets low and states no reasoning for it. The
costs the explanation names are a tool called for the wrong job or passed over,
and iterations spent on wrong picks.

**Fix type — code:** rename to a verb-object form that names the thing acted
on (`summarize_invoice`, `refund_charge`, `fetch_order_status`). Keep the
description for the detail and let the name carry the subject.

**Confidence 0.9:** the pack sets 0.9 for this rule and names no false-positive
or false-negative scenarios for it.

---

## What this policy does not cover

The *quality* of a present description beyond the checks in LC-018, LC-019,
LC-021 and LC-022, descriptions assembled at runtime, and class-based tools
(`class X(BaseTool)` / `extends StructuredTool`), which are a documented discovery
gap. Argument typing via runtime validators other than Pydantic/Zod is not
recognized.

- **Placeholder wording.** LC-018 and LC-021 match the six listed markers, so a
  placeholder worded any other way is not matched.
- **Length.** A description of 40 characters or more passes LC-019 and LC-022
  whatever it says.
- **Names.** LC-024 matches the ten listed names, so a generic name not on the
  list is not matched. LC-024 is declared for `language: python`, and this
  policy file has no TypeScript name rule.
- The pack states no other limits for LC-018, LC-019, LC-021, LC-022 or LC-024.

---

## Recommendations beyond the fix

Write the description for the model: one sentence naming what the tool does, the
inputs it expects, and what it returns. Annotate every parameter with a concrete
type or an `args_schema` Pydantic model (Zod schema in TS). Treat both as part of
the tool's public contract, reviewed like any API surface.

```python
from langchain_core.tools import tool

ORDER_STATUS: dict[str, str] = {}


@tool
def fetch_order_status(order_id: str) -> str:
    """Return the shipping status of one order, given its ID such as "ord_1042".

    Use this when the user asks where a specific order is. For a customer's
    full order history, use list_customer_orders instead.
    """
    return ORDER_STATUS.get(order_id, f"No order {order_id}.")
```

The TypeScript form, where the description is a field in the `tool()` config:

```typescript
import { tool } from "@langchain/core/tools";
import { z } from "zod";

const ORDER_STATUS: Record<string, string> = {};

export const fetchOrderStatus = tool(
  async ({ orderId }) => ORDER_STATUS[orderId] ?? `No order ${orderId}.`,
  {
    name: "fetch_order_status",
    description: "Return the shipping status of one order, given its ID such as ord_1042. Use this when the user asks where a specific order is; for a customer's full order history, use list_customer_orders instead.",
    schema: z.object({ orderId: z.string().describe("The order ID, e.g. ord_1042.") }),
  },
);
```

Say in the description when the model should call the tool rather than a
neighboring tool; where two tools are easy to confuse, say in each which one
the other case belongs to. Name the tool in verb-object form
(`fetch_order_status`, not `process` / `handle`) so the name carries the
subject and the description carries the detail.
