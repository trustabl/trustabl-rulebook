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
references: [LLM06, LLM09]
---

# Policy Rationale: LangChain Tool Definition Hygiene

**Policy ID:** `langchain_tool_definition`
**File:** `langchain/tool_definition.yaml`
**Rules:** LC-001, LC-002, LC-010
**Severities:** low, medium
**Fix types:** code
**References:** LLM06 (Excessive Agency), LLM09 (Misinformation)

---

## What this policy covers

The two pieces of metadata a model relies on to call a LangChain tool correctly:
its **description** and its **parameter schema**. LangChain surfaces both to the
model verbatim — the description as the tool's purpose, the schema (Pydantic
`args_schema` or the wrapped function's type hints; in TS the Zod/JSON `schema`)
as the argument contract. When either is missing, the model is choosing and
populating tool calls blind.

Discovery recognizes the `@tool` decorator and the `StructuredTool` / `Tool`
factories (Python), and the `tool()` factory plus `DynamicStructuredTool` /
`DynamicTool` (TypeScript). The `@tool` decorator is shared with the Claude Agent
SDK; Trustabl disambiguates by import, so a langchain-importing file routes `@tool`
to this pack and a Claude-SDK file does not.

---

## Why tool metadata is a reliability and safety concern

A tool the model cannot understand is a tool it calls at the wrong time, with the
wrong arguments, or not at all (LLM09 — the model acts on a wrong understanding of
what the tool does). In an agent loop that compounds: a mis-called tool returns an
error or a wrong result, the model re-plans on bad information, and the loop
either fails or takes an unintended action (LLM06). Description and schema quality
is the cheapest, highest-leverage lever on agent reliability.

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

---

## What this policy does not cover

The *quality* of a present description (a one-word description satisfies the
check), descriptions assembled at runtime, and class-based tools
(`class X(BaseTool)` / `extends StructuredTool`), which are a documented discovery
gap. Argument typing via runtime validators other than Pydantic/Zod is not
recognized.

---

## Recommendations beyond the fix

Write the description for the model: one sentence naming what the tool does, the
inputs it expects, and what it returns. Annotate every parameter with a concrete
type or an `args_schema` Pydantic model (Zod schema in TS). Treat both as part of
the tool's public contract, reviewed like any API surface.
