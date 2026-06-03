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
references: [LLM06]
---

# Policy Rationale: Tool Definition Hygiene

**Policy ID:** `openai_sdk_tool_definition`  
**File:** `openai_sdk/tool_definition.yaml`  
**Rules:** OAI-001, OAI-002, OAI-007, OAI-022  
**Severities:** low, medium, low, low  
**Fix types:** code, code, code, code  
**References:** LLM06

> **Read [claude_sdk/tool_definition.md](../claude_sdk/tool_definition.md) for the full threat model.**
> This document covers OpenAI Agents SDK–specific differences only.

---

## What this policy covers

OpenAI Agents SDK `@function_tool`-decorated functions whose model-facing
interface is underspecified: OAI-001 fires on a missing docstring
(`has_docstring: false`), OAI-002 on no type-annotated parameters
(`has_typed_params: false`), OAI-007 on a vague name (`name_in`). Same predicates
and same routing rationale as the Claude tool-definition policy.

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

---

## What this policy does not cover

Same gaps as [claude_sdk/tool_definition.md](../claude_sdk/tool_definition.md#what-this-policy-does-not-cover):
present-but-misleading descriptions, present-but-too-loose types (`x: Any`),
overlapping tool purposes, and descriptions supplied via decorator kwargs. For
OAI-022 specifically: a TypeScript `description` assembled from a non-literal
expression is real text the model reads, but the literal-only capture records it as
empty and fires anyway.

---

## Recommendations beyond the fix

The safe pattern — a router-oriented docstring, narrow parameter types, and
distinct verb-noun names — is in
[claude_sdk/tool_definition.md](../claude_sdk/tool_definition.md#recommendations-beyond-the-fix).
For the OpenAI SDK, keep `strict_mode` at its default `True` (see OAI-003) so the
type hints you add are actually enforced at runtime.
