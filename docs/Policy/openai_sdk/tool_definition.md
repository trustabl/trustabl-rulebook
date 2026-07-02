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
    confidence: 0.5
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: Tool Definition Hygiene

**Policy ID:** `openai_sdk_tool_definition`  
**File:** `openai_sdk/tool_definition.yaml`  
**Rules:** OAI-001, OAI-002, OAI-007, OAI-022, OAI-025  
**Severities:** low, medium, low, low, low  
**Fix types:** code, code, code, code, code  
**References:** LLM06

> **Read [claude_sdk/tool_definition.md](../claude_sdk/tool_definition.md) for the full threat model.**
> This document covers OpenAI Agents SDK–specific differences only.

---

## What this policy covers

OpenAI Agents SDK `@function_tool`-decorated functions whose model-facing
interface is underspecified: OAI-001 fires on a missing docstring
(`has_docstring: false`), OAI-002 on no type-annotated parameters
(`has_typed_params: false`), OAI-007 on a vague name (`name_in`). Same predicates
and same routing rationale as the Claude tool-definition policy. OAI-025 is the
odd one out: it flags a tool that is *dead* — defined but referenced nowhere in
the repo — using the engine's call-graph liveness signal rather than the tool's
model-facing interface.

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

### OAI-025 — Tool is defined but never referenced anywhere in the repo (Severity: low, Confidence: 0.5, Fix type: code)

**What we detect:**
A Python `@function_tool` whose call-graph liveness state is `unreachable`
(`reachability_is: [unreachable]`, schema v13). The engine builds an intra-repo
Python call graph (name-based, cross-file) after discovery and stamps each
Python tool's `Reachability`. `unreachable` is asserted only when the tool's
name appears **nowhere** in the repo outside its own definition — not in any
`Agent(tools=[...])` list, not in a handoff, not at any call site. A tool passed
anywhere as a value is `unknown`, and a tool with no signal at all (TypeScript,
or no call graph built) matches nothing — the rule structurally cannot fire on
code the analysis did not classify.

**Why it is flaggable:**
A decorated-but-unwired tool is dead capability code. It is not exposed to any
model today, but it carries tool-grade capability (network, filesystem, whatever
its body does) and sits outside the reviewed agent surface — one refactor that
appends it to a `tools=[...]` list ships it to the model with whatever drift it
accumulated while dead. Dead definitions also misdirect audit effort: reviewers
harden code no agent can call while believing coverage is complete.

**Real-world consequence:**
A repo migrates its email tool to a new implementation but leaves the old
`@function_tool send_email_v1` in place. Months later a refactor wires the stale
v1 (no allowlist, no rate limit) back into an agent. The capability was never
re-reviewed because it "was always there."

**Why severity is low and not medium:**
The tool is, by definition, not reachable by any model today — there is no
present-tense exploit path. The finding is preventive hygiene (attack-surface
minimization and drift control), not an active exposure.

**Fix type — code:**
Delete the definition or wire it into the intended agent deliberately; both are
tool-source edits.

**Confidence 0.5:**
Deliberately the lowest in the pack — this is the first rule gated on the
call-graph analysis. The liveness pass is name-based: dynamic dispatch through
`getattr`, string-keyed registries, or re-exports via `__all__` manipulation
reference a tool without its identifier appearing, so a live tool can be
misclassified as dead. The conservative design (any name occurrence ⇒ not
unreachable) bounds the false-positive surface to string-only dispatch patterns,
but until the analysis earns corpus history beyond the current zero-false-fire
sweep, 0.5 states that uncertainty honestly. Raise only with evidence.

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
