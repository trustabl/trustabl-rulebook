---
policy_id: vercel_ai_tool_definition
category: vercel_ai
topic: tool_definition
rules:
  - id: VAI-004
    severity: low
    confidence: 0.9
    scope: tool
    fix_type: code
  - id: VAI-005
    severity: medium
    confidence: 0.8
    scope: tool
    fix_type: code
  - id: VAI-013
    severity: low
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: VAI-014
    severity: low
    confidence: 0.8
    scope: tool
    fix_type: code
  - id: VAI-016
    severity: low
    confidence: 0.85
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: Vercel AI SDK Tool Definition Hygiene

**Policy ID:** `vercel_ai_tool_definition`  
**File:** `vercel_ai/tool_definition.yaml`  
**Rules:** VAI-004, VAI-005, VAI-013, VAI-014, VAI-016  
**Severities:** low, medium, low, low, low  
**Fix types:** code, code, code, code, code  
**References:** LLM06 (Excessive Agency)

---

## What this policy covers

Authoring hygiene for Vercel AI SDK tools built with `tool({...})` /
`dynamicTool({...})` from the `ai` package. **VAI-004** fires when the tool has no
`description` (predicate `has_docstring: false` over the description field).
**VAI-005** fires when the tool takes input but imposes no field types — it uses
`dynamicTool` (whose input is always `unknown`) or an open schema (`z.any()`,
`z.unknown()`, or an empty `z.object({})`) — predicates `has_params: true` AND
`has_typed_params: false`. **VAI-013** and **VAI-014** check what a present
`description` says: VAI-013 matches one of six listed markers
(`has_description_text`), and VAI-014 when it is under 40 characters
(`has_docstring: true` AND `description_length_lt: 40`). **VAI-016** fires
when the binding identifier (`VarName`) is an ambiguous name from the shared
pack list (`process`, `handle`, `run`, …) via `name_in` — Vercel leaves `ToolDef.Name` empty, so the engine
matches `VarName`. The `description` is the only model-visible account of the
tool (the SDK has no docstring fallback), the `inputSchema` is what the SDK
turns into the model's argument schema, and the binding name is what usually
becomes the agent's tools-record key.

---

## Why definition quality is a distinct concern in the Vercel AI SDK

The model selects which tool to call and what arguments to pass entirely from the
`description` and the `inputSchema` — it never sees the `execute()` implementation.
The Vercel AI SDK is stricter than Python frameworks here: there is **no docstring
fallback**, so a tool defined with no `description` (or an empty one) reaches the
model as a bare name with zero account of what it does. The model then skips the
tool or calls it blindly. Likewise, the SDK builds the argument schema from
`inputSchema`; a `dynamicTool` (input `unknown`) or an open schema gives the model
no field-shape guidance, so it emits wrongly-shaped arguments that the SDK rejects
at validation time — or, worse, forwards unchecked into `execute()`.

That last clause is why this policy references LLM06 rather than only the
output-handling concern: an untyped `inputSchema` does not merely cost reliability,
it widens the tool's input surface. If `execute()` consumes an `unknown` argument
without validating it, a model (or an injection) can pass a value the handler never
anticipated — a path, a URL, a command fragment — directly into the tool's logic.
Typing the input is the first guard that keeps a model-callable tool from being
fed arbitrary shapes.

Naming is the third leg: Vercel derives the model-facing tool name from the
agent's `tools: { key: binding }` record, not from a `name:` field on
`tool({...})`. Discovery therefore emits an empty `Name` and stores the binding
identifier as `VarName`. An ambiguous binding (`const process = tool(...)`) is
how authors commonly end up with a tools record keyed `process` — the same
routing failure CSDK-007 / OAI-007 catch on an explicit function name.

A `description` that is present is not the same as one that is useful. With no
docstring fallback, the string is the entire account of the tool in the prompt,
so a placeholder or a stub like "Gets data." is all the model has, and nothing
in the SDK reports that the description was a stub. VAI-013 and VAI-014 cover
that gap; both rely on this mechanism.

---

## Rule-by-rule defense

### VAI-004 — Tool has no description (Severity: low, Confidence: 0.9, Fix type: code)

**What we detect:** a `tool({...})` / `dynamicTool({...})` with no `description`
(or an empty one) — predicate `has_docstring` over the description field.

**Why it is flaggable:** the SDK passes `description` to the model verbatim and has
no docstring fallback; with none, the tool is a bare name the model cannot reason
about.

**Real-world consequence:** a `lookup` tool with no description is never selected
when the user asks a question it could answer, or is called with a nonsense
argument because the model is guessing at its purpose.

**Why severity is low and not medium:** it is a routing-quality defect with no
direct security impact, and the failure mode (a skipped or mis-called tool) is
visible and recoverable. **Fix type — code:** adding a `description` to the
`tool({...})` options is a tool-source edit. **Confidence 0.9:** presence of a
`description` is unambiguous; the small gap covers a description supplied through
an unusual indirection the predicate does not model.

### VAI-005 — Tool accepts untyped input (Severity: medium, Confidence: 0.8, Fix type: code)

**What we detect:** a tool that takes input but imposes no field types — a
`dynamicTool` (input `unknown`) or an open schema (`z.any()`, `z.unknown()`, empty
`z.object({})`) — predicates `has_params` + `not has_typed_params`.

**Why it is flaggable:** the SDK builds the model's argument schema from
`inputSchema`; an open schema gives no shape guidance, so the model emits
wrongly-typed arguments that fail validation or flow unchecked into `execute()`.

**Real-world consequence:** a `transferFunds` tool with `inputSchema:
z.object({})` (or `dynamicTool`) lets the model pass `{ amount: "all", to:
"../admin" }`; with no field types the SDK forwards it unchecked and the handler
acts on a shape it never validated.

**Why severity is medium and not low:** an untyped input is not just a reliability
tax — it widens the tool's attack surface, since unvalidated model-supplied values
reach `execute()` directly; that potential for a wrong-shaped value to cause a real
action lifts it above the description rule. **Fix type — code:** giving the tool a
concrete Zod object schema is a source edit. **Confidence 0.8:** the rule fires on
the open-schema shapes, so a `dynamicTool` that genuinely cannot be typed and
validates inside `execute()` is over-flagged, and a schema that is typed but still
loose (`z.record(z.any())`) may slip through as a false negative.

### VAI-013 — Vercel AI tool description is a placeholder (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:** a tool whose `description` matches one of six listed
markers — `todo`, `tbd`, `fixme`, `placeholder`, `no description`, `does stuff`
— predicate `has_description_text`. The tool sets a description, so it passes
VAI-004; this rule looks at what the description says.

**Why it is flaggable:** the mechanism is the one stated
[above](#why-definition-quality-is-a-distinct-concern-in-the-vercel-ai-sdk): the
description is the entire account of the tool in the prompt. A placeholder
leaves the tool in the state VAI-004 exists to prevent.

**Real-world consequence:** a tool whose description is "TODO: describe this
tool" is skipped, or called with the wrong arguments, and the only symptom is a
tool the model uses badly or not at all.

**Why severity is low:** the pack sets low, the same as VAI-004. The symptom the
explanation names is a skipped or mis-called tool.

**Fix type — code:** replace the placeholder in the `tool({...})` options with
a real description covering what the tool does, what it returns, and when the
model should call it rather than a neighboring tool. The SDK passes the string
to the model verbatim, so write it for the model rather than a human
maintainer.

**Confidence 0.85:** the pack sets 0.85 for this rule and states no false
positives, false negatives, or other limits for it.

### VAI-014 — Vercel AI tool description is too short to guide model selection (Severity: low, Confidence: 0.8, Fix type: code)

**What we detect:** a tool that has a `description` (`has_docstring: true`)
under 40 characters (`description_length_lt: 40`), both under `all:`. Because
VAI-004 matches `has_docstring: false`, the two rules do not fire on the same
tool.

**Why it is flaggable:** the mechanism is the one stated
[above](#why-definition-quality-is-a-distinct-concern-in-the-vercel-ai-sdk). The
rule treats a description under 40 characters as too short to convey what the
tool does, what it returns, and when to call it rather than a similarly named
neighbor. A stub like "Gets data." is the whole prompt-side account of the
tool, so scope and preconditions are left to guesswork.

**Real-world consequence:** a tool described as "Gets data." sits beside a
similarly named neighbor and the model picks between them on a guess. Each
mis-selected call also consumes a step against the [VAI-007](agent_safety.md)
tool-loop bound, so a thin description spends the loop budget instead of the
run producing an answer.

**Why severity is low:** the pack sets low, the same as VAI-004 and VAI-013.
The cost the explanation names is guesswork at selection time and loop steps
spent on mis-selected calls.

**Fix type — code:** expand the `description` to at least a full sentence
covering inputs, outputs, and the situation in which this tool should be used
over the alternatives. Where two tools are easy to confuse, say in each which
one the other case belongs to.

**Confidence 0.8:** the pack sets 0.8 for this rule and states no false
positives, false negatives, or other limits for it.

### VAI-016 — Ambiguous Vercel AI tool binding name (Severity: low, Confidence: 0.85, Fix type: code)

**What we detect:** a Vercel tool whose `VarName` (binding identifier) is in the
shared ambiguous-name list (`process`, `handle`, `run`, `do`, `execute`,
`perform`, `work`, `go`, `thing`, `stuff`) — predicate `name_in`, with the
engine falling back to `VarName` when `Name` is empty.

**Why it is flaggable:** the binding name is what authors usually promote to the
agent's tools-record key; a generic key gives the model no routing signal.

**Real-world consequence:** `const process = tool({...})` registered as
`tools: { process }` is called for every vague "handle this" request, or skipped
when a better-named sibling exists.

**Why severity is low and not medium:** same as CSDK-007 / OAI-007 — routing
quality, no direct exploit. **Fix type — code:** rename the binding (and the
record key). **Confidence 0.85:** slightly below the Python siblings because the
model-facing key can differ from `VarName` (`tools: { summarizeInvoice: t }`
escapes), and the list is a closed heuristic.

---

## What this policy does not cover

- The *quality* of a schema: a `z.record(z.string(), z.any())` satisfies the
  rules but barely constrains the model.
- Description quality beyond the two checks: VAI-013 matches the six listed
  markers only, so a placeholder worded any other way is not matched, and a
  description of 40 characters or more passes VAI-014 whatever it says. The
  pack states no other limits for either rule.
- Whether `execute()` actually validates an `unknown` input from a `dynamicTool`.
  A `dynamicTool` that validates internally still fires (a deliberate false
  positive) — the rule cannot see the in-handler guard.
- A descriptive binding registered under an ambiguous tools-record key
  (`tools: { process: fetchWeather }`) — discovery matches `VarName`, not the
  record key.
- TypeScript only: a tool defined in plain `.js` may not be analyzed with the same
  fidelity as a typed `.ts` definition.
- Whether the schema matches the tool's real behavior — a misleading
  description of 40 characters or more with no listed marker, and a
  plausible-but-wrong schema, both pass.

---

## Recommendations beyond the fix

```typescript
import { tool } from "ai";
import { z } from "zod";

export const transferFunds = tool({
  description:
    "Transfer an integer amount of cents from the user's account to a payee ID. " +
    "Amounts are in cents; the payee must be an existing saved payee.",
  inputSchema: z.object({
    amountCents: z.number().int().positive(),
    payeeId: z.string().regex(/^payee_[a-z0-9]+$/),
  }),
  execute: async ({ amountCents, payeeId }) => {
    // arguments arrive already validated against the schema
    ...
  },
});
```

1. Give every tool a `description` written for the model — there is no docstring
   fallback — stating what it does, its inputs, and its return value.
2. Give the tool a concrete Zod object schema in `inputSchema` with a typed field
   per argument; constrain values with `.int()`, `.positive()`, `.enum([...])`,
   `.regex(...)` rather than bare `z.string()`.
3. Reserve `dynamicTool` for the rare case where the input genuinely cannot be
   typed, and even then validate the shape inside `execute()` before using it.
4. Keep the description and the schema in sync with the handler's real behavior —
   an overstated description is its own correctness hazard.
5. Use a verb-object binding name (`transferFunds`, not `process` / `handle`) and
   register that same identifier as the agent's tools-record key.
6. Say in the description when the model should call the tool rather than a
   neighboring one; where two tools are easy to confuse, say in each which one
   the other case belongs to.
