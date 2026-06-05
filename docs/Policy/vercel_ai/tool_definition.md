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
references: [LLM06]
---

# Policy Rationale: Vercel AI SDK Tool Definition Hygiene

**Policy ID:** `vercel_ai_tool_definition`  
**File:** `vercel_ai/tool_definition.yaml`  
**Rules:** VAI-004, VAI-005  
**Severities:** low, medium  
**Fix types:** code, code  
**References:** LLM06 (Excessive Agency)

---

## What this policy covers

Authoring hygiene for Vercel AI SDK tools built with `tool({...})` /
`dynamicTool({...})` from the `ai` package. **VAI-004** fires when the tool has no
`description` (predicate `has_docstring: false` over the description field).
**VAI-005** fires when the tool takes input but imposes no field types — it uses
`dynamicTool` (whose input is always `unknown`) or an open schema (`z.any()`,
`z.unknown()`, or an empty `z.object({})`) — predicates `has_params: true` AND
`has_typed_params: false`. The `description` is the only model-visible account of
the tool (the SDK has no docstring fallback), and the `inputSchema` is what the SDK
turns into the model's argument schema.

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

---

## What this policy does not cover

- The *quality* of a `description` or a schema: a one-word description or a
  `z.record(z.string(), z.any())` satisfies the rules but barely constrains the
  model.
- Whether `execute()` actually validates an `unknown` input from a `dynamicTool`.
  A `dynamicTool` that validates internally still fires (a deliberate false
  positive) — the rule cannot see the in-handler guard.
- Tool *naming*: a Vercel tool is keyed by its position in the agent's `tools`
  record rather than a function name, so name-based heuristics (e.g. the mutation
  prefix idempotency check that exists for Python SDKs) do not apply here — Vercel
  ships no name-based rule, which is a deliberate coverage gap.
- TypeScript only: a tool defined in plain `.js` may not be analyzed with the same
  fidelity as a typed `.ts` definition.
- Whether the schema matches the tool's real behavior — a misleading-but-present
  description and a plausible-but-wrong schema both pass.

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
