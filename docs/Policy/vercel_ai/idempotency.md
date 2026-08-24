---
policy_id: vercel_ai_idempotency
category: vercel_ai
topic: idempotency
rules:
  - id: VAI-010
    severity: medium
    confidence: 0.5
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: Idempotency

**Policy ID:** `vercel_ai_idempotency`  
**File:** `vercel_ai/idempotency.yaml`  
**Rules:** VAI-010  
**Severities:** medium  
**Fix types:** code  
**References:** LLM06

> **Read [claude_sdk/idempotency.md](../claude_sdk/idempotency.md) for the full threat model.**
> This document covers Vercel AI SDK–specific differences only.

---

## What this policy covers

Vercel AI SDK `tool({...})` / `dynamicTool({...})` bindings whose **VarName**
signals a mutating action (`create`, `send`, `charge`, `delete`, …, via
`name_has_prefix`) but whose definition body mentions no idempotency-key
marker (`has_body_text`). Same threat model as the Claude / OpenAI
idempotency policies; the detection surface differs because Vercel leaves
`ToolDef.Name` empty.

---

## Why idempotency is a distinct concern in agent tools

Identical to the Claude case — agents retry, and a mutating tool with no
dedupe key cannot tell a retry from a new request, so a retried side effect
double-fires. See
[claude_sdk/idempotency.md](../claude_sdk/idempotency.md#why-idempotency-is-a-distinct-concern-in-agent-tools).

Vercel-specific note: the model-facing tool name is the agent's
`tools: { createCharge: createCharge }` record **key**, not a field on the
`tool({...})` factory. Discovery therefore emits an empty `Name` and puts the
binding identifier in `VarName`. The engine's `name_has_prefix` predicate
falls back to `VarName` when `Name` is empty so this rule can match
`createCharge` / `create_charge` bindings the same way OAI-019 matches an
explicit `name:` field.

---

## Rule-by-rule defense

### VAI-010 — TypeScript mutating Vercel AI tool has no idempotency key (Severity: medium, Confidence: 0.5, Fix type: code)

**What we detect:** a Vercel tool whose binding identifier (`VarName`) starts
with a mutating verb (`create` / `send` / `delete` / `post` / `update` /
`refund` / `charge` / `issue`) and whose `tool({...})` span mentions no
idempotency-key marker (`idempot` / `request_id` / `requestId` / `txn_id` /
`correlation_id` / …).

**Why it is flaggable:** agents retry, and a mutating tool with no dedupe key
double-fires the side effect on a retry — the timeout double-spend.

**Real-world consequence:** `const createCharge = tool({...})` retried after a
lost response bills the customer twice.

**Why severity is medium and not high:** real but conditional on a retry
occurring and the backend not deduping by other means.

**Fix type — code:** add `idempotencyKey: z.string()` to `inputSchema` and
forward it to the backing API.

**Confidence 0.5:** lowest in the pack — backend-enforced idempotency and keys
named outside the marker set are common false positives, and `has_body_text`
is a substring heuristic. Binding names that do not use a mutating verb
(`billCustomer`) also escape.

---

## What this policy does not cover

Same gaps as [claude_sdk/idempotency.md](../claude_sdk/idempotency.md#what-this-policy-does-not-cover):
backend-enforced idempotency, mutating names outside the verb set, whether a
present key is actually honored, and deliberate double-invocation.

Additionally: tools whose model-facing name is a mutating verb in the agent's
`tools` record but whose **binding** identifier is benign (`const t = tool(...)`
registered as `tools: { createCharge: t }`) escape, because discovery matches
`VarName`, not the record key.

---

## Recommendations beyond the fix

```typescript
import { tool } from "ai";
import { z } from "zod";

export const createCharge = tool({
  description: "Charge a card once; safe to retry with the same key.",
  inputSchema: z.object({
    cents: z.number().int().positive(),
    idempotencyKey: z.string().min(8),
  }),
  execute: async ({ cents, idempotencyKey }) => {
    return stripe.charges.create(
      { amount: cents, currency: "usd" },
      { idempotencyKey },
    );
  },
});
```

1. Prefer Stripe-style idempotency headers (or an equivalent store) over
   application-level "maybe it already ran" checks.
2. Keep the mutating verb in the binding name so scanners and reviewers can
   spot side-effecting tools quickly.
3. Surface duplicate-key acknowledgements as structured tool results so the
   model does not invent a second charge after a successful retry.
