---
policy_id: vercel_ai_side_effect_bounds
category: vercel_ai
topic: side_effect_bounds
rules:
  - id: VAI-019
    severity: high
    confidence: 0.5
    scope: tool
    fix_type: code
references: [LLM06, LLM01]
---

# Policy Rationale: Unbounded Side-Effect Parameters

**Policy ID:** `vercel_ai_side_effect_bounds`  
**File:** `vercel_ai/side_effect_bounds.yaml`  
**Rules:** VAI-019  
**Severities:** high  
**Fix types:** code  
**References:** LLM06, LLM01

> **Read [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md) for the full threat model.**
> This document covers Vercel AI SDK-specific differences only.

---

## What this policy covers

A Vercel AI SDK tool (`tool({...})` or `dynamicTool({...})`, import-gated to `ai`) whose binding name signals a send/notify or refund/charge/payout/transfer/issue action (`name_has_prefix`), paired with a free-form recipient or amount schema key (`param_name_matches`), where the tool's source shows no visible bound (`not: has_body_text`) and `needsApproval` is absent or `false`. Same predicates and threat model as [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md), with the SDK's own `needsApproval` as the gate.

---

## Why unbounded side-effect parameters are a distinct concern in agent tools

Identical mechanism to the OpenAI case: a Vercel AI SDK tool's arguments come from the model's own reasoning in the `generateText` / `streamText` loop, which prompt injection or a poisoned upstream result can steer just as readily as in any other agent framework. See [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#why-unbounded-side-effect-parameters-are-a-distinct-concern-in-agent-tools) for the full argument, including why this is distinct from VAI-010 (idempotency, a bounded 2× duplication).

---

## Rule-by-rule defense

### VAI-019 — TypeScript side-effecting tool lets the model choose the recipient or amount with no visible bound (Severity: high, Confidence: 0.5, Fix type: code)

**What we detect:**  
A Vercel AI SDK `tool({...})` bound to a `const` name whose name starts with `send` / `notify` (paired with a parameter matching `to`, `cc`, `bcc`, `email`, `emailAddress`, `toEmail`, `toAddress`, `phone`, `phoneNumber`, `toNumber`, or a name containing `recipient`), OR starts with `refund` / `charge` / `payout` / `transfer` / `issue` (paired with a parameter matching `total`, `price`, a `cents`-suffixed name, or a name containing `amount`) — AND whose body/definition contains none of the shared TypeScript bound-marker list (`.max(`, `.lte(`, `z.enum(`, `MAX_`, `Limit`, `allowList`, an `endsWith("@` domain check) AND has no `needsApproval` option set (absent or `false`).

**Why it is flaggable:**  
Same mechanism as OAI-030: the name confirms a mutating verb, the parameter shape confirms the model supplies the recipient or amount directly, and the absence of a bound marker means the framework will execute the call with any value the model's reasoning produces.

**Real-world consequence:**  
A `const sendEmail = tool({ inputSchema: z.object({ to: z.string() }), execute })` given to `generateText` alongside a page-fetching tool: injected instructions in a fetched page steer the send to an attacker-chosen address.

**Why severity is high and not critical, and high and not medium:**  
Same reasoning as OAI-030 — plausible partial mitigations (a downstream API's own cap, review of the trace, controls configured outside the tool) rule out critical; an unbounded blast radius, versus a bounded small-multiple duplication for the idempotency family, rules out medium.

**Fix type — code:**  
The fix — a zod bound or allow-list, deriving the recipient from trusted context, or setting `needsApproval` — is a change to the tool's own definition.

**Confidence 0.5:**  
Tied with OAI-030/031, PYD-014, MCP-030, and LC-025 for the pack's floor. All of the confidence-gap scenarios in [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#confidence-gap) apply directly.

**Vercel-specific:** `needsApproval` (the SDK's human-in-the-loop option, default `false`) is the gate, exactly as in VAI-018; `true` or an approval function silences the rule. SDK 7 deprecated `needsApproval` on `tool()` in favor of `toolApproval` on `generateText`, `streamText`, or `ToolLoopAgent`; a tool-scope rule cannot see that call-level setting, so a finding in SDK 7 code requires manual review.

---

## What this policy does not cover

All of the gaps in [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#what-this-policy-does-not-cover) apply unchanged. Vercel AI SDK-specific additions:

- **The tool's name comes only from its `const` binding.** Vercel tools carry no `name` field, so `const sendEmail = tool({...})` is matched but an inline `tools: { sendEmail: tool({...}) }` record entry has no discoverable name and is **not** matched. This is the single largest Vercel-specific blind spot and is shared with VAI-010.
- **`dynamicTool`** yields a single opaque `input` parameter, so a recipient/amount key cannot be seen and it does not match.
- **SDK 7 `toolApproval` on the call site** is invisible to a tool-scope rule (see the confidence note): a tool gated there still fires.
- **A zod schema imported from another module** hides its bounds from the source-span scan.

---

## Recommendations beyond the fix

```ts
import { tool } from "ai";
import { z } from "zod";

const MAX_REFUND_CENTS = 50_000; // $500.00

export const refundPayment = tool({
  description: "Refund up to MAX_REFUND_CENTS of a captured charge",
  inputSchema: z.object({
    chargeId: z.string(),
    amountCents: z.number().int().positive().max(MAX_REFUND_CENTS),
  }),
  needsApproval: true,
  execute: async ({ chargeId, amountCents }) =>
    payments.refunds.create({ charge: chargeId, amount: amountCents }),
});
```

1. **Bind the tool to a `const`** so it is discoverable (and reviewable).
2. **Use `needsApproval` as a function** that approves only above a threshold.
3. **Enforce the same cap server-side.**
