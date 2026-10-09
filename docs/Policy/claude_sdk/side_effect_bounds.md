---
policy_id: claude_sdk_side_effect_bounds
category: claude_sdk
topic: side_effect_bounds
rules:
  - id: CSDK-023
    severity: high
    confidence: 0.5
    scope: tool
    fix_type: code
references: [LLM06, LLM01]
---

# Policy Rationale: Unbounded Side-Effect Parameters

**Policy ID:** `claude_sdk_side_effect_bounds`  
**File:** `claude_sdk/side_effect_bounds.yaml`  
**Rules:** CSDK-023  
**Severities:** high  
**Fix types:** code  
**References:** LLM06, LLM01

> **Read [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md) for the full threat model.**
> This document covers Claude Agent SDK-specific differences only.

---

## What this policy covers

A Claude Agent SDK tool created in TypeScript with `tool(name, description, schema, handler)` (imported from `@anthropic-ai/claude-agent-sdk`) whose name signals a send/notify or refund/charge/payout/transfer/issue action (`name_has_prefix`), paired with a free-form recipient or amount key in its schema (`param_name_matches`), where the call's source shows no visible bound (`not: has_body_text`). Same predicates and threat model as [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md), with **no** approval-gate clause because the gate lives on `query()`.

---

## Why unbounded side-effect parameters are a distinct concern in agent tools

Identical mechanism to the OpenAI case: a Claude Agent SDK tool's arguments are produced by the model's reasoning over the conversation and everything the agent has read, which prompt injection or a poisoned upstream result can steer just as readily as in any other agent framework. See [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#why-unbounded-side-effect-parameters-are-a-distinct-concern-in-agent-tools) for the full argument, including why this is distinct from CSDK-016 (idempotency, a bounded 2× duplication).

---

## Rule-by-rule defense

### CSDK-023 — TypeScript side-effecting tool lets the model choose the recipient or amount with no visible bound (Severity: high, Confidence: 0.5, Fix type: code)

**What we detect:**  
A Claude Agent SDK (TypeScript) `tool(name, description, schema, handler)` call whose name starts with `send` / `notify` (paired with a parameter matching `to`, `cc`, `bcc`, `email`, `emailAddress`, `toEmail`, `toAddress`, `phone`, `phoneNumber`, `toNumber`, or a name containing `recipient`), OR starts with `refund` / `charge` / `payout` / `transfer` / `issue` (paired with a parameter matching `total`, `price`, a `cents`-suffixed name, or a name containing `amount`) — AND whose body/definition contains none of the shared TypeScript bound-marker list (`.max(`, `.lte(`, `z.enum(`, `MAX_`, `Limit`, `allowList`, an `endsWith("@` domain check).

**Why it is flaggable:**  
Same mechanism as OAI-030: the name confirms a mutating verb, the parameter shape confirms the model supplies the recipient or amount directly, and the absence of a bound marker means the framework will execute the call with any value the model's reasoning produces.

**Real-world consequence:**  
A `send_email` tool declared `tool("send_email", "Send", { to: z.string(), body: z.string() }, handler)` in an in-process MCP server given to `query()`: an injected instruction in a file the agent reads steers the send to an attacker-chosen address.

**Why severity is high and not critical, and high and not medium:**  
Same reasoning as OAI-030 — plausible partial mitigations (a downstream API's own cap, review of the trace, controls configured outside the tool) rule out critical; an unbounded blast radius, versus a bounded small-multiple duplication for the idempotency family, rules out medium.

**Fix type — code:**  
The fix — a bound or allow-list in the handler, deriving the recipient from trusted context, or routing the call through `canUseTool` — is a change to the tool's own definition or to the `query()` options.

**Confidence 0.5:**  
Tied with OAI-030/031, PYD-014, MCP-030, and LC-025 for the pack's floor. All of the confidence-gap scenarios in [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#confidence-gap) apply directly.

**Claude-SDK-specific:** there is **no tool-level approval gate**. Permission prompts are configured on the `query()` options (`canUseTool`, `permissionMode`), not on the tool, so this rule cannot see them; a tool gated there still fires. The **Python** `@tool("name", "desc", {"to": str})` shape is deliberately not covered: its handler takes a single `args` parameter, so discovery reports `param_names=["args"]` and no parameter-name match can ever see `to` or `amount` (CSDK-006 has the identical blind spot).

---

## What this policy does not cover

All of the gaps in [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#what-this-policy-does-not-cover) apply unchanged. Claude Agent SDK-specific additions:

- **Schema key extraction is limited to an inline object literal** (the third argument). A `z.object({...})` schema, or one held in a variable, yields no parameter names, so the rule cannot see `to` or `amount` and stays silent.
- **Python `@tool` tools** are excluded for the reason above.
- **`canUseTool`, `permissionMode`, `disallowedTools`, or hooks** on `query()` are invisible to a tool-scope rule; a tool gated there still fires. This is a false-positive scenario, accepted because none of them is on the tool.
- **A bound enforced in a helper the handler calls** is not visible to the source-span scan.

---

## Recommendations beyond the fix

```ts
import { tool } from "@anthropic-ai/claude-agent-sdk";
import { z } from "zod";

const MAX_REFUND_CENTS = 50_000; // $500.00

export const refundPayment = tool(
  "refund_payment",
  "Refund up to MAX_REFUND_CENTS of a captured charge",
  { chargeId: z.string(), amountCents: z.number().int().positive().max(MAX_REFUND_CENTS) },
  async ({ chargeId, amountCents }) => {
    if (amountCents > MAX_REFUND_CENTS) throw new Error("refund outside the permitted range");
    await payments.refunds.create({ charge: chargeId, amount: amountCents });
    return { content: [{ type: "text", text: "refunded" }] };
  },
);
// and, on query(): options.canUseTool = async (name, input) => askHuman(name, input)
```

1. **Gate money-moving and messaging tools with `canUseTool`** so a person sees the resolved arguments.
2. **Enforce the same cap server-side.**
3. **Log every call with the resolved recipient/amount and the session ID.**
