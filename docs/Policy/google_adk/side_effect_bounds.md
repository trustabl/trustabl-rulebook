---
policy_id: google_adk_side_effect_bounds
category: google_adk
topic: side_effect_bounds
rules:
  - id: ADK-020
    severity: high
    confidence: 0.5
    scope: tool
    fix_type: code
  - id: ADK-021
    severity: high
    confidence: 0.5
    scope: tool
    fix_type: code
references: [LLM06, LLM01]
---

# Policy Rationale: Unbounded Side-Effect Parameters

**Policy ID:** `google_adk_side_effect_bounds`  
**File:** `google_adk/side_effect_bounds.yaml`  
**Rules:** ADK-020, ADK-021  
**Severities:** high, high  
**Fix types:** code  
**References:** LLM06, LLM01

> **Read [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md) for the full threat model.**
> This document covers Google ADK-specific differences only.

---

## What this policy covers

A Google ADK function tool whose name signals a send/notify or refund/charge/pay/payout/transfer/issue action (`name_has_prefix`), paired with a free-form recipient or amount parameter (`param_name_matches`), where the body shows no visible bound (`not: has_body_text`) and no confirmation gate. **ADK-020** covers Python `FunctionTool(fn)`; **ADK-021** covers TypeScript `new FunctionTool({...})`. Same predicates and threat model as [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md), adapted to ADK's confirmation primitive.

---

## Why unbounded side-effect parameters are a distinct concern in agent tools

Identical mechanism to the OpenAI case: an ADK tool's arguments come from the agent's own reasoning over the session and prior tool results, which prompt injection or a poisoned upstream result can steer just as readily as in any other agent framework. See [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#why-unbounded-side-effect-parameters-are-a-distinct-concern-in-agent-tools) for the full argument, including why this is distinct from ADK-006 (idempotency, a bounded 2× duplication).

---

## Rule-by-rule defense

### ADK-020 — Side-effecting tool lets the model choose the recipient or amount with no visible bound (Severity: high, Confidence: 0.5, Fix type: code)

**What we detect:**  
A Google ADK (Python) `FunctionTool` wrapping a same-file function whose name starts with `send_` / `notify_` (paired with a parameter matching `to`, `cc`, `bcc`, `email`, `email_address`, `phone`, `phone_number`, `to_email`, `to_address`, `to_number`, or a name containing `recipient`), OR starts with `refund_` / `charge_` / `pay_` / `payout_` / `transfer_` / `issue_` (paired with a parameter matching `total`, `price`, a `cents`-suffixed name, or a name containing `amount`) — AND whose body/definition contains none of the shared Python bound-marker list (`le=`/`lt=`, `conint(`, `Literal[`, `MAX_`/`_LIMIT`, `ALLOWED`/`ALLOWLIST`, a domain-suffix check) AND no call to `request_confirmation(`, AND no `require_confirmation` argument on the `FunctionTool(...)` call (absent or `False`).

**Why it is flaggable:**  
Same mechanism as OAI-030: the name confirms a mutating verb, the parameter shape confirms the model supplies the recipient or amount directly, and the absence of a bound marker means the framework will execute the call with any value the model's reasoning produces.

**Real-world consequence:**  
A `send_email(to: str, body: str)` function wrapped as `FunctionTool(send_email)` on an `LlmAgent` that also reads inbound mail: an injected instruction in a received message steers the agent to send to an attacker-chosen address.

**Why severity is high and not critical, and high and not medium:**  
Same reasoning as OAI-030 — plausible partial mitigations (a downstream API's own cap, review of the trace, controls configured outside the tool) rule out critical; an unbounded blast radius, versus a bounded small-multiple duplication for the idempotency family, rules out medium.

**Fix type — code:**  
The fix — wrapping with `require_confirmation=True` (or a per-call callable), a bound on the parameter, or deriving the recipient from trusted context — is a change to the tool's registration or body.

**Confidence 0.5:**  
Tied with OAI-030/031, PYD-014, MCP-030, and LC-025 for the pack's floor. All of the confidence-gap scenarios in [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#confidence-gap) apply directly.

**ADK-specific:** `FunctionTool(fn, require_confirmation=True)` (or a callable deciding per call) is ADK's own human-in-the-loop gate. Discovery captures the `FunctionTool(...)` call's keyword arguments into the tool's `Config`, so the rule sees it; `False` is treated as absent. A `tool_context.request_confirmation(...)` call inside the function is likewise a gate.

### ADK-021 — TypeScript side-effecting tool lets the model choose the recipient or amount with no visible bound (Severity: high, Confidence: 0.5, Fix type: code)

**What we detect:**  
A Google ADK (TypeScript) `new FunctionTool({...})` whose name starts with `send` / `notify` (paired with a parameter matching `to`, `cc`, `bcc`, `email`, `emailAddress`, `toEmail`, `toAddress`, `phone`, `phoneNumber`, `toNumber`, or a name containing `recipient`), OR starts with `refund` / `charge` / `payout` / `transfer` / `issue` (paired with a parameter matching `total`, `price`, a `cents`-suffixed name, or a name containing `amount`) — AND whose body/definition contains none of the shared TypeScript bound-marker list (`.max(`, `.lte(`, `z.enum(`, `MAX_`, `Limit`, `allowList`, an `endsWith("@` domain check) AND no call to `requestConfirmation(` in the tool's source.

**Why it is flaggable:**  
Same mechanism as OAI-030: the name confirms a mutating verb, the parameter shape confirms the model supplies the recipient or amount directly, and the absence of a bound marker means the framework will execute the call with any value the model's reasoning produces.

**Real-world consequence:**  
A `sendEmail` `FunctionTool` with `parameters: z.object({ to: z.string() })` and no domain check on an agent that reads inbound mail: an injected instruction steers the send to an attacker-chosen address.

**Why severity is high and not critical, and high and not medium:**  
Same reasoning as OAI-030 — plausible partial mitigations (a downstream API's own cap, review of the trace, controls configured outside the tool) rule out critical; an unbounded blast radius, versus a bounded small-multiple duplication for the idempotency family, rules out medium.

**Fix type — code:**  
The fix — a zod bound or allow-list, deriving the recipient from trusted context, or requesting confirmation from inside `execute` — is a change to the tool's own definition or body.

**Confidence 0.5:**  
Tied with OAI-030/031, PYD-014, MCP-030, and LC-025 for the pack's floor. All of the confidence-gap scenarios in [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#confidence-gap) apply directly.

**ADK-TS-specific:** ADK for TypeScript has **no declarative confirmation option** on `FunctionTool` — Python's `require_confirmation` has no counterpart; confirmation is implemented by hand inside `execute` through the `ToolContext`. This rule therefore treats a `requestConfirmation(` call in the tool's source as the gate. This was verified against the ADK documentation, which states that TypeScript currently requires manual confirmation logic in `execute`; if a declarative option lands, the rule should gain a kwarg clause like ADK-020's.

---

## What this policy does not cover

All of the gaps in [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#what-this-policy-does-not-cover) apply unchanged. Google ADK-specific additions:

- **Bare functions in `tools=[...]`** (ADK accepts a plain callable and wraps it implicitly) are not discovered for Python; only an explicit `FunctionTool(fn)` of a same-file top-level function is.
- **Wrapping via `FunctionTool(func=fn)`, or a function defined in another module,** is not resolved.
- **`before_tool_callback` on the agent** that inspects or blocks the call is agent-level and invisible to a tool-scope rule; a tool gated that way still fires.
- **`require_confirmation` given as a callable that always returns false** counts as a gate for ADK-020 (the predicate checks presence, not value, other than the literal `False`).

---

## Recommendations beyond the fix

```python
from google.adk.tools import FunctionTool, ToolContext

MAX_REFUND_CENTS = 50_000  # $500.00


def refund_payment(charge_id: str, amount_cents: int, tool_context: ToolContext) -> dict:
    """Refund up to MAX_REFUND_CENTS of a captured charge."""
    if not 0 < amount_cents <= MAX_REFUND_CENTS:
        raise ValueError("refund outside the permitted range")
    return payments_client.refunds.create(charge=charge_id, amount=amount_cents)


refund_tool = FunctionTool(refund_payment, require_confirmation=True)
```

1. **Prefer `require_confirmation` with a callable** that confirms only above a threshold, so low-value calls stay frictionless.
2. **In TypeScript, call `requestConfirmation` from `execute`** and branch on the response before acting.
3. **Enforce the same cap server-side.**
