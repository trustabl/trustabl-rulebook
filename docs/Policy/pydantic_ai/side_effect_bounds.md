---
policy_id: pydantic_ai_side_effect_bounds
category: pydantic_ai
topic: side_effect_bounds
rules:
  - id: PYD-014
    severity: high
    confidence: 0.5
    scope: tool
    fix_type: code
references: [LLM06, LLM01]
---

# Policy Rationale: Unbounded Side-Effect Parameters

**Policy ID:** `pydantic_ai_side_effect_bounds`  
**File:** `pydantic_ai/side_effect_bounds.yaml`  
**Rules:** PYD-014  
**Severities:** high  
**Fix types:** code  
**References:** LLM06, LLM01

> **Read [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md) for the full threat model.**
> This document covers Pydantic AI–specific differences only.

---

## What this policy covers

A Pydantic AI tool (registered via `@agent.tool` / `@agent.tool_plain`, or
the `Tool(fn, ...)` factory) whose name signals a **send/notify** action or a
**refund/charge/pay/payout/transfer/issue** money-moving action
(`name_has_prefix`), paired with a **free-form recipient or amount
parameter** the model supplies (`param_name_matches`), where the function
body shows **no visible bound** on that parameter (`not: has_body_text` —
`le=`/`lt=`, `conint(`/`condecimal(`/`confloat(`, `Literal[...]`, a `MAX_` /
`_LIMIT` constant, an `ALLOWED` / `ALLOWLIST` / `WHITELIST` name, or a
domain-suffix check), and **no `requires_approval` gate** set to a truthy
value. Same predicates, same threat model, and the same four-way `all`
(name/verb × parameter shape × no bound × no gate) as
[openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md).

---

## Why unbounded side-effect parameters are a distinct concern in agent tools

Identical mechanism to the OpenAI case — the model's tool arguments are
downstream of whatever untrusted content it has processed, and a
side-effecting tool with no bound on its recipient or amount lets that
content determine how far the action reaches, not merely whether it fires.
See
[openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#why-unbounded-side-effect-parameters-are-a-distinct-concern-in-agent-tools)
for the full argument, including why this is distinct from PYD-007
(idempotency, a bounded 2× duplication) and from a turn/iteration cap
(volume, not reach).

Pydantic AI–specific note: the SDK's own **deferred-tool approval** feature
(`requires_approval=True` on a tool) is a first-class, SDK-native
human-in-the-loop primitive built for exactly this class of risk — a tool
marked this way returns a `DeferredToolRequests` result instead of
executing, and the run loop must resolve it (approve or deny) before the
side effect happens. That makes the fix for this rule unusually
low-friction on Pydantic AI relative to some other SDKs: the gate already
exists in the framework, it is one keyword argument, and its absence on a
money- or contact-moving tool is a clear signal the author has not reached
for it yet.

---

## Rule-by-rule defense

### PYD-014 — Side-effecting tool lets the model choose the recipient or amount with no visible bound (Severity: high, Confidence: 0.5, Fix type: code)

**What we detect:**  
A Pydantic AI tool whose name starts with `send_` / `notify_` (paired with a
parameter matching `to`, `cc`, `bcc`, `email`, `email_address`, `phone`,
`phone_number`, `to_email`, `to_address`, `to_number`, or a name containing
`recipient`), OR starts with `refund_` / `charge_` / `pay_` / `payout_` /
`transfer_` / `issue_` (paired with a parameter matching `total`, `price`, a
`cents`-suffixed name, or a name containing `amount`) — AND whose function
body contains none of the shared Python bound-marker list — AND whose
decorator/factory kwargs either omit `requires_approval` or set it to the
literal string `False`.

**Why it is flaggable:**  
Same mechanism as OAI-030: the name confirms a mutating verb, the parameter
shape confirms the model supplies the recipient or amount directly, the
absence of a bound marker means the visible source imposes no ceiling, and
the absence of `requires_approval` means the SDK's own native approval gate
was not used either.

**Real-world consequence:**  
A `send_email(to: str, body: str)` tool with no allow-list check anywhere in
its body, wired into an agent that drafts and sends replies to inbound
support email: a crafted message asking the agent to "also loop in" an
external address gets exactly that, because nothing in the tool constrains
who `to` may legitimately be.

**Why severity is high and not critical, and high and not medium:**  
Same reasoning as OAI-030 — plausible partial mitigations (backend-side
caps, an agent-level output check, a human reviewing sent messages)
rule out critical; an unbounded blast radius, versus a bounded small-
multiple duplication for the idempotency family, rules out medium.

**Fix type — code:**  
The fix — a Pydantic field constraint, deriving the recipient from trusted
context, or `requires_approval=True` — is a change to the tool's own
signature or decorator kwargs.

**Confidence 0.5:**  
Tied with OAI-030/031 for the pack's floor. All of the confidence-gap
scenarios in
[openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#confidence-gap)
apply directly, with one Pydantic AI–specific addition: **`RunContext`-based
enforcement.** A tool that declares a `ctx: RunContext[Deps]` parameter and
enforces the bound by reading injected dependencies (a per-user transfer
limit loaded from `ctx.deps`, checked against `amount` inside the function
body) is doing real, data-driven validation that has no fixed marker
string — the check is written in terms of whatever `Deps` type and field
names the application defines, which this rule's static, SDK-wide marker
list cannot anticipate. This is a wider gap for Pydantic AI than for the
other SDKs in this pack because `RunContext` dependency injection is a
first-class, commonly used part of the SDK's own tool-authoring model, not
an unusual pattern.

---

## What this policy does not cover

All of the gaps in
[openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#what-this-policy-does-not-cover)
apply unchanged (verbs/parameter names outside the matched sets, no
data-flow proof, runtime/config-level caps, the intentionally-safe
`charge_customer(customer_id)` shape). Pydantic AI–specific additions:

- **`requires_approval` set via a mechanism discovery does not resolve.**
  Discovery captures decorator/factory kwargs from the call site itself; a
  tool whose approval requirement is set through a `Toolset`-level default
  or applied programmatically after registration is invisible to
  `tool_decorator_kwarg_present`.
- **`RunContext`-based authorization.** A tool that reads the current
  `RunContext` (e.g. the authenticated user's permitted transfer limit) and
  enforces the bound that way, rather than through a static schema
  constraint or a body-text marker, is a real mitigation this rule cannot
  see — the enforcement logic may reference `ctx.deps` in a way with no
  recognizable marker string.
- **Deferred approval resolved automatically.** `requires_approval=True`
  silences this rule regardless of how the run loop actually resolves the
  resulting `DeferredToolRequests` — an application that auto-approves every
  deferred request in its run loop (defeating the point of the gate) still
  reads as gated to this static rule.

---

## Recommendations beyond the fix

```python
from typing import Annotated
from pydantic import Field
from pydantic_ai import Agent

MAX_REFUND_CENTS = 50_000  # $500.00

agent = Agent("openai:gpt-4o")


@agent.tool_plain(requires_approval=True)
def refund_payment(
    charge_id: str,
    amount_cents: Annotated[int, Field(gt=0, le=MAX_REFUND_CENTS)],
) -> dict:
    """Refund up to MAX_REFUND_CENTS of a previously captured charge.

    requires_approval=True defers execution until a human resolves the
    DeferredToolRequests in the run loop; the field bound is a defense-in-
    depth ceiling, not the only control.
    """
    charge = payments_client.charges.retrieve(charge_id)
    if amount_cents > charge.amount:
        raise ValueError("refund cannot exceed the original charge amount")
    return payments_client.refunds.create(
        charge=charge_id,
        amount=amount_cents,
        idempotency_key=f"refund:{charge_id}:{amount_cents}",
    )


@agent.tool_plain
def send_customer_notification(order_id: str, message: str) -> dict:
    """Send a notification to the customer on file for this order.

    The recipient is derived from order_id server-side and is never a
    model-supplied argument.
    """
    order = orders_client.get(order_id)
    return notifications_client.send(to=order.customer_email, body=message)
```

Additional hardening the rule cannot detect but materially reduces risk:

1. **Actually resolve `DeferredToolRequests`, don't auto-approve them.** The
   gate is only as strong as what the run loop does when a tool defers —
   route it to a real human decision, not a blanket approval.
2. **Prefer deriving the recipient over accepting it**, removing the
   free-form parameter entirely where the recipient can be looked up from
   trusted context (`RunContext.deps`, an order or ticket record) instead.
3. **Enforce the same cap server-side**, independent of the Pydantic field
   constraint, so a differently-shaped call path cannot bypass it.
4. **Log every side-effecting call with its resolved recipient/amount**,
   independent of success, so a steered call is auditable even under a cap.
