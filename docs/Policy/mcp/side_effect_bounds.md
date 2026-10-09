---
policy_id: mcp_side_effect_bounds
category: mcp
topic: side_effect_bounds
rules:
  - id: MCP-030
    severity: high
    confidence: 0.5
    scope: tool
    fix_type: code
references: [LLM06, LLM01]
---

# Policy Rationale: Unbounded Side-Effect Parameters

**Policy ID:** `mcp_side_effect_bounds`  
**File:** `mcp/side_effect_bounds.yaml`  
**Rules:** MCP-030  
**Severities:** high  
**Fix types:** code  
**References:** LLM06, LLM01

> **Read [openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md) for the full threat model.**
> This document covers MCP-specific differences only.

---

## What this policy covers

An MCP tool (`@server.tool` / `@mcp.tool()` / `.register_tool`) whose name
signals a **send/notify** action or a **refund/charge/pay/payout/transfer/
issue** money-moving action (`name_has_prefix`), paired with a **free-form
recipient or amount parameter** the calling model supplies
(`param_name_matches`), where the handler body shows **no visible bound** on
that parameter (`not: has_body_text` — `le=`/`lt=`, `conint(`/`condecimal(`/
`confloat(`, `Literal[...]`, a `MAX_` / `_LIMIT` constant, an `ALLOWED` /
`ALLOWLIST` / `WHITELIST` name, a domain-suffix check, or a call to
`ctx.elicit(...)`). Same predicates and threat model as
[openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md),
adapted to MCP's single gate: the protocol's own **elicitation** capability
rather than a per-tool decorator kwarg.

---

## Why unbounded side-effect parameters are a distinct concern in agent tools

Identical mechanism to the OpenAI case, sharpened by MCP's deployment model:
an MCP server is invoked by a client acting on behalf of a model whose
arguments the server has no way to independently trust, over a protocol
boundary that is often literally a separate process or a separate machine
from the model doing the reasoning. See
[openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#why-unbounded-side-effect-parameters-are-a-distinct-concern-in-agent-tools)
for the full argument, including why this is distinct from MCP-007
(idempotency, a bounded 2× duplication) and from a turn/iteration cap
(volume, not reach).

MCP-specific note: the protocol's **elicitation** feature (added in the
2025-06-18 spec revision) lets a server ask the human on the other end of
the client for additional input or confirmation before completing a
request — it is the one gate available at the tool-handler level in the MCP
spec itself, independent of whatever the calling agent framework does or
does not enforce upstream. A refund or notification handler with a free-form
amount or recipient and no `ctx.elicit(...)` call is not using the one
protocol-native checkpoint MCP gives it.

---

## Rule-by-rule defense

### MCP-030 — Side-effecting tool lets the model choose the recipient or amount with no visible bound (Severity: high, Confidence: 0.5, Fix type: code)

**What we detect:**  
An MCP tool whose name starts with `send_` / `notify_` (paired with a
parameter matching `to`, `cc`, `bcc`, `email`, `email_address`, `phone`,
`phone_number`, `to_email`, `to_address`, `to_number`, or a name containing
`recipient`), OR starts with `refund_` / `charge_` / `pay_` / `payout_` /
`transfer_` / `issue_` (paired with a parameter matching `total`, `price`, a
`cents`-suffixed name, or a name containing `amount`) — AND whose handler
body contains none of the shared Python bound-marker list AND no call to
`ctx.elicit(`.

**Why it is flaggable:**  
Same mechanism as OAI-030: the name confirms a mutating verb, the parameter
shape confirms the calling model supplies the recipient or amount directly,
and the absence of both a bound marker and an elicitation call means
nothing in the handler stops an out-of-range value from executing.

**Real-world consequence:**  
A `refund_payment(charge_id: str, amount: int)` MCP tool exposed to a
general-purpose agent client, with no cap anywhere in the handler and no
`ctx.elicit(...)` confirmation step: whatever client and model are on the
other end of the connection can request any refund amount, and the server
has no local checkpoint that would catch it.

**Why severity is high and not critical, and high and not medium:**  
Same reasoning as OAI-030 — plausible partial mitigations (the backing
payment API's own cap, a policy layer at the MCP gateway, an operator
watching the audit log) rule out critical; an unbounded blast radius, versus
a bounded small-multiple duplication for the idempotency family, rules out
medium.

**Fix type — code:**  
The fix — a schema-level bound on the tool's input model, deriving the
recipient from session-bound trusted context, or adding an `elicit(...)`
confirmation step — is a change to the handler's own signature or body.

**Confidence 0.5:**  
Tied with OAI-030/031/PYD-014 for the pack's floor. All of the
confidence-gap scenarios in
[openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#confidence-gap)
apply directly, with one MCP-specific addition: **the client, not the
server, may be the actual enforcement point.** Many MCP clients implement
their own tool-call approval UI (a human confirms every tool invocation
before it reaches the server at all) entirely outside the server's own
source — a server-side finding here can be correct about the *handler*
having no bound while the *deployment* is still safe because of client-side
confirmation this rule has no visibility into. This is the single largest
false-positive class for this rule on MCP specifically, larger than for the
SDK-embedded variants (OAI/PYD/LC), where the tool and the agent loop
typically run in the same process and client-side confirmation is less
commonly the sole control.

---

## What this policy does not cover

All of the gaps in
[openai_sdk/side_effect_bounds.md](../openai_sdk/side_effect_bounds.md#what-this-policy-does-not-cover)
apply unchanged. MCP-specific additions:

- **Client-side tool-call confirmation**, as discussed above in the
  confidence gap — the largest MCP-specific blind spot.
- **Server-level or transport-level policy.** An MCP gateway or proxy that
  enforces per-tool rate limits, per-session spending caps, or an
  organization-wide allow-list of permitted recipients sits entirely outside
  the handler function this rule inspects.
- **`elicit(...)` called but its result ignored.** The predicate checks only
  for the presence of the call, not that the handler branches on its
  response — a handler that calls `ctx.elicit(...)` and then proceeds
  regardless of the answer reads as gated to this rule but is not actually
  gated in practice.
- **Non-Python MCP tool discovery.** This rule ships at `language: python`
  only, matching MCP-007's scope; MCP servers implemented in Go, C#, PHP, or
  Rust (which have field-based tool discovery for other MCP rules, per
  `testdata/rules-fixture/CLAUDE.md`) are not covered by this rule.

---

## Recommendations beyond the fix

```python
from typing import Annotated

from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

mcp = FastMCP("payments")
MAX_REFUND_CENTS = 50_000  # $500.00


@mcp.tool()
async def refund_payment(
    ctx: Context,
    charge_id: str,
    amount_cents: Annotated[int, Field(gt=0, le=MAX_REFUND_CENTS)],
) -> dict:
    """Refund up to MAX_REFUND_CENTS of a previously captured charge.

    Elicits explicit confirmation from the human on the other end of the
    client before executing; the field bound is a defense-in-depth
    ceiling, not the only control.
    """
    charge = payments_client.charges.retrieve(charge_id)
    if amount_cents > charge.amount:
        raise ValueError("refund cannot exceed the original charge amount")

    confirmed = await ctx.elicit(
        f"Confirm refund of {amount_cents} cents for charge {charge_id}?"
    )
    if not confirmed:
        raise PermissionError("refund not confirmed")

    return payments_client.refunds.create(
        charge=charge_id,
        amount=amount_cents,
        idempotency_key=f"refund:{charge_id}:{amount_cents}",
    )
```

Additional hardening the rule cannot detect but materially reduces risk:

1. **Branch on the elicitation result.** Calling `ctx.elicit(...)` is not a
   gate unless the handler actually rejects the call when the human declines
   or does not respond.
2. **Enforce recipient/amount bounds at the transport or gateway layer
   too**, not only in the handler — a policy that sits in front of every MCP
   server on a fleet is more robust than a per-tool check.
3. **Log every side-effecting call with its resolved recipient/amount and
   the session/client identity**, so a steered call is auditable regardless
   of which layer eventually catches (or misses) it.
4. **Do not assume a well-behaved client.** A server exposed to more than
   one client implementation should not rely on client-side confirmation as
   its only control — build the server-side bound regardless.
