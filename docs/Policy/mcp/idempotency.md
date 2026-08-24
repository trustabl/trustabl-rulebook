---
policy_id: mcp_idempotency
category: mcp
topic: idempotency
rules:
  - id: MCP-007
    severity: medium
    confidence: 0.55
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: MCP Mutating-Tool Idempotency

**Policy ID:** `mcp_idempotency`  
**File:** `mcp/idempotency.yaml`  
**Rules:** MCP-007  
**References:** LLM06 (Excessive Agency)

> Shares the retry-safety threat model with
> [openai_sdk/idempotency.md](../openai_sdk/idempotency.md). MCP-specific angle
> only.

---

## What this policy covers

A mutating MCP tool — its name carries a side-effect prefix (`create_`, `send_`,
`delete_`, `post_`, `update_`, `refund_`, `charge_`, `issue_`) — that exposes no
idempotency-key parameter, detected by `all: [name_has_prefix: [...], not:
param_name_matches: {contains: [idempot], exact: [request_id, txn_id]}]`.

## Rule-by-rule defense

### MCP-007 — Mutating tool has no idempotency key (Severity: medium, Confidence: 0.55, Fix type: code)

**What we detect:** a side-effect-named handler with no parameter that looks like
an idempotency key.

**Why it is flaggable:** MCP clients retry tool calls under timeouts and ambiguous
failures, and the same model may be re-driven to repeat an action. Without an
idempotency key the handler executes the mutation twice — a duplicate charge,
order, or message. The excessive-agency framing (LLM06) is that the tool performs
an irreversible side effect with no replay guard. Medium severity, and confidence
0.55 because the signal is name-based: a tool named `create_*` may be internally
idempotent, and a mutating tool with a non-obvious name is missed. The finding is
a prompt to confirm, not a proof.

**Fix type — code:** accepting an idempotency key and de-duplicating server-side
is a source edit.

---

## What this policy does not cover

Whether the side effect is genuinely non-idempotent; mutating tools whose names
carry no recognized prefix; server-side de-duplication achieved without a visible
key parameter; and the TypeScript MCP surface (the name-prefix predicate runs on
Python handlers; a TS analogue is not wired in this pack).

---

## Recommendations beyond the fix

```python
import json

import redis
import stripe
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("payments")

# Shared across every worker and every session, so a retry that lands on a
# different process still dedupes.
_dedup = redis.Redis(host="redis.internal", decode_responses=True)
_TTL_SECONDS = 24 * 60 * 60
_IN_FLIGHT = "__in_flight__"


@mcp.tool()
def refund_charge(charge_id: str, amount_cents: int, idempotency_key: str) -> dict:
    """Refund a charge. Retrying with the same idempotency_key is safe: it
    returns the original refund rather than issuing a second one."""
    key = f"refund:{idempotency_key}"

    cached = _dedup.get(key)
    if cached == _IN_FLIGHT:
        return {"error": "refund already in flight", "code": "in_progress",
                "retryable": True}
    if cached is not None:
        return json.loads(cached)

    # Claim the key before calling the provider, so two concurrent retries
    # cannot both get through.
    if not _dedup.set(key, _IN_FLIGHT, nx=True, ex=_TTL_SECONDS):
        return {"error": "refund already in flight", "code": "in_progress",
                "retryable": True}

    refund = stripe.Refund.create(
        charge=charge_id, amount=amount_cents, idempotency_key=idempotency_key
    )
    payload = {"refund_id": refund.id, "status": refund.status}
    _dedup.set(key, json.dumps(payload), ex=_TTL_SECONDS)
    return payload
```

The retry-safety rationale is in
[openai_sdk/idempotency.md](../openai_sdk/idempotency.md#recommendations-beyond-the-fix).
MCP-specific additions:

1. Make the key a named parameter, not a header or an ambient value. MCP-007
   keys on the parameter name, but the substantive reason is that a connecting
   client can only supply what it can see in the tool's published input schema.
2. Keep the dedup store outside the process. An MCP session can drop and the
   client reconnect; the retry may land on a different worker entirely, so an
   in-memory dict dedupes only within one process's lifetime — which is
   precisely not the window that matters.
3. Return the original result on replay rather than an error. A caller that
   gets `already_refunded` back cannot tell it from a failure, and will often
   escalate; returning the first refund makes the retry a no-op, which is the
   whole point.
4. Say the guarantee in the docstring. The description is published to the
   connecting model, and the model is what decides whether to retry — a tool
   that is safe to retry and does not say so gets retried nervously or not at
   all.
5. Do not let the model mint a fresh key per attempt. A key regenerated on each
   retry satisfies MCP-007's parameter check and guarantees nothing; derive it
   from the task (order id plus intent) or have the client supply it and reuse
   it across the whole retry sequence.
6. Set the TTL longer than the client's retry window, and longer than a
   plausible reconnect gap. A key that expires between the timeout and the
   retry is the same as no key at all.
