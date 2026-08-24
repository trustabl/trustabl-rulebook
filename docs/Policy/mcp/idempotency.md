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

# Policy Rationale: Idempotency

**Policy ID:** `mcp_idempotency`  
**File:** `mcp/idempotency.yaml`  
**Rules:** MCP-007  
**Severities:** medium  
**Fix types:** code  
**References:** LLM06

> Shares the retry-safety threat model with
> [openai_sdk/idempotency.md](../openai_sdk/idempotency.md). MCP-specific
> angle only. The OpenAI doc in turn points at
> [claude_sdk/idempotency.md](../claude_sdk/idempotency.md) for the full
> rationale (CSDK-006 / CSDK-016).

---

## What this policy covers

Python MCP tools (`applies_to: mcp_tool`, `language: python`) whose name
signals a mutating, side-effecting action via `name_has_prefix` on the
snake_case prefixes `create_`, `send_`, `delete_`, `post_`, `update_`,
`refund_`, `charge_`, and `issue_`, but whose parameters include no
idempotency-key-shaped name (`not param_name_matches` for substring `idempot`
or the exact names `request_id` and `txn_id`). In short: the handler changes
the world and the signature gives the client no way to mark a call as a
replay of a prior one.

---

## Why idempotency is a distinct concern in agent tools

MCP tool handlers run on a server that an external host drives. The model
fills every argument; the host issues `tools/call`; the handler performs the
side effect and returns a result. That round trip is not exactly-once. If
the stdio, SSE, or Streamable HTTP transport times out or drops after the
handler has already committed — charged a card, sent a message, created an
order — the client still has no result. Hosts retry the same `tools/call`
(new JSON-RPC id, same arguments) because at-least-once delivery is how they
recover from a lost response. The server sees a second invocation, not a
replay, unless the payload carries a key the handler can look up.

The model retries independently of the transport. A result that is missing,
error-shaped, or “looks inconclusive” is fed back into the next turn; the
model then issues another `tools/call` for the same user intent. MCP-006
makes this worse when the handler raises an unstructured exception: the
client surfaces an opaque protocol error, the model cannot tell “already
done” from “never ran,” and it calls the tool again. The server has no
session-level memory of the first call unless the author added one.

Without an idempotency key the handler cannot distinguish “the host is
asking for a second, distinct action” from “the host or model is retrying
the same action whose result it did not see.” The timeout double-spend is
the concrete failure: `charge_card` succeeds, the `tools/call` result is
lost, the host or model retries, and the customer is billed twice. An
idempotency key lets the backend collapse the retry onto the original
action and return the original result.

This is worse than the same gap in a conventional API because the caller is
not a developer who can hold a request id in application memory. It is a
model plus an orchestrator that will re-issue on timeout and on ambiguous
output, using inputs they fully control. That maps to OWASP LLM06
(Excessive Agency): the agent can cause real-world effects, and without
deduplication those effects compound beyond what the user intended.

---

## Rule-by-rule defense

### MCP-007 — Mutating tool has no idempotency key (Severity: medium, Confidence: 0.55, Fix type: code)

**What we detect:**  
A Python MCP tool whose name begins with one of the mutating snake_case
prefixes `create_`, `send_`, `delete_`, `post_`, `update_`, `refund_`,
`charge_`, or `issue_` (`name_has_prefix`), and whose parameters contain no
idempotency-key-shaped name: no parameter whose name contains the substring
`idempot`, and no parameter named exactly `request_id` or `txn_id`
(`not param_name_matches`). Both conjuncts must hold (`match.all`). This is
a name-and-signature heuristic over the discovered tool; it does not read
the handler body or check whether a key is forwarded to a backend.

**Why it is flaggable:**  
A mutating tool with no dedupe key cannot tell a retried `tools/call` from a
new request. An MCP client timeout, a dropped response after commit, or a
model re-issuing the same action after an unstructured error therefore
double-fires the side effect.

**Real-world consequence:**

- `charge_card(token, cents)` retried after a lost `tools/call` result bills
  the customer twice.
- `send_email(to, body)` retried by the host or the model sends the message
  twice.
- `create_order(sku, qty)` re-issued after an SSE timeout inserts two orders
  for one user intent.

**Why severity is medium and not high:**  
The damage is real (duplicate side effects) but conditional on a retry
actually occurring and on the backend not deduping by other means; many
payment and messaging APIs already enforce idempotency server-side. It is
not low because when the retry does happen, the effect is a real,
user-visible wrong action (a second charge, message, or delete).

**Fix type — code:**  
Add an idempotency-key parameter to the tool signature and thread it to the
backend so a replay is collapsed — a source edit to the MCP handler. A
host-side retry policy cannot supply a key the tool does not accept.

**Confidence 0.55:**  
This is a low-confidence rule by design; the gap is the name heuristic, not
uncertainty about MCP retry mechanics. **False positives:** the prefix
matches non-mutating names (`create_summary` returns text, `update_cache`
rewrites a local dict); the backend already dedupes on a natural key the
signature never names (Stripe-style server-side idempotency); a parameter
outside the heuristic still uniquely identifies the operation. **False
negatives:** a mutating tool whose name is outside the prefix set (`pay_`,
`transfer_`, `book_`, `apply_`) is missed; camelCase Python names
(`createOrder`) fail `name_has_prefix` because every listed prefix ends in
`_`; an idempotency parameter spelled `dedupe_key`, `client_token`, or
`requestId` is not recognized (`contains: [idempot]` / `exact: [request_id,
txn_id]`), so a safe tool still fires. Treat every hit as a review prompt
for a side-effecting MCP handler, not a defect.

---

## What this policy does not cover

- Mutating tools whose names do not start with a listed prefix. The match
  block is `create_` / `send_` / `delete_` / `post_` / `update_` /
  `refund_` / `charge_` / `issue_` only — `pay_invoice`, `transfer_funds`,
  `book_table`, and `apply_credit` are false negatives even when they have
  no key.
- Idempotency parameters spelled outside the heuristic. `dedupe_key`,
  `client_token`, `correlation_id`, and camelCase `requestId` / `txnId` do
  not match `contains: [idempot]` or `exact: [request_id, txn_id]`, so a
  tool that is already safe still fires (false positive from the YAML).
- Backend-enforced idempotency with no key in the signature. If the
  downstream API dedupes on a natural key or its own header, the tool is
  safe and the rule still fires because `not param_name_matches` only sees
  the Python parameter list.
- Whether a matching parameter is actually used. A handler with
  `idempotency_key` silences the rule even if the body ignores the argument
  and never forwards it.
- Substring collision on `idempot`. A parameter named `non_idempotent`
  contains `idempot`, so `param_name_matches` succeeds, the `not` fails, and
  a genuinely non-idempotent tool is missed.
- TypeScript MCP tools. MCP-007 is `language: python`; there is no TS
  sibling in `mcp/idempotency.yaml` (unlike CSDK-016 / OAI-019).
- Deliberate double-invocation: the model calling the tool twice for two
  distinct user actions. An idempotency key does not (and should not) block
  that if the keys differ.

---

## Recommendations beyond the fix

```python
import os

import stripe
from mcp.server.fastmcp import FastMCP

stripe.api_key = os.environ["STRIPE_API_KEY"]
mcp = FastMCP("payments")


@mcp.tool()
def create_invoice(customer_id: str, idempotency_key: str) -> dict:
    """Create an invoice. Pass a stable idempotency_key per logical invoice
    so a retried tools/call is collapsed by Stripe, not duplicated."""
    invoice = stripe.Invoice.create(
        customer=customer_id,
        idempotency_key=idempotency_key,
    )
    return {"ok": True, "invoice_id": invoice.id, "status": invoice.status}
```

1. Require the idempotency key as a parameter and document that the host and
   model must reuse the *same* key when retrying the same logical action
   (and a fresh key for a genuinely new one).
2. Honor the key end-to-end: persist it and return the original result on a
   repeat, rather than just accepting the parameter. Presence in the
   signature is what MCP-007 checks; persistence is what stops the double
   spend.
3. For tools where a natural idempotency key exists (an order number, a
   message id), prefer that over a synthetic one, and still expose it under
   a name the heuristic — and the model — can see (`idempotency_key` or
   `request_id`).
4. Pair with a structured error contract (MCP-006) so an exception does not
   become an opaque protocol error that provokes a blind retry in the first
   place.
