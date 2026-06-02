---
policy_id: claude_sdk_idempotency
category: claude_sdk
topic: idempotency
rules:
  - id: CSDK-006
    severity: medium
    confidence: 0.55
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: Idempotency

**Policy ID:** `claude_sdk_idempotency`  
**File:** `claude_sdk/idempotency.yaml`  
**Rules:** CSDK-006  
**Severities:** medium  
**Fix types:** code  
**References:** LLM06

---

## What this policy covers

Claude Agent SDK tools whose name signals a mutating, side-effecting action
(`create`, `send`, `charge`, `delete`, `transfer`, `pay`, …, via `name_has_prefix`)
but whose parameters include no idempotency key (`param_name_matches` for
`idempotency_key`, `request_id`, `dedupe_key`, and similar). In short: the tool
changes the world but has no way to recognize a duplicate invocation.

---

## Why idempotency is a distinct concern in agent tools

Agents retry. It is built into how they operate: a tool call that times out, errors
ambiguously, or returns something the model finds unsatisfying is frequently
called again — sometimes by the model's own reasoning, sometimes by an
orchestrator's retry policy. For a read that is harmless. For a *mutating* tool it
is not: a `send_email`, `create_order`, or `charge_card` that gets retried after a
response was actually produced but lost in transit fires the side effect twice.

Without an idempotency key the tool has no way to tell "the model is asking for a
second, distinct action" apart from "the model is retrying the same action whose
result it didn't see." The classic failure is the timeout double-spend: the charge
succeeds, the acknowledgement is lost, the model retries, and the customer is
billed twice. An idempotency key lets the backend collapse the retry onto the
original action and return the original result.

This maps to OWASP LLM06 (Excessive Agency): the agent can cause real-world effects,
and without deduplication those effects can compound beyond what the user
intended.

---

## Rule-by-rule defense

### CSDK-006 — Mutating tool has no idempotency key (Severity: medium, Confidence: 0.55, Fix type: code)

**What we detect:**
A tool whose name begins with a mutating verb (`create`, `send`, `charge`,
`delete`, `transfer`, …) and whose parameters contain no idempotency-key-shaped
name (`idempotency_key`, `request_id`, `dedupe_key`, …).

**Why it is flaggable:**
A mutating tool with no dedupe key cannot distinguish a retry from a new request,
so an agent retry double-fires the side effect.

**Real-world consequence:**
`charge_card(token, cents)` retried after a lost response bills the customer
twice; `send_email(to, body)` retried sends the message twice.

**Why severity is medium and not high:**
The damage is real (duplicate side effects) but conditional on a retry actually
occurring and on the backend not deduping by other means; many backends provide
their own idempotency layer. It is not low because when it does happen, the effect
is a real, user-visible wrong action.

**Fix type — code:**
Add an idempotency-key parameter and thread it to the backend — a source edit.

**Confidence 0.55:**
This is the lowest-confidence rule in the pack by design. False positives are
common: the dedupe may live at the backend (the API enforces idempotency
server-side regardless of the tool signature), the verb may be non-mutating
(`create_summary` returns text), or the key may be named outside the heuristic.
Treat it as a review prompt for side-effecting tools, not a defect.

---

## What this policy does not cover

- Backend-enforced idempotency: an API that dedupes by natural key or its own
  mechanism makes the tool safe despite no key in the signature (false positive).
- Mutating tools whose names do not start with a recognized verb (`book_table`,
  `apply_patch`).
- Whether an idempotency key that *is* present is actually used correctly (passed
  through, persisted, honored) — the rule only checks presence.
- Non-retry duplication (the model deliberately calling the tool twice for two
  distinct actions).

---

## Recommendations beyond the fix

```python
from claude_agent_sdk import tool

@tool
def charge_card(token: str, cents: int, idempotency_key: str) -> dict:
    """Charge a card. Pass a stable idempotency_key per logical charge so a
    retry of the same charge is collapsed by the provider, not duplicated."""
    charge = gateway.charge(token, cents, idempotency_key=idempotency_key)
    return {"ok": True, "charge_id": charge.id}
```

1. Require the idempotency key as a parameter and document that the model must
   reuse the *same* key when retrying the same logical action (and a fresh key for
   a genuinely new one).
2. Honor the key end-to-end: persist it and return the original result on a
   repeat, rather than just accepting the parameter.
3. For tools where a natural idempotency key exists (an order number, a message
   id), prefer that over a synthetic one.
