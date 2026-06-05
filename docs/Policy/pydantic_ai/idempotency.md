---
policy_id: pydantic_ai_idempotency
category: pydantic_ai
topic: idempotency
rules:
  - id: PYD-007
    severity: medium
    confidence: 0.55
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: Pydantic AI Mutating-Tool Idempotency

**Policy ID:** `pydantic_ai_idempotency`  
**File:** `pydantic_ai/idempotency.yaml`  
**Rules:** PYD-007  
**Severities:** medium  
**Fix types:** code  
**References:** LLM06 (Excessive Agency)

---

## What this policy covers

Pydantic AI tools whose name implies a side effect but which take no idempotency
key. **PYD-007** fires when a tool function's name starts with one of `create_`,
`send_`, `delete_`, `post_`, `update_`, `refund_`, `charge_`, `issue_` (predicate
`name_has_prefix`) AND no parameter name contains `idempot` or is exactly
`request_id` / `txn_id` (predicate `param_name_matches`, negated). It is a
name-and-signature heuristic — it does not read the tool body.

---

## Why missing idempotency is a distinct concern in Pydantic AI tools

A mutating tool that runs twice does its side effect twice: a duplicate charge, a
double-sent message, a repeated delete. In ordinary code a developer controls how
often a function is called; in an agent the *framework* re-invokes tools. Pydantic
AI retries a tool call when the model's arguments fail validation, and the agent
loop can re-select the same tool across turns — so the same side-effecting action
can fire more than once without the author writing any retry logic. The classic
trigger is a timeout or a validation retry: the backend processed the request but
the response was lost or the arguments were re-validated, so the call repeats and
the action happens again.

An idempotency key closes this: the tool sends a stable key the backend uses to
recognize a retried request and return the original result instead of re-executing.
Without it, the agent's own retry behavior turns a transient failure into a
duplicated real-world effect — an excessive-agency (LLM06) reliability hazard where
the agent takes a consequential action more times than intended. The protection
only holds end to end if the downstream service also honors the key; the parameter
is necessary but not sufficient on its own.

---

## Rule-by-rule defense

### PYD-007 — Mutating tool has no idempotency key (Severity: medium, Confidence: 0.55, Fix type: code)

**What we detect:** a tool whose name begins with a mutation prefix (`create_`,
`send_`, `refund_`, …) and which has no parameter named for an idempotency key
(`*idempot*`, `request_id`, or `txn_id`).

**Why it is flaggable:** the name signals a side effect, and Pydantic AI's
validation-retry and re-selection behavior can fire that side effect twice; without
a key there is no mechanism for the backend to deduplicate.

**Real-world consequence:** a `charge_card(customer, amount)` tool has its
arguments re-validated after a transient model error; Pydantic AI retries, and the
customer is charged twice with no key for the processor to collapse the duplicate.

**Why severity is medium and not high:** the duplicate fires only on a retry path
(timeout, ambiguous failure, or a validation retry), not on every call, and many
backends are already idempotent for other reasons — so the impact is real but
probabilistic rather than guaranteed. **Fix type — code:** adding an
`idempotency_key` parameter and threading it to the API is a tool-source change.
**Confidence 0.55:** this is a name heuristic, so a tool named `update_cache` that
mutates nothing fires (false positive), a side-effecting tool named
`process_payment` without a mutation prefix does not (false negative), and a tool
that achieves idempotency through an unnamed mechanism is over-flagged — the low
number reflects all three gaps.

---

## What this policy does not cover

- Side-effecting tools whose name does not start with a listed prefix
  (`process_`, `apply_`, `submit_`, `transfer_`) — they are false negatives.
- Tools that achieve idempotency without a matching parameter name — e.g. by
  deriving a natural key inside the body, or because the backend dedupes on a
  business field. The signature heuristic cannot see body logic, so these fire
  anyway.
- Read-only tools that happen to match a prefix (`update_view_count` that only
  reads) — a false positive.
- Whether the downstream service actually honors the key. The rule checks for a
  parameter, not that retries are truly deduplicated end to end.

---

## Recommendations beyond the fix

```python
from pydantic_ai import Agent

agent = Agent("openai:gpt-4o")

@agent.tool_plain
def charge_card(customer_id: str, amount_cents: int, idempotency_key: str) -> str:
    """Charge a customer. `idempotency_key` must be stable across retries so a
    re-sent request is collapsed by the processor instead of charging twice."""
    return payments.charge(
        customer=customer_id,
        amount=amount_cents,
        idempotency_key=idempotency_key,   # backend dedupes on this
    )
```

1. Add an `idempotency_key: str` parameter to every mutating tool and pass it
   through to the backing API so a retried call is recognized and deduplicated.
2. Make the key stable for a logical operation — derive it from the operation's
   inputs (e.g. a hash of customer + amount + intent) so the same retried action
   reuses the same key.
3. Confirm the downstream service honors the key; an idempotency parameter the
   backend ignores gives no protection.
4. Where the backend cannot dedupe, guard at the application layer (a
   processed-operations table keyed by the idempotency key) before performing the
   side effect.
