---
policy_id: langchain_idempotency
category: langchain
topic: idempotency
rules:
  - id: LC-017
    severity: medium
    confidence: 0.55
    scope: tool
    fix_type: code
references: []
---

# Policy Rationale: LangChain Mutating-Tool Idempotency

**Policy ID:** `langchain_idempotency`  
**File:** `langchain/idempotency.yaml`  
**Rules:** LC-017  
**Severities:** medium  
**Fix types:** code  
**References:** none

---

## What this policy covers

Python LangChain tools (`applies_to: langchain_tool`, `language: python`,
`scope: tool`) whose name signals a side effect but which take no idempotency
key. The match is `all:` of two predicates. The tool's name starts with one of
`create_`, `send_`, `delete_`, `post_`, `update_`, `refund_`, `charge_`,
`issue_` (predicate `name_has_prefix`), and no parameter name contains
`idempot` or is exactly `request_id` or `txn_id` (predicate
`param_name_matches`, under `not:`).

---

## Why idempotency is a distinct concern in LangChain tools

The pack's explanation says that when the tool takes no idempotency key, "a
repeated call commits the mutation twice".

The pack's explanation says that in an `AgentExecutor` loop, a step whose
observation reads as inconclusive, such as a timeout, a truncated response, or
an error string returned under `handle_tool_error`, can lead the model to reason
about the same goal again and re-issue the same action, and that it cannot know
the first call already committed. If that happens, the mutation is sent a
second time.

The explanation also names retry wrappers, including LangChain's own
`with_retry`, and says a network failure after the side effect landed is
indistinguishable from one before it. The result it names is a duplicate
charge, order, or message.

---

## Rule-by-rule defense

### LC-017 — Mutating LangChain tool has no idempotency key (Severity: medium, Confidence: 0.55, Fix type: code)

**What we detect:**  
A Python LangChain tool whose name starts with `create_`, `send_`, `delete_`,
`post_`, `update_`, `refund_`, `charge_`, or `issue_` (`name_has_prefix`) and
none of whose parameter names contains `idempot` or is exactly `request_id` or
`txn_id` (`not: param_name_matches`), both under `all:`.

**Why it is flaggable:**  
The mechanism is the one stated
[above](#why-idempotency-is-a-distinct-concern-in-langchain-tools): the name
signals a side effect, and the pack's explanation says that with no key "a
repeated call commits the mutation twice".

**Real-world consequence:**  
If a `create_order(customer_id: str, sku: str)` tool times out after the order
was written, and the model re-issues the same action or a `with_retry` wrapper
retries the call, a second order can be created.

**Why severity is medium:**  
The pack sets medium and states no reasoning for it. The costs the explanation
names are a duplicate charge, order, or message.

**Fix type — code:**  
The pack's fix is an edit to the tool source. Accept an idempotency key
parameter (`idempotency_key` or `request_id`), require the caller to derive it
from the unit of work rather than generating a fresh one per call, and
de-duplicate server-side so a repeated call returns the first result instead of
committing again.

**Confidence 0.55:**  
The pack sets 0.55 for this rule and names no false-positive or false-negative
scenarios for it.

---

## What this policy does not cover

- **Tools whose name does not start with a listed prefix.** The match lists
  eight prefixes.
- **Keys under other parameter names.** The match exempts a parameter whose name
  contains `idempot` or is exactly `request_id` or `txn_id`.
- **Languages other than Python.** The rule is declared for
  `language: python`.
- The pack states no other limits for this rule.

---

## Recommendations beyond the fix

```python
from typing import Any
from uuid import uuid4

from langchain_core.tools import tool

# The first result for each key. In production this store lives with the
# service that commits the order, so de-duplication happens server-side.
RESULTS_BY_KEY: dict[str, dict[str, Any]] = {}


@tool
def create_order(customer_id: str, sku: str, quantity: int, idempotency_key: str) -> dict[str, Any]:
    """Create one order for a customer and return the order record.

    idempotency_key identifies this order request. Reuse the same key when
    retrying the same order; a repeated call with that key returns the first
    result instead of creating a second order.
    """
    previous = RESULTS_BY_KEY.get(idempotency_key)
    if previous is not None:
        return previous
    order = {
        "order_id": f"ord_{uuid4().hex[:8]}",
        "customer_id": customer_id,
        "sku": sku,
        "quantity": quantity,
    }
    RESULTS_BY_KEY[idempotency_key] = order
    return order
```

1. Accept an idempotency key parameter (`idempotency_key` or `request_id`) on
   the tool.
2. Derive the key from the unit of work rather than generating a fresh one per
   call, so a repeated call carries the same key.
3. De-duplicate server-side, so a repeated call returns the first result
   instead of committing again.
