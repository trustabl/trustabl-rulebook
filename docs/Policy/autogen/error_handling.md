---
policy_id: autogen_error_handling
category: autogen
topic: error_handling
rules:
  - id: AG2-013
    severity: low
    confidence: 0.6
    scope: tool
    fix_type: code
references: []
---

# Policy Rationale: AutoGen Error Contract Hygiene

**Policy ID:** `autogen_error_handling`  
**File:** `autogen/error_handling.yaml`  
**Rules:** AG2-013  
**Severities:** low  
**Fix types:** code  
**References:** none

---

## What this policy covers

How a registered AutoGen tool surfaces failure. The policy has one rule,
AG2-013, which applies to Python AutoGen / AG2 tools (`applies_to: autogen_tool`,
`language: python`, `scope: tool`) that raise an exception they never catch.
The match is `all:` of two predicates: `has_raise: true` and
`has_try_except: false`.

---

## Why the error contract is a distinct concern in AutoGen tools

AutoGen executes a registered tool on the executor agent's side of the
conversation and sends the result back as that agent's reply. A failure in the
tool comes back the same way, as a string posted into the message history.

Both agents keep talking with that string as the last observation. When an
exception escapes the registered function, the assistant receives the
exception message as a plain string, with no structured field that names the
failure or says whether a retry could succeed. If the
assistant re-issues the same call, the conversation goes on until a cap ends
it: a group chat's `max_round` ([AG2-004](agent_safety.md)) or the executor's
auto-reply cap ([AG2-006](agent_safety.md)). The string also stays in the
transcript and is carried into every subsequent turn's context.

---

## Rule-by-rule defense

### AG2-013 — AutoGen tool raises without a structured error contract (Severity: low, Confidence: 0.6, Fix type: code)

**What we detect:**  
A registered AutoGen tool whose body contains a `raise` (`has_raise: true`)
and has no `try`/`except` block (`has_try_except: false`), both under `all:`.

**Why it is flaggable:**  
The mechanism is the one stated
[above](#why-the-error-contract-is-a-distinct-concern-in-autogen-tools): the
exception escapes the registered function, so the assistant receives its
message as a plain string rather than a structured value with a failure mode
to branch on.

**Real-world consequence:**  
A `lookup_order(order_id: str)` tool raises `KeyError` when the lookup misses.
The assistant receives the exception message as a plain string, with no
structured field that names the failure or says whether a retry could succeed.
If it re-issues the same call, the chat goes on until `max_round` or the
auto-reply cap ends it.

**Why severity is low:**  
The pack sets low and states no reasoning for it. The cost the explanation
names is rounds spent until a cap ends the conversation, and a failure that
stays in the transcript.

**Fix type — code:**  
The pack's fix is an edit to the tool source. Catch the failure modes you
expect and return a structured value the assistant can branch on: name the
failure and say whether retrying could help and what would need to change,
instead of letting the exception escape the registered function. Reserve
raising for programmer errors no amount of agent reasoning can work around.

**Confidence 0.6:**  
The pack sets 0.6 for this rule and names no false-positive or false-negative
scenarios for it.

---

## What this policy does not cover

- **Tools with a `try`/`except` block.** The match requires
  `has_try_except: false`, so a tool with a `try`/`except` block does not fire.
- **Raises the fix keeps.** The fix reserves raising for programmer errors,
  and the match has no predicate that tells those apart, so a tool whose only
  `raise` is such an error still matches.
- **Languages other than Python.** The rule is declared for `language: python`
  only.
- The pack states no other limits for this rule.

---

## Recommendations beyond the fix

```python
from autogen import register_function
from pydantic import BaseModel

ORDERS: dict[str, dict] = {}


class LookupResult(BaseModel):
    ok: bool
    order: dict | None = None
    error: str = ""
    retryable: bool = False
    hint: str = ""


def lookup_order(order_id: str) -> LookupResult:
    """Look up an order by its ID, e.g. "ord_1042", and return the order or a structured error."""
    if not order_id.startswith("ord_"):
        # The assistant can fix this: say what would need to change.
        return LookupResult(
            ok=False,
            error="invalid_order_id",
            retryable=True,
            hint='order_id must start with "ord_", e.g. "ord_1042".',
        )
    try:
        order = ORDERS[order_id]
    except KeyError:
        # A retry cannot help: say so.
        return LookupResult(ok=False, error="order_not_found", retryable=False)
    return LookupResult(ok=True, order=order)


register_function(
    lookup_order, caller=assistant, executor=executor,
    description="Look up an order by its ID and return the order or a structured error.",
)
```

1. Catch the failure modes you expect and return a structured value that
   names the failure, says whether retrying could help, and says what would
   need to change.
2. Reserve raising for programmer errors no amount of agent reasoning can work
   around.
3. Bound the conversation with a group chat's `max_round`
   ([AG2-004](agent_safety.md)) and an auto-reply cap on the executor
   ([AG2-006](agent_safety.md)), the caps that end a chat in which the same
   call is re-issued.
