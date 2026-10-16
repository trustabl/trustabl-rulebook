---
policy_id: pydantic_ai_error_handling
category: pydantic_ai
topic: error_handling
rules:
  - id: PYD-008
    severity: low
    confidence: 0.6
    scope: tool
    fix_type: code
references: []
---

# Policy Rationale: Pydantic AI Error Contract Hygiene

**Policy ID:** `pydantic_ai_error_handling`  
**File:** `pydantic_ai/error_handling.yaml`  
**Rules:** PYD-008  
**Severities:** low  
**Fix types:** code  
**References:** none

---

## What this policy covers

Python Pydantic AI tools (`applies_to: pydantic_ai_tool`, `language: python`,
`scope: tool`) that raise an exception that is neither caught nor a
`ModelRetry`. The match is `all:` of three predicates: `has_raise: true`,
`has_try_except: false`, and `not: has_body_text: [ModelRetry]`. The pack
states that the first two are the same shape as
[CSDK-005](../claude_sdk/error_handling.md) and
[MCP-006](../mcp/error_handling.md), and that the third clause is a
suppressor, not the detection signal: a tool whose only raise is
`raise ModelRetry(...)` is already using the SDK's recovery channel correctly.

---

## Why the error contract is a distinct concern in Pydantic AI tools

Pydantic AI handles a `ModelRetry` differently from an ordinary exception. A
`ModelRetry` is captured by the agent, appended to the message history as
feedback, and the model gets another attempt, up to a retry limit. An ordinary
exception, such as a `KeyError` from a lookup that missed, propagates out of
`agent.run()` and ends the run.

That split decides what a failure costs. A transient failure the model could
have worked around, such as a bad argument it could correct or a lookup that
missed, kills the whole call instead of coming back to the model as a
correction. A tool that raises the wrong kind turns a recoverable failure into
a dead run.

The caller of `agent.run()` then receives a raw traceback rather than a
result, and the exception message may carry internal detail, such as paths or
connection strings, that the tool never meant to expose.

---

## Rule-by-rule defense

### PYD-008 — Pydantic AI tool raises without a ModelRetry or structured error path (Severity: low, Confidence: 0.6, Fix type: code)

**What we detect:**  
A Pydantic AI tool body that contains a `raise` (`has_raise: true`), has no
`try`/`except` block (`has_try_except: false`), and does not match the listed
marker `ModelRetry` (`not: has_body_text: [ModelRetry]`). The pack uses
`has_body_text` for the suppressor because `ModelRetry` is a bare imported
name with no structural signature.

**Why it is flaggable:**  
The mechanism is the one stated
[above](#why-the-error-contract-is-a-distinct-concern-in-pydantic-ai-tools):
an uncaught ordinary exception, such as a `KeyError`, leaves the tool by the
path that ends the run, so the model gets no feedback it can act on.

**Real-world consequence:**  
A `lookup_order(order_id: str)` tool raises `KeyError` when the lookup misses.
The exception propagates out of `agent.run()` and the run ends, where a
`ModelRetry` would have given the model another attempt. The caller receives a
traceback instead of a result, and its message may carry internal detail.

**Why severity is low:**  
The pack sets low and states no reasoning for it. The cost the explanation
names is an ended run and a raw traceback to the caller, whose message may
carry internal detail.

**Fix type — code:**  
The pack's fix is an edit to the tool source. Decide which failures the model
can act on and raise `ModelRetry("...")` for those, with a message that tells
the model exactly what to change. For failures the model cannot fix, catch the
specific exception and return a structured result the caller can branch on (an
error field plus a retryable flag) rather than letting it escape
`agent.run()`.

**Confidence 0.6:**  
The pack sets 0.6. The one false-positive case it names is the one the
suppressor removes: a tool whose only raise is `raise ModelRetry(...)`, which
the pack says would be a false positive if the rule fired on it. The pack names
no other false positives, and no false negatives.

---

## What this policy does not cover

- **Tools with a `try`/`except` block.** The match requires
  `has_try_except: false`, so a tool with a `try`/`except` block does not fire.
- **Tools whose body matches the `ModelRetry` marker.** The suppressor clause
  excludes them.
- **What the exception message contains.** The explanation names internal
  detail in the message as a risk, but no predicate looks at the message.
- **Languages other than Python.** The rule is declared for `language: python`
  only.
- The pack states no other limits for this rule.

---

## Recommendations beyond the fix

```python
from dataclasses import dataclass, field

from pydantic_ai import Agent, ModelRetry

agent = Agent("openai:gpt-4o")

ORDERS: dict[str, dict] = {}


@dataclass
class LookupResult:
    ok: bool
    order: dict = field(default_factory=dict)
    error: str = ""
    retryable: bool = False


@agent.tool_plain
def lookup_order(order_id: str) -> LookupResult:
    """Look up an order by its ID and return the order record.

    Args:
        order_id: The order's ID, "ord_" followed by digits, e.g. "ord_1042".
    """
    if not order_id.startswith("ord_"):
        # The model can fix this: tell it exactly what to change.
        raise ModelRetry('order_id must start with "ord_", e.g. "ord_1042".')
    try:
        order = ORDERS[order_id]
    except KeyError:
        # The model cannot fix this: return a result the caller can branch on.
        return LookupResult(ok=False, error="order_not_found", retryable=False)
    return LookupResult(ok=True, order=order)
```

1. Decide which failures the model can act on, and raise `ModelRetry("...")`
   for those with a message that tells the model exactly what to change.
2. For failures the model cannot fix, catch the specific exception and return
   a structured result with an error field and a retryable flag, rather than
   letting the exception escape `agent.run()`.
3. Keep internal detail such as paths and connection strings out of the
   messages a tool raises or returns.
