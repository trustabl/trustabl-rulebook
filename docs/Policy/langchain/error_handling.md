---
policy_id: langchain_error_handling
category: langchain
topic: error_handling
rules:
  - id: LC-008
    severity: low
    confidence: 0.6
    scope: tool
    fix_type: code
references: []
---

# Policy Rationale: LangChain Error Contract Hygiene

**Policy ID:** `langchain_error_handling`  
**File:** `langchain/error_handling.yaml`  
**Rules:** LC-008  
**Severities:** low  
**Fix types:** code  
**References:** none

---

## What this policy covers

How a LangChain tool surfaces failure. The policy has one rule, LC-008, which
applies to Python LangChain tools (`applies_to: langchain_tool`,
`language: python`, `scope: tool`) that raise an exception they do not catch.
The match is `all:` of two predicates: `has_raise: true` and
`has_try_except: false`.

---

## Why the error contract is a distinct concern in LangChain tools

The pack's policy is written about the `AgentExecutor`. Its policy description
says that by default an exception raised inside a tool escapes the
`AgentExecutor` and ends the run, so the model never sees the failure and never
gets a chance to recover from it. This document repeats that as the pack's
claim, about the `AgentExecutor`.

Two facts about LangChain's `BaseTool` bear on it. `BaseTool.run` handles a
`ToolException` according to `handle_tool_error`, and a pydantic
`ValidationError` according to `handle_validation_error`; both settings default
to `False`, which re-raises the exception. Any other exception is re-raised
whatever the `handle_tool_error` and `handle_validation_error` settings are. A
tool that raises an exception and does not catch it therefore leaves the tool
through the re-raise path unless the exception is a `ToolException` or a
`ValidationError` and the matching setting is on.

The pack's explanation says that the caller then gets a traceback instead of an
answer.

---

## Rule-by-rule defense

### LC-008 — LangChain tool raises without a structured error contract (Severity: low, Confidence: 0.6, Fix type: code)

**What we detect:**  
A Python LangChain tool whose body contains a `raise` (`has_raise: true`) and
has no `try`/`except` block (`has_try_except: false`), both under `all:`.

**Why it is flaggable:**  
The mechanism is the one stated
[above](#why-the-error-contract-is-a-distinct-concern-in-langchain-tools): an
exception the tool raises and does not catch leaves the tool by the re-raise
path, and the pack's policy description says that in an `AgentExecutor` it
escapes and ends the run.

**Real-world consequence:**  
If a `lookup_order(order_id: str)` tool raises `ValueError` when a lookup
misses, and an `AgentExecutor` runs the tool with its defaults, the pack's
policy description says the exception escapes the `AgentExecutor` and ends the
run. The pack's explanation says the model is then not told the step failed.

**Why severity is low:**  
The pack sets low and states no reasoning for it. The costs the explanation
names are an aborted run, a model that is not told the step failed, and a
caller that gets a traceback instead of an answer.

**Fix type — code:**  
The pack's fix is an edit to the tool source. Catch the failure modes you
expect and return a structured result the model can branch on, with an error
field naming the failure and a retryable flag, instead of letting the exception
escape.

**Confidence 0.6:**  
The pack sets 0.6 for this rule and names no false-positive or false-negative
scenarios for it.

---

## What this policy does not cover

- **Tools with a `try`/`except` block.** The match requires
  `has_try_except: false`, so a tool with a `try`/`except` block does not fire.
- **Languages other than Python.** The rule is declared for
  `language: python`.
- The pack states no other limits for this rule.

---

## Recommendations beyond the fix

```python
from typing import Any

from langchain_core.tools import tool

ORDERS: dict[str, dict[str, Any]] = {}


@tool
def lookup_order(order_id: str) -> dict[str, Any]:
    """Look up an order by its ID, e.g. "ord_1042", and return the order or a structured error."""
    if not order_id.startswith("ord_"):
        # A retry with a corrected ID can succeed.
        return {"ok": False, "error": "invalid_order_id", "retryable": True}
    try:
        order = ORDERS[order_id]
    except KeyError:
        # A retry cannot help: say so.
        return {"ok": False, "error": "order_not_found", "retryable": False}
    return {"ok": True, "order": order}
```

1. Catch the failure modes you expect and return a structured result with an
   error field naming the failure and a retryable flag, rather than letting the
   exception escape.
