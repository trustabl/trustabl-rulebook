---
policy_id: langchain_error_handling
category: langchain
topic: error_handling
rules:
  - id: LC-007
    severity: low
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM05]
---

# Policy Rationale: LangChain Error Contract Hygiene

**Policy ID:** `langchain_error_handling`  
**File:** `langchain/error_handling.yaml`  
**Rules:** LC-007  
**Severities:** low  
**Fix types:** code  
**References:** LLM05 (Improper Output Handling)

> Shares the structured-error threat model with
> [openai_sdk/error_handling.md](../openai_sdk/error_handling.md). LangChain-specific
> angle only.

---

## What this policy covers

A LangChain / LangGraph tool — a `@tool`-decorated function, or the function
wrapped by `StructuredTool` / `Tool` — whose body contains a `raise` and no
`try`/`except`, detected by `all: [has_raise: true, has_try_except: false]`.

---

## Why error handling is a distinct concern in agent tools

A conventional caller reads an exception type. A model reads a string. That is
the whole difference, and it is what makes an uncaught raise a reliability
defect rather than a style choice.

LangChain gives the raise two possible destinations, and neither carries
structure. With the executor's default behavior the exception propagates and the
run aborts, so a recoverable failure — a 404, a malformed argument the model
could have corrected — ends the agent. With `handle_tool_error` set, the executor
catches it and stringifies it into a `ToolMessage`, which the model reads as
prose alongside every other message. There is no field distinguishing "you passed
a bad argument, fix it" from "the remote is down, wait" from "you are not
permitted, stop". The model's most common response to an undifferentiated failure
string is to call the tool again with the same arguments, which produces the same
string, until `max_iterations` ends the loop. The cost is the whole iteration
budget spent on a failure that one structured field would have resolved on the
second call.

The stringified exception is also a disclosure channel. `str(e)` on a filesystem
or database error routinely carries absolute paths, hostnames, connection strings
and query fragments. In a conventional service that text lands in a log with an
access control on it. Here it lands in the model's context, and from there in the
transcript, any trace exporter attached to the run, and any surface that renders
the conversation to a user (improper output handling, LLM05).

---

## Rule-by-rule defense

### LC-007 — LangChain tool raises exceptions without a structured error contract (Severity: low, Confidence: 0.6, Fix type: code)

**What we detect:**  
A tool function body containing at least one `raise` statement and no
`try`/`except` block anywhere in that body.

**Why it is flaggable:**  
The presence of a `raise` with no local handler means every failure this
function can produce leaves it as an exception. Whatever the executor does next
— abort, or stringify into a `ToolMessage` — the model receives no field it can
branch on. The tool has no error contract; it has an error side effect.

**Real-world consequence:**

- A `lookup_order` tool raises `KeyError` for an unknown id. With
  `handle_tool_error=True` the model sees `KeyError: 'ORD-991'`, cannot tell that
  the id was simply wrong, and re-calls with `ORD-991` again. The agent burns its
  iteration budget on a failure a `{"error": "no such order", "retryable": false}`
  return would have ended in one turn.
- A tool wrapping `psycopg2` lets an `OperationalError` escape. The message
  carries the full DSN — host, port, database, user — into the model's context and
  into the run transcript.
- A tool raising on a transient timeout aborts the whole run under the default
  executor behavior, when the correct handling was a retry.

**Why severity is low and not medium:**  
The failure degrades recovery and leaks incidentally; it does not by itself grant
capability or cross a privilege boundary. A raise is also frequently deliberate —
plenty of tools raise expecting a wrapping frame, a `handle_tool_error` callable,
or a LangGraph error edge to structure it. Low reflects that this is a reliability
tax paid on the failure path, not an exploit primitive.

**Fix type — code:**  
Catching the failure and returning `{"error": ..., "retryable": ...}` is a source
edit to the tool body. Setting `handle_tool_error` to a mapping function is also a
code change, in the tool's construction.

**Confidence 0.6:**  
The check is body-local, which produces error in both directions. False positives:
a tool that raises deliberately because a wrapping decorator, a `StructuredTool`
subclass, or a `handle_tool_error` callable converts the exception into exactly the
structured shape this rule asks for — the structure exists, just not in this body.
False negatives: a tool with a `try`/`except` that catches and then re-raises, or
catches and returns a bare string, satisfies the predicate while having no more of
a contract than a bare raise. 0.6 is the honest read of a single-frame syntactic
check standing in for a whole-call-path property.

---

## What this policy does not cover

- Exception handling performed by a wrapping frame — a decorator, a
  `StructuredTool` subclass, a `handle_tool_error` callable, or a LangGraph error
  edge — outside the tool body.
- A `try`/`except` that catches and re-raises, or that returns an unstructured
  string. Both satisfy the predicate without providing a contract.
- Whether the returned structured error is *correct* — that `retryable` reflects
  reality, or that the message tells the model what to change.
- Whether the raised or returned message actually contains sensitive data; the
  disclosure risk is inferred from the pattern, not confirmed by inspecting it.
- TypeScript LangChain tools. No raise/catch predicate is wired for TS today, so
  `LC-010`..`LC-014`'s language has no error-contract counterpart.

---

## Recommendations beyond the fix

```python
from langchain_core.tools import tool


@tool
def lookup_order(order_id: str) -> dict:
    """Look up an order by id."""
    try:
        return {"ok": True, "order": ORDERS[order_id]}
    except KeyError:
        return {"ok": False, "error": "no order with that id", "retryable": False}
    except TimeoutError:
        return {"ok": False, "error": "order service timed out", "retryable": True}
```

1. Return a result object with a `retryable` field on every failure path. That one
   boolean is what lets the model choose between correcting its arguments and
   waiting, instead of repeating the call until `max_iterations` ends the run.
2. Name the offending input in the error message ("no order with that id"), not the
   exception type. The model rewrites its next call from that string.
3. If you rely on the executor to relay errors, set `handle_tool_error` to a
   *function* that maps the exception to the same structured shape — `True` only
   stringifies it.
4. Never pass a raw `str(e)` from a database or filesystem client through to the
   model; it carries paths and connection strings into the transcript.
