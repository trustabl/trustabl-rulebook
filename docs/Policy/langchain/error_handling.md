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
references: [LLM05]
---

# Policy Rationale: LangChain Error Contract Hygiene

**Policy ID:** `langchain_error_handling`  
**File:** `langchain/error_handling.yaml`  
**Rules:** LC-008  
**Severities:** low  
**Fix types:** code  
**References:** LLM05 (Improper Output Handling)

> Shares the structured-error threat model with
> [claude_sdk/error_handling.md](../claude_sdk/error_handling.md). LangChain-specific
> angle only.

---

## What this policy covers

LangChain / LangGraph tools (`@tool`, `StructuredTool` / `Tool`,
`StructuredTool.from_function`) whose body contains a `raise` statement but no
`try`/`except` to convert the failure into a structured result. The match is
`has_raise: true` AND `has_try_except: false`. TypeScript LangChain tools are
out of scope — no TS raise/catch predicate is wired.

---

## Why error handling is a distinct concern in LangChain tools

When an ordinary function raises, a developer reads the traceback and fixes the
call. When a LangChain tool raises, the *model* is the consumer of the failure.
AgentExecutor and LangGraph's `ToolNode` surface an uncaught exception as an
opaque `ToolMessage` (or halt the run if `handle_tool_error` is unset). The
model cannot tell a transient, retryable failure (timeout, 503, rate-limit)
from a permanent one (bad argument, not-found), so it retries a charge that
already committed or abandons a call that would have succeeded on retry.

LC-102's `max_iterations` cap does not help here. It bounds how many *steps*
the executor takes, not how the model interprets one failed step: an opaque
traceback still drives a wrong retry-or-give-up decision inside the remaining
budget.

A second, quieter hazard: the raised exception's message frequently carries
internal detail — a file path, a SQL fragment, a stack of internal module
names — which is now rendered into the model context and from there into logs,
provider transcripts, and possibly the user-visible answer. A raw exception is
both a control-flow problem and mild information disclosure (LLM05, Improper
Output Handling).

---

## Rule-by-rule defense

### LC-008 — LangChain tool raises exceptions without a structured error contract (Severity: low, Confidence: 0.6, Fix type: code)

**What we detect:** a Python LangChain tool body that contains a `raise` and no
`try`/`except` (`has_raise: true`, `has_try_except: false`).

**Why it is flaggable:** a raised exception reaches the model as an opaque
`ToolMessage` with no retryable/permanent signal, so the model cannot branch
correctly — and the message may leak internals.

**Real-world consequence:** `charge_card(...)` that does
`raise ValueError("gateway 503")` on a transient fault gives the model no
"retryable" hint; the model may retry a charge that actually went through, or
give up on one that would have succeeded on retry.

**Why severity is low and not medium:** a bare `raise` is frequently fine:
LangChain's `handle_tool_error`, an outer wrapper, or a `ToolException` handler
often converts the exception into something the model can act on, so this is a
reliability-and-hygiene nudge rather than a defect. It is not medium because
the in-body check cannot see those out-of-body handlers and fires on a great
deal of correct code.

**Fix type — code:** wrap the body and return a structured error — a source
edit.

**Confidence 0.6:** false positives when a tool deliberately `raise`s a typed
exception that `handle_tool_error` or an outer wrapper converts into structure.
False negatives when a `try`/`except` swallows errors silently or re-raises
without shaping them — those satisfy the rule while being *worse*. The rule is
a prompt to review, not a verdict.

---

## What this policy does not cover

- Tools that raise but have an external handler (`handle_tool_error`, a
  `ToolException` wrapper, an outer graph node) that structures the error — a
  false positive.
- Tools with a `try`/`except` that catches and then re-raises, or that swallows
  the error and returns a misleading success — these satisfy the rule yet
  handle errors badly.
- The *content* of the structured error: returning `{"error": "..."}` with no
  `retryable` flag passes the rule but still under-informs the model.
- Exceptions raised in a helper the tool calls, in another module.
- TypeScript LangChain tools — no TS raise/catch predicate is wired.

---

## Recommendations beyond the fix

```python
from langchain_core.tools import tool

@tool
def charge_card(token: str, cents: int, idempotency_key: str) -> dict:
    """Charge a card. Returns {ok, charge_id} or {error, retryable}."""
    try:
        charge = gateway.charge(token, cents, idempotency_key=idempotency_key)
        return {"ok": True, "charge_id": charge.id}
    except gateway.Transient:        # timeout, 503, rate-limit
        return {"error": "payment provider temporarily unavailable",
                "retryable": True}
    except gateway.Declined:         # permanent
        return {"error": "card declined", "retryable": False}
```

1. Return a machine-readable error shape with an explicit `retryable` boolean so
   the model branches instead of guessing.
2. Distinguish transient from permanent failures by exception *type*, not by
   string-matching the message.
3. Scrub internal detail (paths, SQL, stack frames) out of the message that
   reaches the model; log the full detail server-side keyed by a request id.
4. If you keep `handle_tool_error=True` on the executor, still return structured
   payloads from the tool — the executor fallback is a last resort, not a
   contract the model can plan around.
