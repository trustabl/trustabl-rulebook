---
policy_id: claude_sdk_error_handling
category: claude_sdk
topic: error_handling
rules:
  - id: CSDK-005
    severity: low
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM05]
---

# Policy Rationale: Error Handling

**Policy ID:** `claude_sdk_error_handling`  
**File:** `claude_sdk/error_handling.yaml`  
**Rules:** CSDK-005  
**Severities:** low  
**Fix types:** code  
**References:** LLM05

---

## What this policy covers

Claude Agent SDK tools whose body contains a `raise` statement but no
`try`/`except` to convert the failure into a structured result. The match is
`has_raise: true` AND `not has_try_except` — the tool can throw, and nothing
inside it shapes the throw into something the model can act on.

---

## Why error handling is a distinct concern in agent tools

When an ordinary function raises, a developer reads the traceback and fixes the
call. When an agent tool raises, the *model* is the consumer of the failure, and
how the failure is presented decides whether the agent recovers or derails. An
unstructured exception reaches the SDK, which renders it to the model as an opaque
error string. The model cannot tell a transient, retryable failure (timeout,
rate-limit) from a permanent one (bad argument, not-found), so it does the wrong
thing: it retries a permanently-failing call in a loop, or abandons a recoverable
one.

There is a second, quieter hazard: the raised exception's message frequently
carries internal detail — a file path, a SQL fragment, a stack of internal module
names — which is now rendered into the model context and from there into logs,
provider transcripts, and possibly the user-visible answer. A raw exception is
both a control-flow problem (the model can't branch on it) and a mild
information-disclosure one.

The rule maps to OWASP LLM05 (Improper Output Handling): the tool's failure
output is handed to the model unshaped, and unshaped tool output drives
unpredictable agent behavior.

---

## Rule-by-rule defense

### CSDK-005 — Tool raises exceptions without a structured error contract (Severity: low, Confidence: 0.6, Fix type: code)

**What we detect:**
A tool body that contains a `raise` and has no `try`/`except` block
(`has_raise: true`, `has_try_except: false`).

**Why it is flaggable:**
A raised exception reaches the model as an opaque string with no
retryable/permanent signal, so the model cannot branch correctly — and the
message may leak internals.

**Real-world consequence:**
`charge_card(...)` that does `raise ValueError("gateway 503")` on a transient
fault gives the model no "retryable" hint; the model may retry a charge that
actually went through, or give up on one that would have succeeded on retry.

**Why severity is low:**
A bare `raise` is frequently fine: the Claude Agent SDK, an outer wrapper, or a
`failure_error_function`-style handler often converts the exception into something
the model can act on, so this is a reliability-and-hygiene nudge rather than a
defect. It is not medium because the in-body check cannot see those out-of-body
handlers and fires on a great deal of correct code — treat it as a prompt to add
an explicit structured-error contract where one is genuinely missing.

**Fix type — code:**
Wrap the body and return a structured error — a source edit.

**Confidence 0.6:**
The lower confidence reflects real false positives: a tool may deliberately
`raise` a typed exception that an outer SDK handler or `failure_error_function`
converts into structure — safe, but the in-body predicate sees only the bare
`raise`. Equally, a tool with a `try/except` that swallows errors silently passes
the rule while being *worse*. The rule is a prompt to review, not a verdict.

---

## What this policy does not cover

- Tools that raise but have an external handler (`failure_error_function`, an
  outer wrapper) that structures the error — a false positive.
- Tools with a `try/except` that catches and then re-raises, or that swallows the
  error and returns a misleading success — these satisfy the rule yet handle
  errors badly.
- The *content* of the structured error: returning `{"error": "..."}` with no
  `retryable` flag passes the rule but still under-informs the model.
- Exceptions raised in a helper the tool calls, in another module.

---

## Recommendations beyond the fix

```python
from claude_agent_sdk import tool

@tool
def charge_card(token: str, cents: int, idempotency_key: str) -> dict:
    """Charge a card. Returns {ok, charge_id} or {error, retryable}."""
    try:
        charge = gateway.charge(token, cents, idempotency_key=idempotency_key)
        return {"ok": True, "charge_id": charge.id}
    except gateway.Transient as e:        # timeout, 503, rate-limit
        return {"error": "payment provider temporarily unavailable",
                "retryable": True}
    except gateway.Declined as e:         # permanent
        return {"error": "card declined", "retryable": False}
```

1. Return a machine-readable error shape with an explicit `retryable` boolean so
   the model branches instead of guessing.
2. Distinguish transient from permanent failures by exception *type*, not by
   string matching the message.
3. Scrub internal detail (paths, SQL, stack frames) out of the message that
   reaches the model; log the full detail server-side keyed by a request id.
