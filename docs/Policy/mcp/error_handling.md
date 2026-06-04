---
policy_id: mcp_error_handling
category: mcp
topic: error_handling
rules:
  - id: MCP-006
    severity: medium
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM05]
---

# Policy Rationale: Error Handling

**Policy ID:** `mcp_error_handling`  
**File:** `mcp/error_handling.yaml`  
**Rules:** MCP-006  
**Severities:** medium  
**Fix types:** code  
**References:** LLM05

---

## What this policy covers

MCP tool handlers — functions registered via `@server.tool`, `@mcp.tool`, or
`.register_tool` — whose body contains a `raise` statement but no `try`/`except`
to convert the failure into a structured result. The match is `has_raise: true`
AND `not has_try_except` (`has_try_except: false`): the handler can throw, and
nothing inside it shapes the throw into a value the connecting client can act on.
The exception is left to propagate out of the handler and across the MCP
protocol boundary as an opaque error frame.

---

## Why error-contract hygiene is a distinct concern in agent tools

An MCP tool is not called by application code that owns a stack trace; it is
called by an external orchestrator — a model in another process, reached over
the protocol — with fully model-controlled inputs and **no human watching the
exchange**. When an ordinary function raises, a developer reads the traceback
and fixes the call. When an MCP handler raises, the runtime serializes the
exception into a protocol error frame and hands it to that model. There is
nobody to read a Python traceback; the model *is* the error handler, and how the
failure is presented decides whether the agent recovers or derails.

Unshaped, the failure reaches the model as an opaque string with no
machine-readable signal. The model cannot distinguish a transient, retryable
fault (timeout, rate-limit, 503) from a permanent one (bad argument, not-found,
permission denied), so it does the wrong thing: it retries a permanently-failing
call in a loop — burning tokens and, on a side-effecting tool, repeating real
actions — or it abandons a call that would have succeeded on retry. Because the
client is an autonomous orchestrator rather than a human reading a stack trace,
this mis-branching is automatic and unsupervised.

There is a second, sharper hazard at the protocol boundary: the raised
exception's message is content that crosses from the server's trust domain into
the model's context. A `KeyError`, an `OSError`, or a hand-built `RuntimeError`
routinely carries internal detail — an absolute file path, a SQL fragment,
internal module names in the stack, or a secret interpolated into the message
(`f"auth failed for {api_key}"`). Once that propagates as a protocol error it is
rendered into the model context, and from there into provider transcripts, logs,
and possibly the user-visible answer. So an uncaught raise in an MCP handler is
both a control-flow defect (the model cannot branch on it) and an
information-disclosure defect (internals and secrets leak across the boundary to
a caller the server does not control). The idiomatic MCP contract is to
**return** a typed result the model can branch on; an uncaught raise breaks that
contract.

The rule maps to OWASP LLM05 (Improper Output Handling): the tool's failure
output is handed to the model unshaped, and unshaped tool output drives
unpredictable agent behavior.

---

## Rule-by-rule defense

### MCP-006 — Tool raises exceptions without a structured error contract (Severity: medium, Confidence: 0.6, Fix type: code)

**What we detect:**  
An MCP tool handler body that contains a `raise` statement and has no
`try`/`except` block guarding it (`has_raise: true`, `has_try_except: false`).
Both predicates are evaluated against the registered handler's own body; the
finding fires only when a throw is present and nothing in-body catches it.

**Why it is flaggable:**  
A `raise` with no surrounding `try`/`except` means the exception leaves the
handler and is serialized into a protocol error frame for the connecting model.
That frame carries no retryable/permanent signal, so the model cannot branch
correctly, and its message may carry internal detail across the server's trust
boundary. The pattern is a reliable indicator that the handler has no in-body
error contract — it throws and lets the protocol layer expose the raw failure.

**Real-world consequence:**  
A `lookup_account(account_id)` handler that does `return cache[account_id]` and
raises a bare `KeyError` on a miss surfaces the raw `KeyError` — exposing the
internal cache's shape and key naming to the model, which interprets the opaque
string as a hard failure and abandons a request a structured `{"error":
"not_found", "retryable": false}` would have let it handle cleanly. Worse, a
handler that raises `RuntimeError(f"db connect failed: {dsn}")` leaks the
connection string — including any embedded credential — into the model context
and downstream transcripts.

**Why severity is medium and not high:**  
It degrades reliability and leaks minor-to-moderate internals across the
protocol boundary rather than directly breaching the system; a well-behaved
caller environment can absorb some mis-branching, and not every exception
message carries a secret. It is not low because mis-handled errors in
side-effecting MCP tools cause real wrong actions (a retry loop re-running a
write or a charge), and a leaked secret in an exception message is a genuine
disclosure — both are concrete harms, not cosmetic ones.

**Fix type — code:**  
The fix is to wrap the handler body in `try`/`except` and return a structured
error result instead of letting the exception escape — a source edit to the tool
itself. It cannot be applied through a guardrail, hook, or constructor parameter.

**Confidence 0.6:**  
The gap below 0.80 reflects real false positives and false negatives. **False
positive:** some MCP server frameworks wrap a handler's raised exception into a
structured error result transparently (an SDK-level error decorator or
middleware), so a handler may deliberately `raise` a typed exception that the
runtime converts into clean structure before it reaches the client — safe, but
the in-body predicate sees only the bare `raise`. **False negative:** a handler
with a `try`/`except` that catches the exception and then `return`s a bare string
(`return f"error: {e}"`) passes the rule — `has_try_except` is true — yet still
leaks the unstructured message and gives the model no `retryable` flag, so it is
no safer than the raise it replaced. The rule is a prompt to review the error
contract, not a verdict on it.

---

## What this policy does not cover

- Handlers that raise but whose framework wraps the exception into a structured
  error result transparently (an SDK error decorator or middleware) — a false
  positive; the in-body predicate cannot see the external wrapper.
- Handlers with a `try`/`except` that catches and then returns a bare,
  unstructured string (`return str(e)`) or re-raises — these satisfy the rule
  (`has_try_except` is true) yet still leak the message and carry no
  `retryable`/`error-code` signal.
- The *content* of a structured error that is present: returning `{"error":
  "..."}` with no `retryable` flag and no scrubbing passes the rule but still
  under-informs the model and may still leak internals in the message string.
- Exceptions raised in a helper the handler calls in another module — the body
  predicate only inspects the registered handler's own body, so a leak one call
  deep is not detected.
- Handlers that fail by returning a misleading success (swallow-and-continue)
  rather than raising — there is no `raise` to detect, so the rule stays silent
  on a tool that hides failures entirely.

---

## Recommendations beyond the fix

```python
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("accounts")


@mcp.tool()
def lookup_account(account_id: str) -> dict:
    """Look up an account. Returns {ok, account} or {error, retryable}."""
    try:
        account = directory.fetch(account_id)        # may raise
        return {"ok": True, "account": account.public_view()}
    except directory.NotFound:                        # permanent
        return {"error": "account_not_found", "retryable": False}
    except directory.Unavailable:                     # timeout, 503, rate-limit
        return {"error": "directory temporarily unavailable", "retryable": True}
```

1. Return a machine-readable error shape with an explicit `retryable` boolean so
   the model branches deterministically instead of guessing from a free-text
   string.
2. Distinguish transient from permanent failures by exception *type*, not by
   string-matching the message — type-based branching survives wording changes
   and localization.
3. Scrub internal detail (absolute paths, SQL fragments, DSNs, stack frames, and
   any interpolated secret) out of the message that crosses the protocol
   boundary; log the full detail server-side keyed by a request id the client
   never sees.
4. Treat the structured-error shape as part of the tool's published contract:
   document the error codes the handler can return so the calling model (and its
   author) can rely on them, the same way they rely on the success shape.
5. Never let a `try`/`except` swallow a failure into a misleading success —
   returning `{"ok": True}` after a partial failure is worse than raising,
   because it hides the fault from the one consumer (the model) that has no other
   way to see it.
