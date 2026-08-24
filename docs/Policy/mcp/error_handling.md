---
policy_id: mcp_error_handling
category: mcp
topic: error_handling
rules:
  - id: MCP-006
    severity: low
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM05]
---

# Policy Rationale: MCP Error Contract Hygiene

**Policy ID:** `mcp_error_handling`  
**File:** `mcp/error_handling.yaml`  
**Rules:** MCP-006  
**References:** LLM05 (Improper Output Handling)

> Shares the structured-error threat model with
> [openai_sdk/error_handling.md](../openai_sdk/error_handling.md). MCP-specific
> angle only.

---

## What this policy covers

An MCP tool handler that can raise without catching, detected by
`all: [has_raise: true, has_try_except: false]`.

## Rule-by-rule defense

### MCP-006 — Tool raises exceptions without a structured error contract (Severity: low, Confidence: 0.6, Fix type: code)

**What we detect:** a handler body that contains a `raise` and no `try`/`except`.

**Why it is flaggable:** when an MCP tool handler raises, the runtime surfaces the
exception to the connecting client as an opaque protocol error. The model on the
other end often cannot recover or retry intelligently, and the raw message may
leak internal detail — stack frames, absolute paths, secrets in arguments —
across the server's trust boundary to whatever client connected (improper output
handling, LLM05). Low severity because the impact is degraded recovery plus a
modest disclosure channel, and a handler often raises intentionally for a caller
or runtime that structures it; confidence 0.6 because the body-only check does
not see a `try` in a calling frame.

**Fix type — code:** returning a structured `{"error": ..., "retryable": ...}`
result instead of raising is a source edit.

---

## What this policy does not cover

Whether the raised message actually contains sensitive data; exception handling
done by a wrapping frame outside the handler body; and the TypeScript MCP error
surface (no TS raise/catch predicate is wired).

---

## Recommendations beyond the fix

```python
import logging

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("billing")
log = logging.getLogger(__name__)
_http = httpx.Client(timeout=10.0)


@mcp.tool()
def get_invoice(invoice_id: str) -> dict:
    """Look up an invoice by id. Returns the invoice, or a structured error."""
    try:
        resp = _http.get(f"https://billing.internal/v1/invoices/{invoice_id}")
        resp.raise_for_status()
    except httpx.TimeoutException:
        return {"error": "billing service timed out", "code": "upstream_timeout",
                "retryable": True}
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return {"error": f"no invoice {invoice_id}", "code": "not_found",
                    "retryable": False}
        # Full detail to the server's log; a summary to the caller.
        log.exception("billing lookup failed for %s", invoice_id)
        return {"error": "billing service unavailable", "code": "upstream_error",
                "retryable": exc.response.status_code >= 500}
    return {"invoice": resp.json()}
```

The structured-error rationale is in
[openai_sdk/error_handling.md](../openai_sdk/error_handling.md#recommendations-beyond-the-fix).
MCP-specific additions:

1. Treat the error payload as a published interface, not a debug string. An MCP
   server does not know which client or model will connect to it, so a stable
   `code` field is the only thing a caller can branch on reliably — the prose in
   `error` will be read by a model, but should never be the thing it keys on.
2. Say whether a retry could succeed. An MCP client that cannot tell a
   permanent failure from a transient one will either retry a `404` forever or
   give up on a timeout that would have cleared, and for a mutating tool that
   first mistake is the one idempotency has to absorb
   ([idempotency.md](idempotency.md)).
3. Keep the exception on the server side of the boundary. Log the traceback
   with the session identifier and return a summary; the raw message is what
   carries absolute paths, internal hostnames, and argument values across to
   the client (LLM02).
4. Distinguish a *tool* failure from a *protocol* failure. A tool that could not
   do its job has produced a legitimate result the model should reason about;
   an exception escaping the handler is reported as the call itself failing,
   which is a different thing and worth reserving for genuine bugs.
5. Do not catch what you cannot describe. A bare `except Exception: return
   {"error": "failed"}` silences MCP-006 without giving the caller anything more
   than the traceback did — catch the failure modes you can name, and let a
   programmer error crash loudly enough to reach your logs.
