---
policy_id: mcp_network
category: mcp
topic: network
rules:
  - id: MCP-004
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
references: [LLM10]
---

# Policy Rationale: MCP Tool Network Hygiene

**Policy ID:** `mcp_network`  
**File:** `mcp/network.yaml`  
**Rules:** MCP-004  
**References:** LLM10 (Unbounded Consumption)

> Shares the timeout threat model with
> [openai_sdk/network.md](../openai_sdk/network.md). MCP-specific angle only.

---

## What this policy covers

Outbound network calls from inside an MCP tool handler made without a timeout
(`call_without_kwarg` over the `requests` / `httpx` / `urllib` / aliased-`aiohttp` callee set, with a
kwarg present as literal `None` counted as missing).

## Rule-by-rule defense

### MCP-004 — Network call has no timeout (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:** a handler calling an HTTP client method from the recognized
callee list without a `timeout=` argument (or with `timeout=None`).

**Why it is flaggable:** the MCP runtime does not bound tool execution, so a
request to a slow or unresponsive host hangs the handler indefinitely. The
stalled handler blocks the server's reply to the connecting client and ties up
the worker serving that session — unbounded resource consumption triggered by an
ordinary tool call. High severity because the failure stalls the whole session,
not just the one request; confidence 0.85 because the missing-kwarg match is a
structured AST check, with the residual gap being client aliases reached across
function or module boundaries (resolved only within a single function today).

**Fix type — code:** adding `timeout=` is a source edit to the handler.

---

## What this policy does not cover

Retries, circuit breaking, and connection-pool exhaustion; aliased clients
resolved across function/module boundaries; and async HTTP clients whose method
names are not in the callee set.

---

## Recommendations beyond the fix

```python
import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("reports")

# One shared client, one default timeout. A new call site inherits the bound
# instead of having to remember it.
_http = httpx.Client(timeout=httpx.Timeout(10.0, connect=5.0))


@mcp.tool()
def fetch_report(report_id: str) -> dict:
    """Fetch a rendered report by id from the reports service."""
    try:
        # Explicit per-call timeout is the contract MCP-004 checks; the client
        # default above is defense in depth for call sites added later.
        resp = _http.get(f"https://reports.internal/v1/{report_id}", timeout=10.0)
        resp.raise_for_status()
    except httpx.TimeoutException:
        return {"error": "reports service did not respond in time", "retryable": True}
    except httpx.HTTPStatusError as exc:
        return {
            "error": f"reports service returned {exc.response.status_code}",
            "retryable": exc.response.status_code >= 500,
        }
    return {"report": resp.text[:500_000]}
```

The timeout rationale itself is in
[openai_sdk/network.md](../openai_sdk/network.md#recommendations-beyond-the-fix).
MCP-specific additions:

1. Size the handler's timeout against the *client's* patience, not just the
   upstream host's. An MCP client applies its own request deadline; a handler
   that waits 120s for an upstream the client abandoned at 30s leaves the worker
   serving that session busy long after anyone is listening for the answer.
2. Also set a default on a module-level client. MCP-004 matches the call site,
   so a client default does not discharge the rule by itself — but it is what
   bounds the next handler someone adds to the server before review catches a
   missing `timeout=`.
3. Split connect from read (`httpx.Timeout(read, connect=...)`). An unreachable
   host should fail in seconds; a legitimately slow report may need longer.
4. Return the timeout as a structured result rather than letting it raise.
   An exception crosses the MCP boundary as an opaque protocol error the
   connecting model cannot branch on — that is MCP-006's concern
   ([error_handling.md](error_handling.md)), and a timeout is exactly the case
   where the model needs to know the call is worth retrying.
5. Cap the response read. A timeout bounds how long a host may stall; it does
   not bound how much a host that answers promptly and then drips forever may
   send.
