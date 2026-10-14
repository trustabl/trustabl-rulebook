---
policy_id: mcp_observability
category: mcp
topic: observability
rules:
  - id: MCP-023
    severity: medium
    confidence: 0.7
    scope: tool
    fix_type: code
references: []
---

# Policy Rationale: MCP Tool Observability Hygiene

**Policy ID:** `mcp_observability`  
**File:** `mcp/observability.yaml`  
**Rules:** MCP-023  
**Severities:** medium  
**Fix types:** code  
**References:** none

> The same `has_print_call` predicate backs the per-SDK stdout rules, such as
> CSDK-019 in [claude_sdk/observability.md](../claude_sdk/observability.md) and
> OAI-010 in [openai_sdk/observability.md](../openai_sdk/observability.md).
> This document covers the MCP server case: on a stdio server, stdout is the
> protocol channel.

---

## What this policy covers

How an MCP tool handler emits diagnostics. The policy has one rule, MCP-023,
which applies to Python MCP tool handlers (`applies_to: mcp_tool`,
`language: python`, `scope: tool`) and matches a handler whose body contains a
print call (`has_print_call: true`). The print writes to the process's stdout,
which on a stdio server is the channel the client reads protocol messages from.

---

## Why stdout diagnostics are a distinct concern in MCP servers

On an MCP server using the stdio transport, stdout is not a log sink. It is the
protocol channel: the client reads newline-delimited JSON-RPC messages from it.
The pack names stdio as the default transport for FastMCP, and as a way an
editor or desktop client launches a server.

A `print()` in a tool handler therefore does not write a log line. It writes
into the JSON-RPC frame stream. The loose line interleaves with the frames, and
the client hits a parse error on a line that is not JSON. Depending on the
client, it drops the response, logs a protocol error, or tears down the
connection.

The failure does not look like the cause. The symptom is a tool call that
returns nothing, or a server that disconnects mid-session. The print that broke
it reads like harmless debugging.

A server run over HTTP or SSE escapes the corruption, but the diagnostic is
still lost: the model never sees stdout, only the tool's return value.

---

## Rule-by-rule defense

### MCP-023 — MCP tool prints to stdout, corrupting a stdio transport (Severity: medium, Confidence: 0.7, Fix type: code)

**What we detect:**
A Python MCP tool handler whose body calls `print()`, matched by the predicate
`has_print_call: true`.

**Why it is flaggable:**
The call writes to the process's stdout. On a stdio server that is the channel
carrying the client's JSON-RPC messages, so the print writes a line that is not
JSON into the protocol stream. Over HTTP or SSE the diagnostic is still lost,
because the model never sees stdout, only the return value.

**Real-world consequence:**
- A FastMCP server is launched over stdio by a desktop client. A handler prints
  a debug line. The client hits a parse error on that line and, depending on
  the client, drops the response or tears down the connection. The symptom is a
  tool call that returns nothing, or a server that disconnects mid-session.
- The same server runs over HTTP. The protocol stream is not corrupted, but the
  printed diagnostic never reaches the model, which only sees the return value.

**Fix type — code:**
The fix is an edit to the handler source: remove the `print()`, emit
diagnostics through a module logger on stderr, and return anything the model
needs as part of the tool's result.

**Confidence 0.7:**
The pack sets confidence at 0.7 for this rule. It states no known false
positives, false negatives, or other limits for MCP-023.

---

## What this policy does not cover

- **Code outside a tool handler.** MCP-023 is tool-scoped. A print elsewhere in
  the server process is outside this rule.
- **Languages other than Python.** The rule is declared for `language: python`
  only, and `mcp/observability.yaml` has no rule for other languages.
- **The transport.** The match is the print call alone. Whether the server
  actually runs over stdio is not part of the match.
- **Logging configured onto stdout.** The fix warns against reconfiguring
  logging onto stdout, but the match is `has_print_call` only. A logger whose
  handler writes to stdout is not part of the match.
- **What the print contains.** The pack does not address the content of the
  printed output, so this document attaches no OWASP reference.

---

## Recommendations beyond the fix

```python
import logging
import sys

from mcp.server.fastmcp import FastMCP

# Diagnostics go to stderr, which the stdio transport leaves alone.
logging.basicConfig(stream=sys.stderr, level=logging.INFO)
logger = logging.getLogger(__name__)

mcp = FastMCP("orders")


@mcp.tool()
def lookup_order(order_id: str) -> dict:
    """Look up one order by its ID and return its status and total."""
    row = ORDERS.get(order_id)
    # Operator diagnostics: a module logger on stderr, never print().
    logger.info("lookup_order order_id=%s found=%s", order_id, row is not None)
    # Model-facing information: the return value.
    if row is None:
        return {"ok": False, "error": "not_found", "order_id": order_id}
    return {"ok": True, "order": row}


if __name__ == "__main__":
    mcp.run()
```

1. **Log through a module logger on stderr.** Use
   `logging.getLogger(__name__)` with a `StreamHandler` on `sys.stderr`. The
   transport leaves stderr alone.
2. **Keep logging off stdout everywhere in the process.** Make sure nothing in
   the process reconfigures logging onto stdout. MCP-023 matches print calls
   only, so it does not flag a logger configured onto stdout.
3. **Put model-facing information in the return value.** If the model needs the
   information, return it as part of the tool's result. The model never sees
   stdout, only the return value.
