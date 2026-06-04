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
(`call_without_kwarg` over the `requests` / `httpx` / `urllib` callee set, with a
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
