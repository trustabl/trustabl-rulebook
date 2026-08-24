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
**Severities:** high  
**Fix types:** code  
**References:** LLM10 (Unbounded Consumption)

> Shares the timeout threat model with
> [openai_sdk/network.md](../openai_sdk/network.md). This document covers the
> MCP-specific mechanism: a handler that blocks holds the session's reply
> channel, not just its own request.

---

## What this policy covers

Python MCP tool handlers (`applies_to: mcp_tool`) that call an outbound HTTP
client without a timeout. The match is `call_without_kwarg` with
`missing: timeout` over a fixed callee set: the `requests` module functions
(`get`, `post`, `put`, `delete`, `patch`, `head`, `request`), `requests.Session.get`
and `requests.Session.post`, the `httpx` module functions, `urllib.request.urlopen`
and bare `urlopen`, and `aiohttp.ClientSession.get` and `aiohttp.ClientSession.post`
(aliased sessions canonicalize to that form). A `timeout` kwarg present with a
literal `None` counts as missing, since `None` disables the timeout rather than
setting one.

---

## Why unbounded network calls are a distinct concern in agent tools

A conventional web application bounds a hung outbound call at several layers it
gets for free. The application server enforces a request timeout and kills the
worker. A reverse proxy returns 504 upstream. The browser gives up and the user
reloads. The blast radius of a missing `timeout=` is one request that eventually
fails.

An MCP server has none of that. The handler runs inside the server process with
no execution bound imposed by the runtime. When `requests.get()` blocks on a host
that accepts the TCP connection and then never responds, the call does not fail;
it waits. On Linux, a `requests` call with no timeout inherits the OS socket
default, which can leave the handler blocked for minutes or indefinitely. The
`tools/call` that triggered it never returns a result.

The connecting client is holding that session open. Over stdio there is one
process serving one session, and a blocked handler stops the server responding
to anything, including tool calls the model has already queued. Over SSE or
Streamable HTTP the worker serving that session is tied up for the duration.
Either way the stall is scoped to the session, not to the one tool call, which
is what separates this from the same bug in a normal API client.

The model then makes it worse. It has no signal distinguishing "this tool is
slow" from "this tool is hung", because both look identical from its side:
nothing came back. If the host times out at the transport layer and the model
re-issues the call, a second handler blocks on the same unresponsive host while
the first is still waiting. Each retry consumes another worker and none of them
are released. That is OWASP LLM10 (Unbounded Consumption): an ordinary tool
invocation, against a host the tool author does not control, exhausts server
capacity with no attacker action required beyond being slow to answer.

---

## Rule-by-rule defense

### MCP-004 — Network call has no timeout (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:**  
A call to one of the listed HTTP client callees where the `timeout` keyword
argument is absent from the call site, or is present with a literal `None`.
This is a structural check on the call's keyword arguments, not a search of the
handler body text. It resolves aliases within a single function, so
`s = aiohttp.ClientSession(); s.get(url)` canonicalizes to
`aiohttp.ClientSession.get`.

**Why it is flaggable:**  
Every callee in the list defaults to no timeout when the argument is omitted.
`requests` and `urlopen` fall back to the OS socket timeout, which on most
systems is effectively unbounded. The absence of the kwarg is therefore not a
style issue; it is the mechanism by which the handler can block forever.

**Real-world consequence:**

- A `fetch_page(url)` tool calls `requests.get(url)` against a host that
  accepts the connection and stops sending. The handler never returns, the
  `tools/call` never completes, and over stdio the server stops answering the
  client entirely.
- A tool calling a third-party API during that API's outage blocks one worker
  per invocation. The model retries on transport timeout, and each retry
  consumes another worker while the earlier ones are still waiting.
- A tool that fetches a model-supplied URL lets the model choose an endpoint
  that never responds, converting a routine call into a session-level stall.

**Why severity is high and not medium:**  
The damage is not confined to the failing call. The handler holds the reply
channel for the session, so one hung request degrades every subsequent tool
call in that session, and under stdio it halts the server. There is also no
partial mitigation available outside the tool: the MCP runtime imposes no
execution bound, so nothing upstream of the handler will terminate it. Medium
would be appropriate if the failure were contained to the one call, which is
exactly the assumption that does not hold here.

**Fix type — code:**  
The timeout must be supplied at the call site (or at client construction and
threaded through), which is a source edit to the handler. No host
configuration, sandbox policy, or agent constructor parameter can inject a
timeout into a call that does not accept one.

**Confidence 0.85:**  
The gap is not uncertainty about the mechanism; a missing `timeout` on these
callees genuinely means no timeout. It reflects the limits of the callee list
and of single-function alias resolution. **False positives:** a timeout
configured at client construction rather than at the call site, such as
`httpx.Client(timeout=10.0)` or
`aiohttp.ClientSession(timeout=ClientTimeout(total=10))`, satisfies the concern
but leaves the call site bare, so the rule fires on safe code. The same applies
to a `requests.Session` with a custom transport adapter that enforces a timeout,
and to a call already wrapped in `asyncio.wait_for(...)`. **False negatives:** a
client aliased across a function or module boundary is not resolved, so a helper
that returns a configured session hides the call from the rule.

---

## What this policy does not cover

- **Session methods outside `get` and `post`.** The callee list includes
  `requests.Session.get` and `requests.Session.post` but not `Session.put`,
  `Session.delete`, `Session.patch`, `Session.head`, or `Session.request`. A
  mutating call through a session is a false negative.
- **`aiohttp` verbs outside `get` and `post`.** `aiohttp.ClientSession.put`,
  `.delete`, and `.patch` are not listed, so async mutating calls escape.
- **Instance-level `httpx` calls.** The list covers the module-level `httpx.get`
  and friends, not `httpx.Client(...).get(...)` or `httpx.AsyncClient`. It also
  omits `httpx.stream`.
- **HTTP clients outside the list entirely.** `urllib3` used directly,
  `http.client`, `pycurl`, and vendored SDK clients (`boto3`, `openai`,
  `stripe`) all make outbound calls the rule never inspects, and several default
  to their own timeouts, which is why they are excluded rather than an oversight.
- **Non-HTTP blocking.** Raw sockets, database drivers, gRPC channels, and
  filesystem calls on network mounts stall a handler identically and are out of
  scope for this policy.
- **Whether the timeout value is sensible.** `timeout=600` satisfies the rule
  and still stalls the session for ten minutes. The rule checks presence, not
  magnitude.
- **What happens after the timeout fires.** A handler that catches the timeout
  and retries in a loop without a ceiling passes this rule and reproduces the
  original failure. See MCP-006 for the related concern of surfacing the failure
  as a structured error rather than an opaque exception.
- **TypeScript MCP tools.** MCP-004 is `language: python`; `fetch` in a TS
  handler has no timeout by default and has no sibling rule in
  `mcp/network.yaml`.

---

## Recommendations beyond the fix

```python
import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetcher")

# One client, one explicit timeout budget, reused across calls.
_client = httpx.Client(
    timeout=httpx.Timeout(connect=3.0, read=10.0, write=10.0, pool=3.0),
    limits=httpx.Limits(max_connections=10),
)


@mcp.tool()
def fetch_page(url: str) -> dict:
    """Fetch a URL and return its text. Times out rather than stalling the
    session; the caller receives a structured error it can act on."""
    try:
        response = _client.get(url, timeout=10.0)
        response.raise_for_status()
    except httpx.TimeoutException:
        return {"ok": False, "error": "timeout", "url": url}
    except httpx.HTTPStatusError as exc:
        return {"ok": False, "error": "http_status",
                "status": exc.response.status_code, "url": url}
    return {"ok": True, "status": response.status_code, "text": response.text}
```

1. Set the timeout at the call site even when the client already carries one.
   It costs nothing, it survives refactors that swap the client, and it is what
   this rule can actually see.
2. Split connect and read budgets rather than passing a single number. A host
   that refuses to connect should fail in seconds; a large download legitimately
   needs longer to read.
3. Return the timeout as a structured tool result, not an uncaught exception.
   An opaque protocol error gives the model nothing to reason about and invites
   a blind retry, which is how one slow host becomes several blocked workers
   (see MCP-006).
4. Cap concurrency with `httpx.Limits` or an equivalent pool bound, so that
   even correctly timed-out calls cannot occupy every worker at once during an
   upstream outage.
5. Never pass `timeout=None` to silence the rule. It disables the timeout
   entirely and is treated as missing by design.