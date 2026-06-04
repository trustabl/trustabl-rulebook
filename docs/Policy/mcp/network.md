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
**References:** LLM10

---

## What this policy covers

This policy targets outbound HTTP calls made from inside an MCP tool handler —
a function registered with `@server.tool`, `@mcp.tool`, or `.register_tool`.
Detection is the `call_without_kwarg` predicate over the `requests.*` /
`httpx.*` / `urllib.request.urlopen` callee families: `requests.get / post /
put / delete / patch / head / request`, the `requests.Session.get / post`
aliases, `httpx.get / post / put / delete / patch / head / request`, and
`urllib.request.urlopen` (or the bare `urlopen` import). The rule fires when one
of those callees is invoked from a discovered MCP tool body with no `timeout=`
keyword argument — the kwarg absent, or present with a literal `None`, both
count. The MCP runtime never injects a timeout itself, so a missing timeout is
directly observable in source.

---

## Why network timeouts are a distinct concern in agent tools

An MCP tool does not run inside a request the developer can cancel. It runs
inside an MCP server that is invoked by an **external orchestrator** — a Claude
Desktop client, an IDE agent, another team's agent loop — with inputs the model
produces from conversation context, frequently with **no human in the loop** on
the individual tool call. The author of the tool and the operator of the
orchestrator are usually different people, so the tool body is the only place
the failure can be bounded, and it has been left unbounded.

When a handler calls `requests.get(url)` with no timeout, the call blocks on a
stalled socket until the kernel gives up. `requests` and `httpx` default to no
timeout, and `urllib`'s `urlopen` defaults to `socket._GLOBAL_DEFAULT_TIMEOUT`,
which is `None` unless someone called `socket.setdefaulttimeout()` at process
start — almost nobody does. The practical default on Linux is the system
`tcp_syn_retries` timeout: multiple minutes of dead air. For that entire window
the tool invocation produces nothing, and the connecting client's
request-response exchange with the server cannot complete.

The blast radius is larger than one stalled fetch, and that is the
MCP-specific angle. An orchestrator that does not hear back from a tool call
commonly **retries** it, or **fans out** several tool calls concurrently as the
model explores — so one slow upstream dependency does not stall one invocation,
it stalls several. Worse, an MCP server is frequently **shared across multiple
connected clients**: a single hung upstream dependency can occupy the worker(s)
serving every connected agent, so the failure of one third-party endpoint
degrades availability for every consumer of the server, not just the agent that
triggered it. This is the unbounded-consumption shape — OWASP LLM Top 10:2025
**LLM10 (Unbounded Consumption)**: a model-driven, retry-prone caller plus a
server with no per-call wall clock turns one slow host into a resource-exhaustion
condition no orchestrator-side timeout was guaranteed to catch.

---

## Rule-by-rule defense

### MCP-004 — Network call has no timeout (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:**
An MCP tool handler (`@server.tool` / `@mcp.tool` / `.register_tool`) whose body
invokes `requests.get / post / put / delete / patch / head / request`, a
`requests.Session.get / post` alias, `httpx.get / post / put / delete / patch /
head / request`, or `urllib.request.urlopen` / the bare `urlopen` — with no
`timeout=` keyword argument on that call. A `timeout=` present but set to a
literal `None` counts as missing.

**Why it is flaggable:**
Every client in the callee set defaults to no timeout. Without one, a stalled
socket pins the handler until the kernel times the connection out, and because
the MCP runtime imposes no wall clock on tool code, the server's reply to the
connecting client is blocked for the full OS TCP timeout — minutes, not seconds.
The pattern is therefore a direct, mechanical indicator that one slow upstream
host can stall the tool invocation indefinitely.

**Real-world consequence:**
- A `fetch_page(url)` MCP tool that calls `requests.get(url)` on a model-supplied
  URL hangs the invocation when the URL points at a slow or non-responsive host.
  The connecting agent sees no result and commonly retries, multiplying the held
  workers.
- Because the server is shared, a second agent connected to the same MCP server
  for an unrelated tool finds its calls queued behind the workers stuck on the
  first agent's dead host — one external dependency outage becomes a server-wide
  stall (LLM10, unbounded consumption).

**Why severity is high and not medium:**
The failure mode is denial of the tool invocation — and, on a shared server, of
the server itself — not a slow or lower-quality response. There is no partial,
in-band mitigation: without an explicit `timeout=`, the kernel default applies,
and the kernel default is "minutes." Medium is reserved for issues that degrade
output quality; this one removes availability for every client of the server, so
it is scored high.

**Fix type — code:**
The fix is a source-level `timeout=` kwarg on the call. No guardrail, hook, or
sandbox parameter can inject a timeout into an already-running socket wait, and
the MCP runtime does not expose a per-tool wall clock to configure externally, so
the tool body is the only place the bound can be applied.

**Confidence 0.85:**
The gap is a small set of false-positive and false-negative cases. False
positive: a `requests.Session` (or `httpx.Client`) configured with a default
timeout on the *session/client object* — via a mounted adapter or the client
constructor — and then used through a `.get(...)` call site that carries no
kwarg; the predicate sees a bare call and fires even though the session enforces
a bound. False negative: a request made through a cross-module helper (the tool
calls `do_fetch(url)`, which performs the timeout-less request in another file)
— the predicate inspects the tool body directly and does not follow calls into
other modules — and a timeout passed positionally (`urlopen(req, None, 10)`),
which `call_without_kwarg` does not see. These are uncommon enough relative to
the bare call-site form to keep the rule above 0.8 rather than dropping it
toward the SSRF rules' lower band.

---

## What this policy does not cover

- **Other HTTP clients.** `aiohttp` (notably — async MCP handlers commonly use it
  and it is **not** in the callee set), `urllib3` used directly, raw
  `socket.create_connection`, `pycurl`, gRPC stubs, and custom transports all
  make outbound calls the predicate never inspects.
- **Session/client-level timeouts.** A timeout configured on a
  `requests.Session`, an `httpx.Client(timeout=...)`, or a mounted adapter is a
  real bound, but the call site that uses it carries no `timeout=` kwarg, so the
  rule fires anyway (false positive) — and conversely a developer who reads this
  finding may "fix" only the flagged call while a sibling call through the same
  unbounded client stays exposed.
- **Library or process defaults.** A process that calls
  `socket.setdefaulttimeout(30)` at startup does bound `urlopen`, but the rule
  cannot see that global and still flags the bare call; treat the call-site
  `timeout=` as the contract regardless.
- **Unreasonable-but-present timeouts.** A `timeout=3600` is functionally no
  bound for an interactive agent, but the rule treats any `timeout=` kwarg as a
  pass and will not flag it.
- **Transitive calls.** When the tool body calls a helper that performs the
  request without a timeout, the body-only walk does not follow into the helper
  and the rule stays silent.
- **Retry-without-backoff storms.** A handler that times out cleanly but retries
  in a tight loop is still an unbounded-consumption hazard; that is idempotency /
  retry territory, not this timeout policy.

---

## Recommendations beyond the fix

```python
import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetch-server")

# One shared client with a default timeout, so every tool inherits the bound
# even if a future call site forgets the per-call kwarg.
_client = httpx.Client(timeout=httpx.Timeout(15.0, connect=5.0))

@mcp.tool()
def fetch_page(url: str) -> dict:
    """Fetch a URL and return its text content (capped)."""
    try:
        resp = _client.get(url, timeout=15.0)  # explicit per-call bound, belt and braces
        resp.raise_for_status()
    except httpx.TimeoutException:
        # Return a structured tool error rather than letting the handler block
        # or raising an opaque traceback the orchestrator cannot branch on.
        return {"error": "upstream timed out", "url": url, "retryable": False}
    except httpx.HTTPError as exc:
        return {"error": str(exc), "url": url, "retryable": False}
    body = resp.text[:500_000]  # cap the read so a slow-drip server cannot exhaust memory
    return {"content": body or "[empty response]"}
```

1. **Set the timeout on a shared client, not only at the call site.** A
   module-level `httpx.Client(timeout=...)` / `requests.Session` gives every
   handler a default bound, so a new tool that forgets the per-call kwarg still
   inherits one — closing the false-negative the rule cannot see.
2. **Return timeouts as structured tool errors.** Catch the timeout and return a
   JSON-serializable error the orchestrator can branch on, rather than letting
   the handler block or surfacing a raw traceback — an unhandled hang reads to
   the model as silence and invites a retry.
3. **Bound the connect phase separately.** Use `httpx.Timeout(read, connect=...)`
   (or `requests` `(connect, read)` tuple) so a host that never completes the TCP
   handshake fails fast, independent of the read budget.
4. **Cap the response read.** `resp.text[:N]` / `resp.read(N)` prevents a
   slow-drip or oversized response from exhausting the worker's memory even when
   the connection itself is timely — a second unbounded-consumption vector the
   timeout alone does not close.
5. **Validate the destination before calling.** Confirm the scheme is `http(s)`
   and the host is on an allow-list before issuing the request; on a shared MCP
   server, a model-supplied URL is an SSRF vector into whatever internal network
   the server's egress can reach.
6. **Keep timeouts tight enough to free workers under load.** On a server shared
   across clients, a generous timeout still holds a worker for that whole window;
   size the bound to the endpoint's real latency budget so a dead dependency
   releases the worker quickly.
