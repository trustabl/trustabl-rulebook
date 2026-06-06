---
policy_id: autogen_network
category: autogen
topic: network
rules:
  - id: AG2-012
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
references: [LLM10]
---

# Policy Rationale: AutoGen Tool Network Hygiene

**Policy ID:** `autogen_network`  
**File:** `autogen/network.yaml`  
**Rules:** AG2-012  
**Severities:** high  
**Fix types:** code  
**References:** LLM10 (Unbounded Consumption)

---

## What this policy covers

Network-call hygiene inside AutoGen tool functions. **AG2-012** uses the
`call_without_kwarg` predicate: it fires when the tool body calls one of the
`requests.*` or `httpx.*` request functions (`get`, `post`, `put`, `delete`,
`patch`, `head`, `request`) without a `timeout=` keyword argument. A call that
already passes `timeout=` does not fire.

---

## Why a missing timeout is a distinct concern in AutoGen tools

A `requests.get(url)` with no `timeout` blocks until the remote responds or the
connection dies — which, against a slow or hostile server, can be forever.
AutoGen has no tool-level timeout to rescue it: the tool call runs inside the
agent conversation loop, so a hung request stalls the entire agent until the
socket eventually gives up. Under load this exhausts whatever runtime hosts the
agent — threads, connections, the event loop — and the failure never surfaces to
the model, so the agent simply appears to freeze. That is the Unbounded
Consumption (LLM10) failure mode: a single unresponsive endpoint ties up the
agent indefinitely with no upper bound on the wait. In a multi-agent group chat
the stall is worse: one hung tool call can block the whole conversation, not just
one turn.

---

## Rule-by-rule defense

### AG2-012 — Tool network call has no timeout (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:** an AutoGen tool body that calls a `requests.*` / `httpx.*`
request function with no `timeout=` keyword (predicate `call_without_kwarg`).

**Why it is flaggable:** without a timeout the request can hang indefinitely, and
AutoGen has no tool-level timeout — the hung call blocks the agent loop until the
socket dies.

**Real-world consequence:** a `fetch_report(url)` tool calls `requests.get(url)`
with no timeout; a slow upstream makes the agent hang for minutes per call, and
under concurrent load the host runs out of connections while every agent waits.

**Why severity is high:** this matches the timeout rules in every other SDK pack
(CSDK-003, MCP-004, OAI-005, ADK-003, PYD-006), which all rate a missing timeout
high. A hung call with no tool-level timeout stalls the whole agent loop — and, in
a group chat, the whole conversation — and the failure never surfaces to the
model, so the blast radius is the agent's availability, not a single turn. **Fix type — code:** adding
`timeout=` is a tool-source edit. **Confidence 0.85:** the rule looks for the
`timeout` kwarg on the recognized callees, so it over-fires when a timeout is set
another way (a session-level default, an `httpx.Client(timeout=...)` the call
inherits) and under-fires on request libraries outside the recognized
`requests`/`httpx` set (`urllib`, `aiohttp`, a custom client).

---

## What this policy does not cover

- Request libraries other than `requests` / `httpx` — `urllib.request`,
  `aiohttp`, `urllib3`, or a bespoke HTTP client are not in the recognized callee
  set.
- A timeout set through a mechanism other than the per-call `timeout=` kwarg — a
  `requests.Session` default, an `httpx.Client(timeout=...)` the call inherits,
  or a socket-level default — the rule cannot see it and fires anyway.
- Whether the chosen timeout value is *appropriate*. A call with `timeout=600`
  satisfies the rule but still hangs the agent for ten minutes.
- Retries, connection-pool exhaustion, and other resource limits beyond the
  single request timeout.

---

## Recommendations beyond the fix

```python
import requests
from autogen import register_function

def fetch_report(report_id: str) -> str:
    """Fetch a report by ID from the vetted host with a tight timeout."""
    resp = requests.get(
        f"https://api.example.com/reports/{report_id}",
        timeout=10,                       # fail fast on a slow remote
    )
    resp.raise_for_status()
    return resp.text

register_function(fetch_report, caller=assistant, executor=executor,
                  description="Fetch a report by ID.")
```

1. Pass `timeout=` (typically 5–30 seconds) to every request, sized tight enough
   to fail fast and loose enough for legitimate slow responses on that endpoint.
2. Prefer a configured client (`httpx.Client(timeout=...)`) so a default applies
   even where a per-call value is forgotten — but keep an explicit per-call
   timeout on slow endpoints.
3. Surface failures as a structured error the model can react to (retry, fall
   back, report) rather than letting the call hang.
4. Add retry-with-backoff and a circuit breaker for endpoints the agent depends
   on, so a flaky remote degrades gracefully instead of stalling the loop.
