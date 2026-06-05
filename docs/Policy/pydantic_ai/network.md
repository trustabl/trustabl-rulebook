---
policy_id: pydantic_ai_network
category: pydantic_ai
topic: network
rules:
  - id: PYD-006
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: Pydantic AI Tool Network Hygiene

**Policy ID:** `pydantic_ai_network`  
**File:** `pydantic_ai/network.yaml`  
**Rules:** PYD-006  
**Severities:** high  
**Fix types:** code  
**References:** LLM06 (Excessive Agency)

---

## What this policy covers

Network-call hygiene inside Pydantic AI tool functions. **PYD-006** uses the
`call_without_kwarg` predicate: it fires when the tool body calls one of the
`requests.*` or `httpx.*` request functions (`get`, `post`, `put`, `delete`,
`patch`, `head`, `request`) without a `timeout=` keyword argument. A call that
already passes `timeout=` does not fire.

---

## Why a missing timeout is a distinct concern in Pydantic AI tools

A `requests.get(url)` with no `timeout` blocks until the remote responds or the
connection dies — which, against a slow or hostile server, can be forever. The tool
call runs inside the agent's run loop; a request with no timeout blocks that run
until the remote eventually responds or the connection drops, and under load this
ties up whatever runtime hosts the agent without ever surfacing the failure to the
model. The agent simply appears to freeze.

This is an availability/excessive-agency hazard (LLM06): an unbounded external wait
gives a single slow or adversarial endpoint indefinite hold over the agent. The
hazard is sharper in Pydantic AI than in some frameworks because the agent loop is
synchronous from the model's perspective and a hung tool stalls the whole run — and
because Pydantic AI tools frequently call out to APIs the model selects, a
model-chosen slow endpoint can be reached deliberately. That combination is why the
pack rates this **high** rather than the medium a pure reliability lint would
carry: a hung outbound call is both a denial-of-service vector and a lever an
injection can pull.

---

## Rule-by-rule defense

### PYD-006 — Tool network call has no timeout (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:** a Pydantic AI tool body that calls a `requests.*` / `httpx.*`
request function with no `timeout=` keyword (predicate `call_without_kwarg`).

**Why it is flaggable:** without a timeout the request can hang indefinitely, and
the hung call blocks the agent run loop until the socket dies — a denial-of-service
exposure a model-chosen endpoint can trigger on purpose.

**Real-world consequence:** a `fetch_report(url)` tool calls `requests.get(url)`
with no timeout; an injection points it at an endpoint that accepts the connection
and never responds, hanging the agent run indefinitely and, under concurrency,
exhausting the host's connections.

**Why severity is high and not medium:** unlike a pure reliability lint, the hung
call is reachable and triggerable by model-influenced input in an agent whose run
loop blocks on it, so it is both an availability incident and an injection-pullable
lever — the pack rates it high to match that dual exposure. **Fix type — code:**
adding `timeout=` is a tool-source edit. **Confidence 0.85:** the rule looks for the
`timeout` kwarg on the recognized callees, so it over-fires when a timeout is set
another way (a session default, an `httpx.Client(timeout=...)` the call inherits)
and under-fires on request libraries outside the recognized `requests`/`httpx` set.

---

## What this policy does not cover

- Request libraries other than `requests` / `httpx` — `urllib.request`, `aiohttp`,
  `urllib3`, or a bespoke HTTP client are not in the recognized callee set.
- A timeout set through a mechanism other than the per-call `timeout=` kwarg — a
  `requests.Session` default, an `httpx.Client(timeout=...)` the call inherits, or a
  socket-level default — the rule cannot see it and fires anyway.
- Whether the chosen timeout value is *appropriate*. A call with `timeout=600`
  satisfies the rule but still hangs the agent run for ten minutes.
- *Where* the request goes — a model-controlled destination is the separate SSRF
  concern of **PYD-005** (ssrf.md). PYD-006 is only about the missing timeout.

---

## Recommendations beyond the fix

```python
import requests
from pydantic_ai import Agent

agent = Agent("openai:gpt-4o")

@agent.tool_plain
def fetch_report(report_id: str) -> str:
    """Fetch a report by ID from the vetted host with a tight timeout."""
    resp = requests.get(
        f"https://api.example.com/reports/{report_id}",
        timeout=10,                       # fail fast on a slow remote
    )
    resp.raise_for_status()
    return resp.text
```

1. Pass `timeout=` (typically 5–30 seconds) to every request, sized tight enough to
   fail fast and loose enough for legitimate slow responses on that endpoint.
2. Prefer a configured client (`httpx.Client(timeout=...)`) so a default applies
   even where a per-call value is forgotten — but keep an explicit per-call timeout
   on slow endpoints.
3. Surface failures as a structured error the model can react to (retry, fall back,
   report) rather than letting the call hang.
4. Pair the timeout with the SSRF guard from PYD-005 — a model-callable fetch needs
   both a bounded wait and a constrained destination.
