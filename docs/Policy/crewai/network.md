---
policy_id: crewai_network
category: crewai
topic: network
rules:
  - id: CREW-007
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
references: []
---

# Policy Rationale: CrewAI Tool Network Hygiene

**Policy ID:** `crewai_network`  
**File:** `crewai/network.yaml`  
**Rules:** CREW-007  
**Severities:** high  
**Fix types:** code  
**References:** none

---

## What this policy covers

Network-call hygiene inside CrewAI tools. The policy has one rule, CREW-007,
which applies to Python CrewAI tools (`applies_to: crewai_tool`,
`language: python`, `scope: tool`) that make a network request with no
timeout. The match is `call_without_kwarg` with `missing: timeout` over a
fixed callee list: the `requests` functions `get`, `post`, `put`, `delete`,
`patch`, `head` and `request`; `requests.Session.get` and
`requests.Session.post`; the `httpx` functions of the same seven names;
`urllib.request.urlopen` and bare `urlopen`, which the pack says covers the
from-import form; and `aiohttp.ClientSession.get` and
`aiohttp.ClientSession.post`, the form the pack says aliased aiohttp sessions
canonicalize to.

---

## Why unbounded network calls are a distinct concern in CrewAI tools

A tool that issues an outbound request with no deadline hangs indefinitely on
a slow or unresponsive remote, and the agent that called it stalls with it.

The cost is larger than one stuck agent. In a crew that runs its tasks in
sequence, each task's output is passed forward as context, so a tool stalled
inside one task blocks every task sequenced behind it, and the crew does not
finish while it waits.

The agent's iteration cap does not end the wait. The `max_iter` cap of
[CREW-110](agent_safety.md) bounds how many reasoning steps an agent takes,
not how long a single tool call may run.

---

## Rule-by-rule defense

### CREW-007 — CrewAI tool network call has no timeout (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:**  
A CrewAI tool that calls one of the listed callees without a `timeout`
keyword argument, matched by the predicate `call_without_kwarg` with
`missing: timeout`.

**Why it is flaggable:**  
The mechanism is the one stated
[above](#why-unbounded-network-calls-are-a-distinct-concern-in-crewai-tools):
with no timeout, the request hangs indefinitely on a slow or unresponsive
remote, and the tasks sequenced behind the stalled one wait with it.

**Real-world consequence:**  
A `fetch_order_status` tool calls `requests.get(...)` with no `timeout=`
against an orders API that has stopped answering. The tool never returns, so
the task that called it never completes. In a crew that runs its tasks in
sequence, every task behind it waits, and the crew does not finish.
`max_iter` does not end the wait, because it counts reasoning steps and the
agent is stuck inside a single tool call.

**Why severity is high:**  
The pack sets high and states no reasoning for it.

**Fix type — code:**  
The pack's fix is an edit to the tool source. Pass `timeout=` to the request.
The pack suggests 5–30 seconds: a value tight enough to fail fast and loose
enough for this endpoint's legitimate slow responses. Catch the resulting
timeout so the tool returns a structured error string the agent can reason
about instead of leaving the crew hung.

**Confidence 0.85:**  
The pack sets 0.85 for this rule and names no false-positive or
false-negative scenarios for it. Its comments on the match explain the bare
`urlopen` and aliased aiohttp entries stated above.

---

## What this policy does not cover

- **Callees outside the list.** The match names the callees listed
  [above](#what-this-policy-covers); the pack names no others. For example,
  `requests.Session.put` is not in the list, and neither are the
  `aiohttp.ClientSession` methods other than `get` and `post`.
- **The timeout value.** The match looks for a missing `timeout` keyword; the
  pack states no check on the value passed.
- **Languages other than Python.** The rule is declared for
  `language: python` only.
- The pack states no other limits for this rule.

---

## Recommendations beyond the fix

```python
import requests
from crewai.tools import tool


@tool("fetch_order_status")
def fetch_order_status(order_id: str) -> str:
    """Fetch the shipping status of one order from the orders API, given its ID such as "ord_1042". Returns the status text, or an error string if the API does not answer within 10 seconds."""
    try:
        response = requests.get(
            "https://orders.example.com/api/status",
            params={"order_id": order_id},
            timeout=10,
        )
        response.raise_for_status()
    except requests.Timeout:
        return "Error: orders_api_timeout. The orders API did not answer within 10 seconds."
    except requests.RequestException as exc:
        return f"Error: orders_api_error ({type(exc).__name__})."
    return response.text
```

1. Pass `timeout=` on every outbound request. The pack suggests 5–30 seconds,
   chosen for the endpoint's legitimate slow responses.
2. Catch the timeout and return a structured error string the agent can
   reason about. A `raise` with no `try`/`except` is what
   [CREW-008](error_handling.md) matches.
3. Size `max_iter` to the agent's role and pair it with
   `max_execution_time=`, which CREW-110's fix describes as bounding a slow or
   stalled run in wall-clock seconds (see [agent_safety.md](agent_safety.md)).
   The timeout on the call is still needed: `max_iter` bounds reasoning
   steps, not how long a single tool call may run.
