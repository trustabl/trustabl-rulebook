---
policy_id: langchain_network
category: langchain
topic: network
rules:
  - id: LC-007
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
references: [LLM10]
---

# Policy Rationale: LangChain Tool Network Hygiene

**Policy ID:** `langchain_network`  
**File:** `langchain/network.yaml`  
**Rules:** LC-007  
**Severities:** high  
**Fix types:** code  
**References:** LLM10 (Unbounded Consumption)

> Shares the timeout / unbounded-consumption framing with
> [autogen/network.md](../autogen/network.md) and
> [mcp/network.md](../mcp/network.md). This document covers the LangChain
> Requests-specific rule only.

---

## What this policy covers

Network-call hygiene inside LangChain Python tool functions. **LC-007** uses the
`call_without_kwarg` predicate: it fires when a discovered `langchain_tool` body
invokes a `requests` HTTP method (`get`, `post`, `put`, `delete`, `patch`,
`head`, `request`) — including the `requests.Session.*` forms — without a
`timeout=` keyword argument. A call that already passes a finite `timeout=` does
not fire. Literal `timeout=None` is treated as missing (same engine behavior as
sibling packs). This initial rule is **Requests-specific**; `httpx`, `urllib`,
and `aiohttp` are out of scope.

---

## Why network hygiene is a distinct concern in LangChain tools

In a LangChain agent the model selects which tool to invoke and with what
arguments. The tool body then runs to completion before the agent step can
advance. When that body issues a `requests` call with no finite timeout, and the
upstream fails to respond, the Requests client has no deadline: the tool stays
blocked, the agent step cannot complete, and whatever worker or event-loop slot
is serving the run remains occupied.

Failure chain (reliability / availability / bounded execution — not a guaranteed
hang or compromise):

LangChain agent → model selects tool → `@tool` → Requests call → upstream fails
to respond → no finite timeout → tool blocked → agent step cannot complete →
workers / resources consumed.

Consequences under load: stalled tool execution, uncontrolled latency, worker
and connection-pool exhaustion, cascading degradation when many concurrent agent
turns share the same host, and agent workflow failure when the turn budget is
spent waiting on one socket.

This is sharper in an agentic loop than in a conventional request handler. A
normal API call often has a parent deadline or client cancel path; a LangChain
tool invocation typically does not. The model also cannot branch on a failure it
never sees — the step simply does not return — so retries and fallback tools
never run until the OS finally drops the connection.

**Timeout versus retry:** a `timeout=` bounds a single request *attempt*. Retry
logic decides what happens *after* an attempt fails. Retries do not replace a
finite request timeout; without one, each attempt can still block indefinitely
before any retry policy applies.

**HTTPX note:** this rule does **not** claim that `httpx.get(url)` is unsafe
merely because `timeout=` is omitted. HTTPX supplies a default timeout. Alternate
HTTP libraries are outside this initial Requests-specific rule.

The OWASP LLM Top 10:2025 anchor is **LLM10 (Unbounded Consumption)**: one
unresponsive dependency can consume unbounded wall-clock and host resources
through an ordinary tool call.

---

## Rule-by-rule defense

### LC-007 — LangChain tool network call has no timeout (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:**  
A LangChain Python tool (`@tool`, `StructuredTool.from_function`, or equivalent
`langchain_tool` discovery) whose body calls `requests.get` / `post` / `put` /
`delete` / `patch` / `head` / `request`, or the matching `requests.Session.*`
methods, without a `timeout=` keyword (predicate `call_without_kwarg`,
`missing: timeout`). Literal `timeout=None` counts as missing.

**Why it is flaggable:**  
`requests` without an explicit timeout waits until the remote responds or the
connection dies. Inside a LangChain tool there is no framework-injected per-call
deadline, so that wait stalls the tool invocation and the agent step that depends
on it — unbounded consumption of the worker serving the run.

**Real-world consequence:**  
- A `fetch_report(report_id)` `@tool` calls `requests.get(...)` with no timeout;
  a slow upstream leaves the tool blocked and the ReAct / agent step unfinished.
- Under concurrent agent turns, many such blocked tools exhaust connection or
  worker pools and degrade neighboring workflows.
- The model never receives a structured timeout error, so it cannot fall back,
  skip, or report — the workflow fails by stall rather than by handled exception.

**Why severity is high and not medium:**  
Sibling timeout rules across packs (MCP-004, AG2-012, OAI-005, ADK-003, PYD-006)
rate a missing request timeout **high** because the blast radius is agent
availability, not a single slow response. Medium would fit degraded output
quality; here the agent step may not complete at all while resources remain
held. There is no partial in-band mitigation once the unbounded call is in
flight.

**Fix type — code:**  
Adding an explicit finite `timeout=` (and handling the resulting exception) is a
tool-source edit. No LangChain constructor flag, guardrail, or sandbox policy
injects a deadline into an already-running `requests` call.

**Confidence 0.85:**  
The residual gap is structural, not semantic: the predicate recognizes the
`timeout` *keyword* on listed callees inside the tool body. It can over-fire when
a timeout is applied outside the call site (Session defaults, wrappers) and
under-fire on positional forms, helpers, and libraries this rule deliberately
excludes — see limitations below. That calibration matches the other
`call_without_kwarg` timeout rules at 0.85.

---

## What this policy does not cover

Honest engine / scope limitations for LC-007:

- **Positional timeout** — `requests.get(url, 10)` may not be recognized by
  `call_without_kwarg`, which looks for the `timeout=` keyword.
- **Session / client-level wrappers** — a timeout configured on a
  `requests.Session` (or similar) may not be visible at the per-call site, so the
  rule can still fire.
- **Helper / wrapper functions** — a call that goes through a local helper which
  injects `timeout=` can escape detection if the tool body only shows the helper
  call.
- **Dynamically configured timeouts** — values built at runtime and not present
  as a static `timeout=` kwarg may not be statically resolvable.
- **Alternate HTTP libraries** — `httpx`, `urllib`, and `aiohttp` are outside this
  Requests-specific initial rule (HTTPX in particular already defaults to a
  timeout; do not treat a bare `httpx.get(url)` as LC-007).
- **Alias / interprocedural limits** — inherited from the engine: aliases and
  callees resolved only within the scanned function boundary may miss or
  over-match across modules.

Also out of scope (by design, not engine blind spots):

- Whether the chosen finite timeout value is *appropriate* for the upstream SLA —
  any finite `timeout=` satisfies the predicate.
- Destination control / SSRF — covered separately by
  [langchain/ssrf.md](ssrf.md) (LC-005 / LC-013).
- Retry policy quality, circuit breakers, and connection-pool sizing beyond the
  single-attempt timeout.

Do **not** treat literal `timeout=None` as a detection limitation: the engine
counts it as missing, same as an omitted kwarg.

---

## Recommendations beyond the fix

```python
import requests
from langchain_core.tools import tool
from requests.exceptions import RequestException, Timeout


@tool
def fetch_report(report_id: str) -> str:
    """Fetch a vetted report by ID with a finite Requests timeout."""
    # Choose timeout per upstream latency / SLA — 10s is illustrative only.
    try:
        resp = requests.get(
            f"https://api.example.com/reports/{report_id}",
            timeout=10,
        )
        resp.raise_for_status()
        return resp.text
    except Timeout:
        return "error: upstream timed out; try again or use a different tool"
    except RequestException as exc:
        return f"error: request failed: {exc}"
```

1. Pass an explicit finite `timeout=` on every `requests` call, sized to that
   upstream's latency and SLA — do not copy a universal 5s or 30s default across
   services.
2. Catch and handle timeout (and related request) exceptions so the tool returns
   a structured error the model can act on instead of blocking the agent step.
3. Combine with retries where appropriate *after* each attempt already has a
   finite timeout; retries amplify stalls if the attempt itself is unbounded.
4. Prefer a Session or shared client with a documented default timeout for
   consistency, but keep an explicit per-call `timeout=` on slow or critical
   endpoints so the bound is visible at the call site (and to this rule).
5. Pair with the SSRF controls in [langchain/ssrf.md](ssrf.md) when the URL or
   host is model-influenced — a bounded wait and a constrained destination are
   complementary.
