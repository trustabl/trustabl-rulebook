---
policy_id: crewai_network
category: crewai
topic: network
rules:
  - id: CREW-009
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
references: [LLM10]
---

# Policy Rationale: CrewAI Tool Network Hygiene

**Policy ID:** `crewai_network`  
**File:** `crewai/network.yaml`  
**Rules:** CREW-009  
**Severities:** high  
**Fix types:** code  
**References:** LLM10 (Unbounded Consumption)

> Shares the request-timeout threat model with
> [openai_sdk/network.md](../openai_sdk/network.md). CrewAI-specific angle only.

---

## What this policy covers

A CrewAI tool that calls an HTTP client — `requests.*`, `httpx.*`,
`urllib.request.urlopen`, or an `aiohttp.ClientSession` method — without passing
`timeout=`. Detected by `call_without_kwarg` over a fixed callee list, the same
set the other packs' no-timeout rules use.

---

## Why a missing timeout is a distinct concern in agent tools

Python's HTTP clients do not time out by default. `requests.get(url)` with no
`timeout=` waits indefinitely — not for a long time, but forever — if the remote
accepts the connection and then never responds. That is a well-known footgun in
ordinary code. What changes in an agent is who notices.

CrewAI bounds iterations, not time. `max_iter` caps how many steps an agent takes;
nothing caps how long one step takes, so a request that never returns is an
unbounded path rather than a slow one.

The crew structure widens the blast radius past the agent that made the call. In
a sequential process, tasks execute in order and each waits for its predecessor,
so a stall inside one agent's tool call blocks **every task queued behind it**. The
agents downstream are not slow — they never start. One unresponsive endpoint
therefore takes out the whole crew run, and none of the queued tasks produce a
result either. The kickoff simply does not return.

The result is the worst shape a failure can take: not an error the model can
react to, not a slow response, but silence. The run does not fail, so no retry
policy engages and no alert fires on a non-zero exit. It does not finish, so
nothing downstream proceeds. Whatever runtime hosts the agent stays occupied
until the connection eventually dies at the TCP layer — which may be minutes,
or may be never on a half-open connection. Under any concurrency, those held
runtimes accumulate (unbounded consumption, LLM10).

A hostile or merely broken endpoint is enough. Where the URL is model-chosen,
the endpoint may be attacker-chosen too, which turns a missing keyword argument
into a denial-of-service primitive against the agent host.

---

## Rule-by-rule defense

### CREW-009 — CrewAI tool network call has no timeout (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:** a call to one of the listed HTTP client functions with no
`timeout=` keyword argument.

**Why it is flaggable:** the absence of the keyword is the defect — these clients
have no default. There is no other bound in the path, so the call's duration is
whatever the remote decides.

**Real-world consequence:**

- A `fetch_quote` tool queries a price endpoint that accepts the connection and
  stalls. The researcher agent stops mid-step, and the analyst and writer tasks
  behind it never run. `max_iter` never advances, because the step never ends.
- A crew scheduled on a timer accumulates overlapping stalled runs, each holding
  its own worker, because the previous run never finished to release it.
- Where the URL is model-chosen, a task summarizing untrusted content can steer
  the call at an endpoint chosen to stall — turning a missing keyword argument
  into a denial-of-service primitive against the crew host.

**Why severity is high and not medium:** there is no partial mitigation in the
default configuration. A missing `timeout=` is not a smaller bound, it is the
absence of any bound, and the failure is silent rather than loud. It is not
critical because it costs availability rather than integrity or confidentiality,
and a platform-level request timeout — where one exists — caps the damage
externally.

**Fix type — code:** `timeout=` is an argument at the call site inside the tool
body. No agent or framework setting substitutes for it.

**Confidence 0.85:** the predicate reads the call site, so it is accurate about
what it sees. The gap accounts for both directions. False positives: a session
object configured with a default timeout elsewhere, or a client wrapped by a
helper that injects one, so the bound exists outside the matched call. False negatives: a `requests.Session()` with a default set on the adapter, or a call reached through a shared helper in a BaseTool subclass, both escape the callee match.

---

## What this policy does not cover

- A timeout supplied outside the matched call — on a `Session`, a transport
  adapter, an `httpx.Client(timeout=...)` constructor, or a wrapper function.
- HTTP clients outside the callee list, and any hand-rolled socket code.
- A `timeout=` passed but set uselessly high; the rule checks that a bound was
  chosen, not that it was chosen well.
- Connect-versus-read timeout distinctions: `timeout=5` on `requests` applies to
  each phase separately, so a response streamed slowly can still exceed it.
- Retries around the call, which multiply the total wait even when each attempt
  is individually bounded.
- Non-HTTP blocking calls — database drivers, subprocesses, file locks — which
  hang the same way and are out of scope here.

---

## Recommendations beyond the fix

```python
import requests

TIMEOUT = 10  # seconds


@tool("fetch_quote")
def fetch_quote(symbol: str) -> dict:
    """Fetch a price quote."""
    try:
        r = requests.get(f"https://quotes.example.com/{symbol}", timeout=TIMEOUT)
        r.raise_for_status()
        return {"ok": True, "quote": r.text}
    except requests.Timeout:
        return {"ok": False, "error": "quote service timed out", "retryable": True}
```

1. Pass `timeout=` on every outbound call, sized from the endpoint's real latency
   profile rather than a round number.
2. Return the timeout to the model as a structured, retryable error. Converting a
   hang into an exception the tool swallows is only half the fix — the agent still
   needs to know the call failed so the crew can proceed or fail deliberately.
3. Prefer a configured client — `httpx.Client(timeout=...)` or a `Session` with a
   default — so a new call site cannot silently omit the bound. This rule will not
   see that bound and will still fire; that is the known false positive above, and
   it is the right trade against silently missing real ones.
4. Remember `max_iter` is not a time bound, and that in a sequential process the
   cost of one stalled call is the whole run. If a crew must be time-bounded, wrap
   `kickoff()` at the caller.
