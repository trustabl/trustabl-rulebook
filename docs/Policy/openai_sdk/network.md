---
policy_id: openai_sdk_network
category: openai_sdk
topic: network
rules:
  - id: OAI-005
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: OAI-011
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: OAI-016
    severity: high
    confidence: 0.6
    scope: tool
    fix_type: code
  - id: OAI-018
    severity: medium
    confidence: 0.55
    scope: tool
    fix_type: code
  - id: OAI-024
    severity: medium
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM10, LLM06, LLM02]
---

# Policy Rationale: Network

**Policy ID:** `openai_sdk_network`  
**File:** `openai_sdk/network.yaml`  
**Rules:** OAI-005, OAI-011, OAI-016, OAI-018, OAI-024  
**Severities:** high, high, high, medium, medium  
**Fix types:** code, code, code, code, code  
**References:** LLM10, LLM06, LLM02

---

## What this policy covers

This policy targets outbound HTTP calls made from inside an OpenAI Agents SDK `@function_tool` body. Two predicates anchor it: `call_without_kwarg` for `requests.*` / `httpx.*` (OAI-005), and `call_without_kwarg` for `urllib.request.urlopen` / `urlopen` (OAI-011). Both fire when the corresponding callee is invoked from a discovered `@function_tool` without `timeout=` passed as a keyword argument. The SDK never injects a timeout itself, so a missing timeout is observable in source.

---

## Why network hygiene is a distinct concern in agent tools

In an agentic system the model drives the call sequence. A single hung outbound request does not just freeze one HTTP fetch — it freezes the run loop. While the tool blocks on a stalled TCP connection, the conversation cannot advance, no other tool can run, the user sees no response, and the wall-clock budget for the whole turn is consumed by one slow endpoint. Conventional applications have a parent request that the caller can cancel; an agent turn typically does not.

The default for Python's stdlib `urlopen` is `socket._GLOBAL_DEFAULT_TIMEOUT`, which resolves to `None` unless someone has called `socket.setdefaulttimeout()` at process start. Almost nobody does, so the practical default is "wait until the OS gives up," which on Linux is the system `tcp_syn_retries` timeout — multiple minutes. `requests` and `httpx` behave the same way: no timeout unless asked.

Worse, agents retry. When the tool finally errors out, the model frequently calls it again. Two stuck retries multiply the blocking, and in the worst case a third hung call exhausts the worker pool entirely. This is why the SDK's documented guidance is to wrap network calls with explicit timeouts and to surface timeout errors structurally (`failure_error_function`) so the model can branch instead of looping.

---

## Rule-by-rule defense

### OAI-005 — Network call has no timeout (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:**
A `@function_tool`-decorated function whose body invokes `requests.get / post / put / delete / patch / head` or `httpx.get / post / put / delete / patch` without a `timeout=` keyword argument on that call.

**Why it is flaggable:**
`requests` and `httpx` both default to no timeout. Without one, a stalled socket pins the tool — and therefore the agent's run loop — until the kernel times the connection out.

**Real-world consequence:**
A `web_fetch`-style tool that calls `requests.get(url)` on a model-supplied URL will hang the entire agent turn when the URL points at a slow or non-responsive host. The user sees no output; the model cannot recover; retries compound the blockage.

**Why severity is high and not medium:**
The failure mode is denial of the agent loop itself, not a slow response. There is no partial mitigation: without an explicit `timeout=`, the kernel default applies, and the kernel default is "minutes." Medium is reserved for issues that degrade output quality; this one freezes the worker.

**Fix type — code:**
Requires editing the tool source to pass `timeout=`. No guardrail, hook, or sandbox parameter can inject a timeout into an already-running call.

**Confidence 0.85:**
The gap is a false-positive case where a custom `requests.Session` with `request()` defaults already enforces a timeout via an adapter — the predicate sees a bare `requests.get` and fires. False negatives include calls via `httpx.Client(...).get(...)` where the client carries the timeout. Both are uncommon enough to keep the rule above 0.8.

### OAI-011 — urllib network call has no timeout (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:**
A `@function_tool`-decorated function whose body invokes `urllib.request.urlopen` (or the bare `urlopen` import) without a `timeout=` keyword argument on that call.

**Why it is flaggable:**
`urlopen`'s timeout parameter defaults to `socket._GLOBAL_DEFAULT_TIMEOUT`, which is `None` unless `socket.setdefaulttimeout` was called process-wide. In practice that means no timeout, and the call blocks until the OS-level TCP timeout — typically several minutes. OAI-005 explicitly does not cover `urllib`; this rule closes that hole.

**Real-world consequence:**
- `fetch_url_metadata(url)` at https://github.com/jawwad-ali/Sunday-Afternoon-Q4/blob/main/class14/tools.py#L54 calls `urllib.request.urlopen(request, timeout=10)` — safe because it sets the timeout, but if that kwarg were removed the tool would hang.
- `web_search` and `web_fetch` at https://github.com/taco-devs/termo-agent/blob/main/termo_agent/adapters/platform_adapter.py#L404 and https://github.com/taco-devs/termo-agent/blob/main/termo_agent/adapters/platform_adapter.py#L438 demonstrate the safe pattern. A sibling tool that forgets the kwarg would silently freeze the agent.

**Why severity is high and not medium:**
Same blast radius as OAI-005 — a hung `urlopen` blocks the agent loop indefinitely. The stdlib's `urlopen` is more commonly used in tools written by people unfamiliar with `requests`, so the rule earns its place even though `urllib` is less prevalent than `requests` in modern code.

**Fix type — code:**
The fix is a source-level `timeout=N` kwarg on the call. No hook or sandbox parameter intercepts stdlib socket waits.

**Confidence 0.85:**
False positives: code that wraps `urlopen` behind a helper that injects a timeout (`def safe_urlopen(req): return urlopen(req, timeout=10)` — then a caller writing `safe_urlopen(req)` is safe but undetected). False negatives: positional call `urlopen(req, None, 10)` passes timeout positionally, which the `call_without_kwarg` predicate does not see — but the convention overwhelmingly favors the kwarg form.

---

### OAI-016 — TypeScript tool fetch call has no AbortSignal timeout (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:** a TypeScript tool body that calls `fetch(` with no
`AbortSignal` / `AbortController` / `signal:` / `AbortSignal.timeout` present
(`has_body_text` for `fetch(` AND `not has_body_text` for the abort markers).

**Why it is flaggable:** Node's and the browser's `fetch` have no implicit
timeout; a slow host blocks the tool's `execute` callback — and the agent run
loop — indefinitely, burning the turn's wall-clock budget and tying up the worker.
Because these templates often interpolate the URL from tool arguments, the
un-cancellable call also amplifies SSRF/exfiltration impact.

**Real-world consequence:** a TS `web_fetch` tool hangs the whole agent turn when
the model supplies a slow or hostile URL.

**Why severity is high and not medium:** the failure denies the agent loop, with
no in-band mitigation short of an explicit signal.

**Fix type — code:** pass `signal: AbortSignal.timeout(ms)` (or an
`AbortController`) to `fetch`.

**Confidence 0.6:** `has_body_text` is a brittle substring check — it can miss a
timeout wired through a wrapper, or fire when the abort lives in a helper.

**Provisional (TypeScript):** this rule loads and validates today but will not
fire until the engine's TypeScript tool parser ships; it is load-validated only.

### OAI-018 — Tool builds outbound URL from non-literal value (Severity: medium, Confidence: 0.55, Fix type: code)

**What we detect:** an `@function_tool` body that issues an HTTP request whose URL
is built from a non-literal value (`has_dynamic_url_call: true`).

**Why it is flaggable:** tool arguments are model-produced, so a model-controlled
URL can be steered at an attacker host or an internal address the egress can reach
(SSRF), and the request body (auth headers, payload) leaks to whatever the URL
resolves to.

**Real-world consequence:** a tool that interpolates a model-supplied
`connection_id` into a base URL is pointed at the cloud metadata endpoint or an
internal service. See [claude_sdk/ssrf.md](../claude_sdk/ssrf.md) for the full SSRF
threat model.

**Why severity is medium and not high:** the OpenAI variant is scored slightly
lower than the Claude/ADK SSRF rules pending corpus calibration; the exploit path
is the same, conditional on the host's network position.

**Fix type — code:** validate the model-supplied value against a host allow-list,
or look it up in a server-side registry and build the URL from the trusted entry.

**Confidence 0.55:** many tools build URLs from validated IDs; the predicate cannot
see validation that lives in another module (false positive).

### OAI-024 — TypeScript tool builds outbound URL from a non-literal value (Severity: medium, Confidence: 0.6, Fix type: code)

**What we detect:**
A TypeScript `@function_tool` `execute` body that issues an HTTP request whose URL
argument is non-literal (`has_dynamic_url_call: true`). The fact is structural, not
substring: `tsHandlerFacts` walks the handler, recognizes a `call_expression`
whose callee is one of the `fetch` / `axios(.get/.post/...)` / `got(.get/.post)` /
`undici.fetch` / `undici.request` clients, and inspects that call's first
positional argument. A plain `string`-node literal does **not** fire; a template
string with at least one `${...}` substitution (NamedChildCount > 0), an
identifier, a member expression, or a concatenation does. A backtick template with
no substitution is treated as a literal and does not fire. This is the same
predicate as the Python sibling
[OAI-018](#oai-018--tool-builds-outbound-url-from-non-literal-value-severity-medium-confidence-055-fix-type-code),
resolved against the TypeScript HTTP-client shapes.

**Why it is flaggable:**
Tool arguments are model-produced from conversation context, so a non-literal URL
is a model-controlled destination: an attacker shaping that context can steer the
request at an attacker host or an internal address the agent's egress can reach
(SSRF), and the request body, headers, and credentials leak to whatever the URL
resolves to. Same mechanism as OAI-018; see
[claude_sdk/ssrf.md](../claude_sdk/ssrf.md) for the full SSRF threat model.

**Real-world consequence:**
A TS tool that does `fetch(\`https://api.example.com/${connectionId}\`)` with a
model-supplied `connectionId` is pointed at `http://169.254.169.254/...` (cloud
metadata) or an internal service, and the outbound request's auth header rides
along.

**Why severity is medium and not high:**
Matches OAI-018's medium — the exploit path is real but conditional on the host's
network position and on the model actually controlling the value; the OpenAI SSRF
variants are scored a notch below the Claude/ADK SSRF rules pending corpus
calibration.

**Fix type — code:**
Validating the model-supplied value against a host allow-list, or resolving an
opaque ID against a server-side registry and building the URL from the trusted
entry, is an edit to the tool's source.

**Confidence 0.6:**
Marginally above the Python OAI-018's 0.55 because the TS fact is *structural* — it
keys on the AST type of the first argument of a recognized HTTP-client call, so a
literal URL is correctly excluded by construction (no substring guesswork). The gap
that remains: **false positives** — a non-literal URL that is in fact a validated
or constant value (an ID checked against an allow-list in another module, or a base
URL read from config) still fires, because the body-only walk does not see the
validation and does not reason about whether the value is constant. **False
negatives** — an HTTP client outside the recognized set (`node:http`/`https`
`request`, `superagent`, `ky`, a wrapped client), a URL passed positionally to a
helper that performs the fetch, or a `new URL(base, modelValue)` constructed before
the call all escape the first-argument check on a known callee.

---

## What this policy does not cover

- Network calls made via libraries outside the listed callees: `aiohttp`, `urllib3` directly, `socket.create_connection`, `pycurl`, gRPC stubs, custom transports.
- Network calls where a `timeout=` is set to an unreasonable value (e.g. `timeout=3600`). The rule treats any timeout kwarg as a pass.
- Network calls made transitively — the tool calls a helper that performs the request without a timeout. The predicate inspects the tool body directly and does not follow calls into other modules.
- Retries without backoff. A tool that times out cleanly but retries in a tight loop is still a denial-of-budget hazard; that is OAI-009 / idempotency territory, not this policy.
- For OAI-024: HTTP clients outside the recognized `fetch`/`axios`/`got`/`undici` set (`node:http`/`https` `request`, `superagent`, `ky`, a wrapped client), a URL constructed via `new URL(base, modelValue)` before the call, and a model-supplied value passed positionally into a helper that performs the fetch — all escape the first-argument check on a known callee.

---

## Recommendations beyond the fix

```python
from agents import function_tool
import urllib.request

@function_tool(failure_error_function=lambda exc, ctx: {"error": str(exc), "retryable": False})
def web_fetch(url: str) -> str:
    """Fetch a URL and return its text content."""
    req = urllib.request.Request(url, headers={"User-Agent": "AgentBot/1.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        body = resp.read(500_000).decode("utf-8", errors="replace")
    return body or "[empty response]"
```

1. Pair every outbound HTTP call with `failure_error_function` so the model receives a structured timeout payload it can branch on (OAI-004).
2. Cap response size with `resp.read(N)` so a slow-drip server cannot exhaust memory even when the connection itself is timely.
3. Validate the URL scheme is `http(s)` and the host is on an allow-list before calling `urlopen` — prevents SSRF into the agent's internal network.
4. Run the agent under a process-wide `socket.setdefaulttimeout(30)` as defense-in-depth, but do not rely on it: tool-level `timeout=` is the contract.
