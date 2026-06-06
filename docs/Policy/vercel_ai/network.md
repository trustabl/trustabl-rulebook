---
policy_id: vercel_ai_network
category: vercel_ai
topic: network
rules:
  - id: VAI-011
    severity: high
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM10, LLM06]
---

# Policy Rationale: Vercel AI SDK Network Safety

**Policy ID:** `vercel_ai_network`  
**File:** `vercel_ai/network.yaml`  
**Rules:** VAI-011  
**Severities:** high  
**Fix types:** code  
**References:** LLM10 (Unbounded Consumption), LLM06 (Excessive Agency)

---

## What this policy covers

Vercel AI SDK tools whose `execute()` body makes an outbound HTTP call with no
timeout. **VAI-011** fires on the `has_http_call_without_timeout` fact: a handler
that calls `fetch` / `axios` / `got` / `undici` and passes no options object
carrying a `signal`, `timeout`, or `abortSignal` key. A call that attaches any of
those — `fetch(url, { signal: AbortSignal.timeout(ms) })`, `axios.get(url, {
timeout: ms })` — does not fire. The fact is structural: discovery walks the
`execute` handler, recognizes the HTTP-client call, and inspects its argument
objects for a timeout-bearing key.

---

## Why an unbounded HTTP call is a distinct concern in Vercel AI tools

Node's `fetch` (and the browser's) has no implicit timeout: with no `signal`, a
request waits until the OS gives up on the socket, which on Linux is the
`tcp_syn_retries` window — minutes. In a normal web handler a parent request can
be cancelled; inside a Vercel AI agent the tool call sits in the model's tool
loop, and there is no external caller to abort it. While the call hangs, the turn
cannot advance: the user sees nothing, no other tool runs, and the whole turn's
wall-clock and token budget drains against one stalled endpoint. The serverless
runtime's own per-invocation limit may then kill the function mid-turn, losing
all progress.

The hazard compounds with two others. Agents retry: when the call finally errors,
the model often calls the tool again, multiplying the stall and threatening the
request-worker pool. And it stacks with SSRF (VAI-003): a model-controlled URL
that *also* cannot time out is the ideal target for an injected instruction that
points the fetch at an internal host which simply never answers — a slow-loris
into the agent's own network.

---

## Rule-by-rule defense

### VAI-011 — Tool HTTP call has no timeout (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:** a Vercel AI tool `execute()` handler that calls
`fetch`/`axios`/`got`/`undici` with no options object carrying a `signal`,
`timeout`, or `abortSignal` key (`has_http_call_without_timeout`). A bare
`fetch(url)` or `fetch(url, { method })` fires; any of the three timeout keys
clears it.

**Why it is flaggable:** the SDK and the runtime inject no timeout, so a missing
one is observable in source and means the call can block the tool loop until the
OS or the platform kills it.

**Real-world consequence:** a `fetchUrl({ url })` tool that does `await
fetch(url)` is handed a URL on a sinkhole host; the turn hangs until the
serverless function's wall-clock limit terminates it, and the user's request is
lost with no partial answer.

**Why severity is high and not medium:** the failure denies the agent loop, not
just one response — there is no in-band mitigation once the call is in flight, and
the kernel default is "minutes." Medium is reserved for output-quality issues;
this freezes the turn.

**Fix type — code:** the fix is a source edit on the call —
`signal: AbortSignal.timeout(ms)` for `fetch`, or `timeout:` for axios/got. No
guardrail, hook, or runtime config can inject a deadline into an in-flight call.

**Confidence 0.6:** the check is precise about the call shape (no substring
guesswork), but it cannot follow indirection. **False positives** (fires though
bounded): an options object passed by identifier (`fetch(url, opts)`), a
`signal`/`AbortController` defined on a separate line, a `Promise.race([fetch(url),
timeout])`, or an `axios.create({ timeout })` instance whose per-call site shows
no `timeout` key. **False negatives** (silent though unbounded): `signal:
req.signal` with no deadline behind it, or an axios `timeout: 0` (which means "no
timeout"). The rule shares its predicate and its 0.6 calibration with the OpenAI
TS sibling OAI-016.

---

## What this policy does not cover

- A timeout reached indirectly — options passed by identifier, a signal/controller
  bound on a separate line, a `Promise.race` deadline, or an `axios.create({
  timeout })` instance — is not seen, so the rule fires on some already-bounded
  calls.
- A non-deadline `signal: req.signal`, or an axios `timeout: 0`, is treated as a
  timeout and does not fire.
- HTTP clients outside the recognized `fetch`/`axios`/`got`/`undici` set, or a
  call made in a helper in another module (discovery sees the `execute` body, not
  a wrapper elsewhere).
- TypeScript only: a tool defined in plain `.js`/`.mjs` is not AST-parsed, so its
  `execute()` HTTP calls are a coverage gap.
- Retry-without-backoff and unbounded response-body reads are separate
  budget-exhaustion hazards this rule does not model.

---

## Recommendations beyond the fix

```typescript
import { tool } from "ai";
import { z } from "zod";

export const getStatus = tool({
  description: "Fetch a status path from the vetted API host.",
  inputSchema: z.object({ path: z.string() }),
  execute: async ({ path }) => {
    const url = new URL(`/${path.replace(/^\/+/, "")}`, "https://api.example.com");
    // Bound the call: abort after 10s so a slow host cannot hang the turn.
    const res = await fetch(url, {
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
    });
    // Cap how much we read so a slow-drip body cannot drain the budget either.
    const body = (await res.text()).slice(0, 500_000);
    return { status: res.status, body };
  },
});
```

1. Attach `AbortSignal.timeout(ms)` (5–30s) to every `fetch`; for runtimes without
   it, drive an `AbortController` from a `setTimeout` and clear it in a `finally`.
   axios and got take a `timeout` option directly.
2. Surface the resulting `AbortError` / `TimeoutError` as a structured tool result
   the model can branch on, rather than letting the promise hang or throwing raw.
3. Cap the response body size so a timely-but-slow-drip server cannot exhaust the
   budget the timeout was meant to protect.
4. Pair with VAI-003: validate the destination host so a model-controlled URL
   cannot aim the (now time-bounded) request at an internal address.
