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
references: [LLM10]
---

# Policy Rationale: Vercel AI Tool Network Hygiene

**Policy ID:** `vercel_ai_network`  
**File:** `vercel_ai/network.yaml`  
**Rules:** VAI-011  
**Severities:** high  
**Fix types:** code  
**References:** LLM10 (Unbounded Consumption)

---

## What this policy covers

Network-call hygiene inside Vercel AI SDK tool `execute()` handlers. **VAI-011**
uses the `has_http_call_without_timeout` predicate: it fires when a tool's
`execute()` body makes an outbound HTTP call (`fetch`, `axios`, `got`, or
`undici`) with no timeout bound — no `signal`, `timeout`, or `abortSignal`
option on the call. A call that already carries one of those does not fire.

---

## Why a missing timeout is a distinct concern in Vercel AI tools

Node's `fetch` has **no implicit deadline**. A `fetch(url)` with no `signal`
blocks until the remote responds or the socket dies — which, against a slow or
hostile server, can be indefinite. The tool's `execute()` handler runs *inside*
the model's tool loop: a call that never returns ties up the request worker
servicing that conversation and burns the turn's wall-clock budget with no way
to cancel, and the model never receives a result it can react to. The agent
simply appears to hang.

This is an availability / unbounded-consumption hazard (LLM10): a single slow or
adversarial endpoint gets indefinite hold over the tool callback, and under
concurrency a handful of hung calls exhaust the worker pool. The hazard is
sharper than a generic reliability lint because Vercel AI tools routinely fetch
URLs the model supplies or influences — so a model-chosen slow endpoint can be
reached *deliberately*. It compounds with **VAI-003** (model-controlled URL): a
destination the model steers that *also* cannot time out can be aimed at an
internal host that simply accepts the connection and never answers. That
combination — reachable by model-influenced input, and unbounded once reached —
is why the pack rates this **high** rather than the medium a pure reliability
lint would carry.

---

## Rule-by-rule defense

### VAI-011 — Tool HTTP call has no timeout (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:** a Vercel AI tool `execute()` body that calls `fetch` /
`axios` / `got` / `undici` with no `signal`, `timeout`, or `abortSignal` option
(predicate `has_http_call_without_timeout`).

**Why it is flaggable:** Node `fetch` has no default timeout, so without an
explicit bound the call can hang forever; because the call sits in the model's
tool loop, the hung request blocks the worker and consumes the turn's wall-clock
budget rather than surfacing a failure the model can handle.

**Real-world consequence:** a `fetchPage({ url })` tool calls
`await fetch(url)` with no `signal`; an injection (or an unlucky model
completion) points it at an endpoint that accepts the connection and never
responds, hanging the tool turn indefinitely and, under load, exhausting the
request workers that serve other conversations.

**Why severity is high and not medium:** unlike a pure reliability lint, the
hung call is reachable and triggerable by model-influenced input in a loop that
blocks on it, so it is both an availability incident and an injection-pullable
lever — and it compounds with the model-controlled-URL exposure of VAI-003. The
pack rates it **high** to match that dual exposure. **Fix type — code:** adding
an `AbortSignal` / `timeout` option is a tool-source edit. **Confidence 0.6:**
the rule looks for a timeout option on the recognized callees, so it over-fires
when a deadline is supplied another way (a wrapping client with a baked-in
`timeout`, an `AbortController` whose `signal` is threaded in from outside the
matched call, a framework default) and under-fires on HTTP clients outside the
recognized `fetch`/`axios`/`got`/`undici` set — the lower confidence reflects
how varied TypeScript HTTP-call shapes are.

---

## What this policy does not cover

- HTTP clients outside the recognized set — `node:http`/`https` `request`,
  `node-fetch`, `superagent`, `ky`, or a bespoke wrapper are not matched.
- A deadline supplied through a mechanism other than the per-call option — a
  client instance created with a default `timeout`, an `AbortController.signal`
  threaded in from outside the matched call, or a server-level socket timeout —
  the rule cannot see it and fires anyway (a false positive).
- Whether the chosen timeout is *appropriate*. A `fetch` with
  `AbortSignal.timeout(600_000)` satisfies the rule but still hangs the tool turn
  for ten minutes.
- *Where* the request goes — a model-controlled destination is the separate SSRF
  concern of **VAI-003** (ssrf.md). VAI-011 is only about the missing timeout;
  the two are designed to be fixed together.

---

## Recommendations beyond the fix

```ts
import { tool } from "ai";
import { z } from "zod";

export const fetchPage = tool({
  description: "Fetch a page from the vetted host with a tight timeout.",
  parameters: z.object({ path: z.string() }),
  execute: async ({ path }) => {
    // Fail fast on a slow remote; AbortSignal.timeout cancels the fetch.
    const res = await fetch(`https://api.example.com/${path}`, {
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) {
      // Surface a structured error the model can react to, not a hang.
      return { error: `upstream ${res.status}` };
    }
    return { body: await res.text() };
  },
});
```

1. Attach a deadline to every outbound call — `AbortSignal.timeout(ms)` on modern
   runtimes, or an `AbortController` with a `setTimeout(() => controller.abort())`
   cleared in a `finally` on older ones. `axios` and `got` take a `timeout`
   option directly.
2. Size the timeout tight enough to fail fast and loose enough for legitimate
   slow responses on that endpoint (typically 5–30 seconds).
3. Catch the abort and return it as a **structured tool error** the model can act
   on (retry, fall back, report) rather than letting the turn hang.
4. Pair the timeout with the SSRF guard from VAI-003 — a model-callable fetch
   needs both a bounded wait and a constrained destination.
