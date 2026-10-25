---
policy_id: google_adk_network
category: google_adk
topic: network
rules:
  - id: ADK-003
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: ADK-017
    severity: high
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM10]
---

# Policy Rationale: Network Call Hygiene

**Policy ID:** `google_adk_network`  
**File:** `google_adk/network.yaml`  
**Rules:** ADK-003, ADK-017  
**Severities:** high, high  
**Fix types:** code, code  
**References:** LLM10

> **Read [openai_sdk/network.md](../openai_sdk/network.md) for the full threat model.**
> This document covers Google ADK–specific differences only.

---

## What this policy covers

Python Google ADK `FunctionTool`-wrapped functions that make an outbound HTTP
call (`requests.*` / `httpx.*`) without a `timeout=` keyword argument
(`call_without_kwarg`, alias-aware), matched by ADK-003. Same predicate and
threat model as the OpenAI/Claude network policies.

TypeScript ADK `FunctionTool`s are covered by ADK-017 (`language:
typescript`), which matches `has_http_call_without_timeout: true`. The rule's
explanation describes the target as an outbound HTTP call (`fetch` / `axios` /
`got` / `undici`) with no deadline: no `signal`, `timeout`, or `abortSignal`
option.

---

## Why network hygiene is a distinct concern in agent tools

Identical to the OpenAI case — a timeout-less call hangs on a stalled socket, and
because the model drives the call sequence, one hung request freezes the whole
turn. See [openai_sdk/network.md](../openai_sdk/network.md#why-network-hygiene-is-a-distinct-concern-in-agent-tools).

ADK-specific note: ADK has no tool-level wall clock, so a hung request blocks the
agent loop until the OS TCP timeout (minutes). On managed runtimes (Cloud Run,
Vertex AI) a stuck request also holds a request slot, so under load timeout-less
tools degrade availability for the whole service.

ADK-017 applies the same concern to TypeScript tools. The pack's explanation
says a slow or unresponsive host blocks the tool callback, and that the agent
tree carries the stall past the tool: a stalled tool inside a `SequentialAgent`
blocks every step after it, and inside a `ParallelAgent` the whole fan-out
waits on its slowest branch, so one unresponsive host stalls work that has
nothing to do with it. It adds that ADK-108 (a Python rule, in
[agent_safety.md](agent_safety.md); the TypeScript option is `maxIterations`)
bounds how many times a `LoopAgent` goes round, not how long one tool call may
run.

---

## Rule-by-rule defense

### ADK-003 — Network call has no timeout (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:** a `FunctionTool`-wrapped body calling `requests`/`httpx`
methods (or a resolved session alias) with no `timeout=` kwarg.

**Why it is flaggable:** these clients default to no timeout; the call blocks until
the kernel gives up, pinning the agent loop.

**Real-world consequence:** a `get_weather(city)` tool hits a slow endpoint and the
whole ADK turn hangs; the model's retry compounds it.

**Why severity is high and not medium:** it denies the agent loop itself, with no
mitigation short of an explicit `timeout=`.

**Fix type — code:** add `timeout=` to the call.

**Confidence 0.85:** same profile as the other network rules — a client whose
timeout is configured on a session object, or a request behind a cross-module
helper, can be a false positive/negative.

### ADK-017 — TypeScript FunctionTool HTTP call has no timeout (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:**
A TypeScript ADK `FunctionTool` that makes an outbound HTTP call with no
deadline, matched by `has_http_call_without_timeout: true`. The rule's
explanation names the clients (`fetch`, `axios`, `got`, `undici`) and the
missing options (`signal`, `timeout`, `abortSignal`).

**Why it is flaggable:**
The mechanism is the one stated
[above](#why-network-hygiene-is-a-distinct-concern-in-agent-tools): with none
of those options, the pack's explanation says a slow or unresponsive host
blocks the tool callback, and the agents around the tool wait on it.

**Real-world consequence:**

- A tool inside a `SequentialAgent` calls `await fetch(url)` against a host
  that does not answer. The pack's explanation says a stalled tool there blocks
  the steps after it.
- The same tool inside a `ParallelAgent`: the pack's explanation says the
  fan-out waits on its slowest branch, so the stall reaches work that has
  nothing to do with that host.
- The tool fetches a caller-controlled URL (ADK-016, a `typescript` rule in
  [ssrf.md](ssrf.md)). With no timeout, the pack's explanation says it can be
  steered at an internal host that does not answer.

**Why severity is high:**
The pack sets high, the same as ADK-003, and states no reasoning for it. The
costs the explanation names are a stall that reaches the later steps of a
`SequentialAgent` and the fan-out of a `ParallelAgent`, a loop bound that does
not limit how long one call may run, and exposure that compounds with ADK-016.

**Fix type — code:**
The deadline is attached at the call site: `signal: AbortSignal.timeout(...)`
for `fetch` on modern runtimes, an `AbortController` aborted from a
`setTimeout` on older ones, or the `timeout` option for `axios` and `got`. That
is an edit to the tool source.

**Confidence 0.6:**
The pack sets confidence at 0.6 for this rule. It names no false-positive or
false-negative scenarios for ADK-017.

---

## What this policy does not cover

Same gaps as [openai_sdk/network.md](../openai_sdk/network.md#what-this-policy-does-not-cover):
non-listed clients, unreasonable-but-present timeout values, transitive calls
through another module, and retry-without-backoff storms (idempotency, ADK-006).

Those gaps describe ADK-003's Python callee list. ADK-017 is a separate
TypeScript rule, and the pack names no limits for it.
`google_adk/network.yaml` holds two rules, ADK-003 (`language: python`) and
ADK-017 (`language: typescript`), so tools in other languages are not covered.

---

## Recommendations beyond the fix

The safe pattern — explicit `timeout=`, capped response read, structured error —
is in [openai_sdk/network.md](../openai_sdk/network.md#recommendations-beyond-the-fix).
For ADK, return a structured error dict the Gemini model can branch on, and set a
defensive timeout tight enough to free the managed-runtime request slot quickly.

The TypeScript equivalent for ADK-017:

```typescript
import { FunctionTool } from "@google/adk";

export const getServiceStatus = new FunctionTool({
  name: "get_service_status",
  description:
    "Return the current status summary of the payments service. Times out after 15 seconds and returns an error result instead of waiting.",
  execute: async () => {
    try {
      const response = await fetch("https://status.example.com/api/v2/summary.json", {
        signal: AbortSignal.timeout(15_000),
      });
      if (!response.ok) {
        return { status: "error", error: `status page returned HTTP ${response.status}` };
      }
      return { status: "ok", summary: await response.json() };
    } catch (err) {
      const timedOut = err instanceof DOMException && err.name === "TimeoutError";
      return {
        status: "error",
        error: timedOut ? "status page timed out" : "status page unreachable",
      };
    }
  },
});
```

On runtimes without `AbortSignal.timeout`, create an `AbortController`, abort
it from a `setTimeout`, pass `controller.signal`, and clear the timer in a
`finally`. `axios` and `got` take a `timeout` option directly. Return the abort
as a structured tool result so the agent can react to an unreachable upstream
rather than the branch hanging.
