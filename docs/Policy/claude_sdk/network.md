---
policy_id: claude_sdk_network
category: claude_sdk
topic: network
rules:
  - id: CSDK-003
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: CSDK-020
    severity: high
    confidence: 0.6
    scope: tool
    fix_type: code
references: [LLM10]
---

# Policy Rationale: Network Call Hygiene

**Policy ID:** `claude_sdk_network`  
**File:** `claude_sdk/network.yaml`  
**Rules:** CSDK-003, CSDK-020  
**Severities:** high, high  
**Fix types:** code, code  
**References:** LLM10

> **Read [openai_sdk/network.md](../openai_sdk/network.md) for the full threat model.**
> This document covers Claude Agent SDK–specific differences only.

---

## What this policy covers

Claude Agent SDK `@tool` / `@claude_tool` bodies (and MCP tool registrations)
that make an outbound HTTP call without a `timeout=` keyword argument. Detection
is the `call_without_kwarg` predicate over the `requests.*` / `httpx.*` /
`urllib.request.urlopen` callee families — the same mechanism described in the
OpenAI network doc, including local client-alias resolution
(`s = requests.Session(); s.get(...)`).

TypeScript Claude Agent SDK tools are covered by CSDK-020 (`language:
typescript`), which matches `has_http_call_without_timeout: true`. The rule's
explanation describes the target as an outbound HTTP call (`fetch` / `axios` /
`got` / `undici`) with no deadline: no `signal`, `timeout`, or `abortSignal`
option.

---

## Why network hygiene is a distinct concern in agent tools

The mechanism is identical to the OpenAI case — a timeout-less call hangs on a
stalled socket, and because the model drives the call sequence, one hung request
freezes the whole conversation turn rather than a single cancellable request.
See [openai_sdk/network.md](../openai_sdk/network.md#why-network-hygiene-is-a-distinct-concern-in-agent-tools).

Claude-specific note: the Claude Agent SDK does not impose a tool-level wall
clock either, so a hung `requests.get` blocks the agent loop until the OS TCP
timeout (minutes). The same rule applies to MCP tools, where the blocked call
also stalls whatever external orchestrator invoked the MCP server.

CSDK-020 applies the same concern to TypeScript tools. A slow or unresponsive
host blocks the tool callback until the socket eventually dies, and because the
call sits inside the agent's turn, it stalls the conversation rather than
failing it: the model gets no result and no error, and the turn cannot advance.

---

## Rule-by-rule defense

### CSDK-003 — Network call has no timeout (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:**
A Claude SDK or MCP tool whose body calls a `requests` / `httpx` method,
`urllib.request.urlopen`, or a resolved session alias of these, with no
`timeout=` kwarg (the kwarg absent, or present as `None`, both count).

**Why it is flaggable:**
These clients default to no timeout; without one the call blocks until the kernel
gives up, pinning the agent loop.

**Real-world consequence:**
A `fetch_page(url)` Claude tool called on a slow host hangs the turn — the user
sees nothing, and the model's retry on the eventual error compounds the stall.

**Why severity is high and not medium:**
The failure denies the agent loop itself, with no in-band mitigation short of an
explicit `timeout=`. Same reasoning as OAI-005/011.

**Fix type — code:**
Add `timeout=` to the call — a source edit; no hook or sandbox injects it.

**Confidence 0.85:**
Same profile as the OpenAI network rules — a client whose timeout is configured
on a `Session`/`Client` object rather than the call site can be a false positive,
and a request behind a cross-module helper a false negative.

### CSDK-020 — TypeScript Claude SDK tool HTTP call has no timeout (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:**
A TypeScript Claude Agent SDK tool that makes an outbound HTTP call with no
deadline, matched by `has_http_call_without_timeout: true`. The rule's
explanation names the clients (`fetch`, `axios`, `got`, `undici`) and the
missing options (`signal`, `timeout`, `abortSignal`).

**Why it is flaggable:**
Without one of those options, a slow or unresponsive host blocks the tool
callback until the socket eventually dies. The call sits inside the agent's
turn, so the conversation stalls on it rather than failing.

**Real-world consequence:**

- A `fetch_page` tool calls `await fetch(url)` against a host that never
  answers. The model gets no result and no error, and the turn cannot advance.
  A turn cap does not end it, because the run is stuck inside a single turn
  rather than taking too many.
- In a server embedding the SDK, the same call holds the request worker for
  the duration.
- The same tool fetches a model-controlled URL (CSDK-013, in [ssrf.md](ssrf.md)).
  With no timeout, it can be pointed at an internal host that never answers.

**Why severity is high:**
The pack sets high, the same as CSDK-003. Its explanation gives the reasons:
the call stalls the conversation rather than failing it, a turn cap does not
bound the stall, a server embedding the SDK loses the request worker for the
duration, and the exposure compounds with CSDK-013.

**Fix type — code:**
The deadline is attached at the call site: `signal: AbortSignal.timeout(...)`
for `fetch` on modern runtimes, an `AbortController` aborted from a
`setTimeout` on older ones, or the `timeout` option for `axios` and `got`. That
is an edit to the tool source.

**Confidence 0.6:**
The pack sets confidence at 0.6 for this rule. It states no known false
positives, false negatives, or other limits for CSDK-020.

---

## What this policy does not cover

Identical to [openai_sdk/network.md](../openai_sdk/network.md#what-this-policy-does-not-cover):
non-listed clients (raw `socket`, `pycurl`, `urllib3` directly), unreasonable-but-present
timeout values, transitive calls through another module, and retry-without-backoff
storms (idempotency territory, CSDK-006). Since the 2026-07 callee harmonization
the list covers `requests` (incl. `Session` aliases), `httpx`, `urllib`
(`urllib.request.urlopen` and the bare `urlopen` import), and aliased `aiohttp`
sessions (canonicalized to `aiohttp.ClientSession.<method>`).

That list is CSDK-003's Python callee list. CSDK-020 is a separate TypeScript
rule, and the pack states no limits for it. `claude_sdk/network.yaml` has
CSDK-003 (`language: python`) and CSDK-020 (`language: typescript`) only, so
tools in other languages are not covered.

---

## Recommendations beyond the fix

The safe pattern — an explicit `timeout=`, a capped response read, and a
structured error the model can branch on — is in
[openai_sdk/network.md](../openai_sdk/network.md#recommendations-beyond-the-fix).
For Claude SDK tools, return a structured error dict on timeout so the model can
react rather than seeing an opaque traceback, and prefer a single shared client
with a default timeout if many tools fetch the same service.

The TypeScript equivalent for CSDK-020:

```typescript
import { tool } from "@anthropic-ai/claude-agent-sdk";
import { z } from "zod";

export const fetchPage = tool(
  "fetch_page",
  "Fetch a URL and return its text. Times out after 15 seconds and returns a structured error instead of waiting.",
  { url: z.string().url() },
  async ({ url }) => {
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(15_000) });
      return { content: [{ type: "text", text: await response.text() }] };
    } catch (err) {
      const timedOut = err instanceof DOMException && err.name === "TimeoutError";
      return {
        isError: true,
        content: [{ type: "text", text: timedOut ? `timeout fetching ${url}` : `fetch failed: ${url}` }],
      };
    }
  },
);
```

On runtimes without `AbortSignal.timeout`, create an `AbortController`, abort
it from a `setTimeout`, pass `controller.signal`, and clear the timer in a
`finally`. `axios` and `got` take a `timeout` option directly. Return the abort
as a structured tool error so the model can retry or route around it instead of
the turn hanging.
