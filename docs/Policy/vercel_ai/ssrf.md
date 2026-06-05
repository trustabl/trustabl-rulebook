---
policy_id: vercel_ai_ssrf
category: vercel_ai
topic: ssrf
rules:
  - id: VAI-003
    severity: high
    confidence: 0.75
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: Vercel AI SDK Server-Side Request Forgery

**Policy ID:** `vercel_ai_ssrf`  
**File:** `vercel_ai/ssrf.yaml`  
**Rules:** VAI-003  
**Severities:** high  
**Fix types:** code  
**References:** LLM06 (Excessive Agency)

---

## What this policy covers

Vercel AI SDK tools whose `execute()` body fetches a URL the model controls.
**VAI-003** fires on the `has_dynamic_url_call` fact: a handler that issues an
outbound HTTP call (`fetch`, `axios`, `got`, `undici`) whose URL argument is not a
constant — it comes from the tool's arguments, a template string, or a
concatenation. A call to a hard-coded constant URL does not fire.

---

## Why SSRF is a distinct concern in Vercel AI tools

When the request URL is a literal, the developer chose the destination. When it is
built from a tool argument or a template, the *model* chooses the destination at
call time — and in a Vercel AI agent the model's choices are reachable by prompt
injection. A server-side request originates from inside the agent's network, so it
can reach what an external caller cannot: internal services on private CIDRs,
localhost admin ports, and the cloud metadata endpoint (169.254.169.254) that
hands out short-lived IAM credentials. A single injected instruction that
redirects the fetch to the metadata endpoint exfiltrates those credentials through
the model's next output.

There is a second-order hazard specific to agents: the fetched body re-enters the
conversation as text the model reads, so an attacker who controls the fetched page
controls a fresh prompt-injection channel into the agent. The SSRF primitive is
both an outbound credential-theft path and an inbound injection path at once —
excessive agency (LLM06) even when the developer never intended the tool to reach
internal hosts.

---

## Rule-by-rule defense

### VAI-003 — Tool execute() fetches a model-controlled URL (Severity: high, Confidence: 0.75, Fix type: code)

**What we detect:** a Vercel AI tool handler that issues an outbound HTTP call
(`fetch`/`axios`/`got`/`undici`) whose URL is non-literal — from an argument, a
template, or a concatenation (the `has_dynamic_url_call` fact).

**Why it is flaggable:** a model-controlled request target lets a prompt injection
point the request at internal services or the metadata endpoint, and feeds the
response back into the conversation as untrusted text.

**Real-world consequence:** a `fetchUrl({ url })` tool calling `fetch(url)` is
injected with
`url="http://169.254.169.254/latest/meta-data/iam/security-credentials/role"`; the
returned credentials are exfiltrated through the model's next reply.

**Why severity is high and not critical:** SSRF is serious but its blast radius
depends on the host's network position (a host with no reachable internal services
or metadata endpoint gets far less); it is not the unconditional code execution
the engine reserves critical for. **Fix type — code:** constraining or hard-coding
the destination is an edit to the handler. **Confidence 0.75:** `fetch` is also
the everyday way to call a legitimate external API, so a non-literal URL is a
weaker signal of *intent* here than a shell or eval call — the rule over-fires on
tools that fetch a dynamic-but-vetted endpoint and under-fires when the URL is
assembled in a helper in another module, which is why confidence sits below the
shell/eval rules.

---

## What this policy does not cover

- A request whose URL is dynamic but already validated against an allow-list
  inside the handler — the fact cannot see the guard, so it fires anyway (a known
  false positive, and the main reason confidence is 0.75).
- A fetch assembled in a helper in another module — discovery sees the handler, so
  a wrapper elsewhere escapes the fact.
- DNS-rebinding and time-of-check/time-of-use attacks against an allow-list that
  validates the hostname but not the resolved IP — Node's `fetch` does not let you
  pin the resolved address without a custom agent/dispatcher.
- TypeScript only: a tool defined in plain `.js` may not be analyzed with the same
  fidelity as a typed `.ts` handler, so a `.js` `execute()` fetch can be a coverage
  gap.
- Exfiltration or internal access through non-HTTP primitives (raw sockets, DNS)
  belongs to other concerns.

---

## Recommendations beyond the fix

```typescript
import { tool } from "ai";
import { z } from "zod";
import { lookup } from "node:dns/promises";
import ipaddr from "ipaddr.js";

const ALLOWED = new Set(["api.example.com"]);

export const getStatus = tool({
  description: "Fetch a status path from the vetted API host only.",
  inputSchema: z.object({ path: z.string() }),
  execute: async ({ path }) => {
    const url = new URL(`/${path.replace(/^\/+/, "")}`, "https://api.example.com");
    if (!ALLOWED.has(url.hostname)) return { error: "host not allowed" };
    const { address } = await lookup(url.hostname);
    const range = ipaddr.parse(address).range();
    if (range !== "unicast") return { error: "resolves to a non-public address" };
    const res = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(10_000) });
    return { body: await res.text() };
  },
});
```

1. If the tool only ever talks to one service, hard-code the base URL with `new
   URL(path, BASE)` and accept only a path or query from the model — never a full
   URL.
2. When a host must be dynamic, validate it against an allow-list, resolve the
   hostname, and re-check the resolved IP against private / loopback / link-local
   ranges to defeat DNS rebinding.
3. Set `redirect: "error"` (or validate each hop) so a 302 cannot bounce the
   request into an internal address, and always set an `AbortSignal.timeout(...)`.
4. Treat the fetched body as untrusted — keep it out of the system prompt and do
   not let it expand the agent's permissions.
