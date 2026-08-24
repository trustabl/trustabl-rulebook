---
policy_id: vercel_ai_observability
category: vercel_ai
topic: observability
rules:
  - id: VAI-017
    severity: low
    confidence: 0.65
    scope: tool
    fix_type: code
references: [LLM02]
---

# Policy Rationale: Vercel AI SDK Observability Hygiene

**Policy ID:** `vercel_ai_observability`  
**File:** `vercel_ai/observability.yaml`  
**Rules:** VAI-017  
**Severities:** low  
**Fix types:** code  
**References:** LLM02

---

## What this policy covers

This policy targets Vercel AI SDK `tool({ execute })` handlers that write
diagnostics to standard output via `console.log` / `console.info` /
`console.debug` / `process.stdout.write`. The detection is the structured
`has_print_call` predicate: for TypeScript tools it reads the discovery fact
`prints_stdout` set by a callee walk of the `execute` body. Because the fact
matches exact callees rather than a substring, lookalikes such as
`logger.log(...)` do not fire. stderr counterparts (`console.warn`,
`console.error`, `process.stderr.write`) are deliberately silent — they are
the remediation, not the defect.

---

## Why stdout diagnostics are a distinct concern in Vercel AI tools

In a conventional Node script, `console.log` is a reasonable way to surface
progress — a human is watching the terminal. A Vercel AI `execute()` handler
has no human watching: only the function's *return value* flows back into the
agent loop, so anything sent to stdout is invisible to the model. The
diagnostic the author meant as "show me what happened" never reaches the one
consumer (the model) that decides what to do next, and in production it
usually never reaches the operator either — structured log pipelines capture
logger records and JSON, not raw process stdout, so the print silently
evaporates exactly when an incident makes you want it.

The sharper, agent-specific failure is transport corruption. The Model Context
Protocol's stdio transport uses the process's **stdout as the wire** —
newline-delimited JSON-RPC frames. A tool that is reachable over an MCP stdio
server and calls `console.log("debug")` interleaves loose text between
JSON-RPC messages on that same channel. The client's parser then sees
malformed frames: responses get dropped, the session desyncs, and the failure
looks like an intermittent protocol bug far from its cause. Unlike a missing
log line, this is a hard break, not a cosmetic one — and the tool author who
added the `console.log` for local debugging has no signal that the same tool
will corrupt a stdio transport in another deployment.

There is a smaller security edge. Diagnostic prints frequently embed values
the tool is handling — `console.log("calling billing", { apiKey })`,
`console.log(await resp.json())` — and whatever captures the process's stdout
(container logs, a shared journald sink, a log-aggregation service) then holds
that data. In an agentic system the values passing through a tool often
include credentials, user PII, or upstream tool output, so a careless
diagnostic becomes a sensitive-information-disclosure path into log storage
with a different (usually broader) audience than the agent itself. This is the
LLM02 angle; it is secondary to the reliability concern but real.

---

## Rule-by-rule defense

### VAI-017 — Tool execute() writes diagnostics to stdout (Severity: low, Confidence: 0.65, Fix type: code)

**What we detect:**
A Vercel AI SDK `tool({ execute })` whose body calls `console.log`,
`console.info`, `console.debug`, or `process.stdout.write` (predicate
`has_print_call` via the `prints_stdout` discovery fact). stderr-bound
callees and unrelated `*.log` helpers are not matched.

**Why it is flaggable:**
A stdout write in a tool body is output sent to a channel no agent consumer
reads, and — when the tool is served over MCP stdio — to a channel that is
actively load-bearing for the protocol. The presence of the call is the
signal: the author routed information to stdout instead of to the return
value (which the model reads) or a logger / stderr (which operators read
without corrupting the wire).

**Real-world consequence:**
- A `lookupOrder({ orderId })` tool calls `console.log("DEBUG resolved", row)`.
  In production behind a JSON log pipeline the line is dropped; when a
  customer disputes a lookup there is no trace of what the tool saw.
- The same tool is later exposed through an MCP stdio server. Each
  `console.log` now emits a non-JSON line on stdout between JSON-RPC frames;
  the MCP client raises parse errors and intermittently loses tool responses,
  presenting as a flaky agent.
- `chargeCard(...)` calls `console.log("charging", amount, "with", apiKey)`
  for local debugging. The container's stdout is shipped to a shared logging
  backend, and the API key now sits in log storage readable by anyone with
  log access.

**Why severity is low and not medium:**
In the common case this is a reliability/observability degradation, not an
exploit — a missing log line or a noisy stream. The two ways it escalates
(stdio-transport corruption, secret-to-log disclosure) are both *conditional*:
the first only bites when the tool is served over an MCP stdio transport, the
second only when sensitive values are printed and stdout is captured to a
broader audience. Neither is guaranteed by the mere presence of a stdout
write, so the rule stays at `low`. It is not `info` because the
transport-corruption case is a hard functional break, not a style nit — and
`info` is reserved.

**Fix type — code:**
Removing the stdout write or replacing it with a module logger /
`console.error` / a field in the return value is an edit to the tool source.
No guardrail, hook, or agent constructor kwarg changes how a tool body writes
to stdout.

**Confidence 0.65:**
The gap reflects genuine ambiguity about whether a given stdout write is a
problem in the tool's actual deployment, which the rule cannot see. False
positives: a tool intentionally run only over a non-stdio transport
(HTTP/SSE) where stdout is harmlessly captured. False negatives: diagnostics
written through a custom logger that has been misconfigured to emit on
stdout, or indirection (`const log = console.log; log(...)`) that the callee
walk does not resolve. The 0.65 says: the pattern is reliably *present* when
flagged, but whether it is *harmful* depends on transport and on what is
printed — both outside the rule's view.

---

## What this policy does not cover

- `console.warn` / `console.error` / `process.stderr.write` — stderr is the
  remediation and must not fire.
- A logger configured (or misconfigured) with a transport pointing at stdout —
  that is a configuration issue, not a matched callee, and is invisible to the
  rule.
- `logger.log`, `pino`, `winston`, and other higher-level printers — the rule
  deliberately matches only the Node stdout callees above.
- Whether the tool is actually served over an MCP stdio transport. The
  transport-corruption risk is *potential*; the rule flags the precondition,
  not a confirmed break.

---

## Recommendations beyond the fix

```typescript
import { tool } from "ai";
import { z } from "zod";
import { createLogger } from "./logger";

const log = createLogger("tools.lookupOrder");

export const lookupOrder = tool({
  description: "Look up an order by id",
  inputSchema: z.object({ orderId: z.string() }),
  execute: async ({ orderId }) => {
    const row = await db.orders.find(orderId);
    // Ops: structured logger (or console.error). Never console.log on a
    // tool that might share a process with an MCP stdio server.
    log.info("resolved order", { orderId, status: row?.status });
    // Model: return the data the agent needs.
    return row ?? { error: "not_found", orderId };
  },
});
```

Prefer returning diagnostics the model should act on, and routing operator
diagnostics to a logger or stderr so stdout stays free for protocol frames.
