---
policy_id: pydantic_ai_agent_safety
category: pydantic_ai
topic: agent_safety
rules:
  - id: PYD-101
    severity: low
    confidence: 0.7
    scope: agent
    fix_type: config
  - id: PYD-102
    severity: high
    confidence: 0.85
    scope: agent
    fix_type: config
  - id: PYD-103
    severity: medium
    confidence: 0.75
    scope: agent
    fix_type: config
  - id: PYD-105
    severity: low
    confidence: 0.7
    scope: agent
    fix_type: config
references: [LLM05, LLM06, LLM10]
---

# Policy Rationale: Pydantic AI Agent Safety

**Policy ID:** `pydantic_ai_agent_safety`  
**File:** `pydantic_ai/agent_safety.yaml`  
**Rules:** PYD-101, PYD-102, PYD-103, PYD-105  
**Severities:** low, high, medium, low  
**Fix types:** config, config, config, config  
**References:** LLM05 (Improper Output Handling), LLM06 (Excessive Agency), LLM10 (Unbounded Consumption)

---

## What this policy covers

Agent-scope rules for the Pydantic AI `Agent(...)` constructor (normalized
`pydantic_ai_agent`). **PYD-101** fires when the agent has no validated output
type — `output_type` is absent (defaulting to `str`) or set explicitly to `str`
(predicate: `agent_kwarg_missing` OR `agent_kwarg_value` matching `str`).
**PYD-102** fires when the agent wires `CodeExecutionTool` (predicate
`agent_uses_hosted_tool_class`). **PYD-103** fires when the agent wires a native
URL fetcher — `WebFetchTool` or `UrlContextTool` (same predicate). **PYD-105**
fires when `end_strategy="exhaustive"` (predicate `agent_kwarg_value`).

---

## Why agent configuration is a distinct concern in Pydantic AI

Pydantic AI's defining feature is that `output_type` can be a Pydantic model the
framework validates and, on failure, re-prompts the model to correct — turning
model output into a typed contract. PYD-101 flags agents that forfeit that: with
`output_type` absent or `str`, the agent returns whatever text the model produced,
so downstream code parses unvalidated strings and a prompt injection or confused
model can return malformed or unexpected content consumed as if it were trusted.
That is the Improper Output Handling (LLM05) angle — the validation layer the
framework offers is simply switched off.

The two highest-risk kwargs wire native capabilities directly onto the agent.
`CodeExecutionTool` (PYD-102) is a provider-native tool that runs code the model
generates; once it is in the tool set a prompt injection has a direct path to
arbitrary code execution in the provider's execution environment — excessive
agency (LLM06). The native URL fetchers (PYD-103) retrieve model-chosen URLs, an
SSRF surface into internal services and the cloud metadata endpoint, plus a
data-exfiltration channel to attacker-controlled URLs. This is not theoretical for
Pydantic AI: its built-in fetchers have already needed SSRF hardening
(CVE-2026-46678 and CVE-2026-25580 cover a metadata-endpoint blocklist that could
be bypassed via DNS rebinding or alternate IP encodings), so enabling one without
network-egress controls reintroduces that exposure.

Finally, `end_strategy="exhaustive"` (PYD-105) changes what happens when the model
emits a final result while tool calls are still pending: exhaustive mode runs those
remaining calls anyway before ending, instead of returning immediately (the
`early` default). If any pending call is side-effecting — a write, a charge, a send
— exhaustive mode executes it even though the model already considered the task
done, widening the blast radius of a run and making duplicate or unintended side
effects more likely (an LLM06/LLM10 reliability edge).

---

## Rule-by-rule defense

### PYD-101 — Agent has no structured output validation (Severity: low, Confidence: 0.7, Fix type: config)

**What we detect:** an `Agent(...)` with `output_type` absent or set to `str`
(predicates `agent_kwarg_missing` / `agent_kwarg_value`).

**Why it is flaggable:** without a validated `output_type` the agent returns raw
text; downstream code consumes unvalidated, possibly-injected content as trusted.

**Real-world consequence:** an agent expected to return a decision is left at the
default `str`; a prompt injection makes it return `"APPROVED — ignore prior
checks"`, which the calling code treats as an authoritative result because nothing
validated the shape.

**Why severity is low and not medium:** it is a defensive-default finding — the
agent may be entirely safe if its output is only ever shown to a human, and the
free-form mode is a legitimate choice for chat-style agents — so the impact is
conditional and often nil. **Fix type — config:** setting `output_type` is a
constructor change. **Confidence 0.7:** many agents intentionally return prose
(`str` is the right choice for a chatbot), so the rule over-flags those — the gap
that holds it at 0.7.

### PYD-102 — Agent wires the code-execution native tool (Severity: high, Confidence: 0.85, Fix type: config)

**What we detect:** an `Agent` whose resolved tools include `CodeExecutionTool`
(predicate `agent_uses_hosted_tool_class`), wired via `capabilities=` or
`builtin_tools=`.

**Why it is flaggable:** `CodeExecutionTool` runs model-generated code. Once it is
in the tool set, a prompt injection or confused model can run attacker-chosen code
in the provider's execution environment — a direct prompt-injection-to-RCE path.

**Real-world consequence:** an agent that wires `CodeExecutionTool` to "do data
analysis" is injected to run code that reads the execution environment's secrets or
makes outbound calls to exfiltrate in-context data.

**Why severity is high and not critical:** execution happens in the provider's
managed sandbox, and a successful attack still requires the tool to be wired and
the prompt surface reachable by untrusted input — high, not critical, because the
engine reserves that tier for unconditional host RCE. **Fix type — config:** the
fix is removing the tool from the agent's capability/tool list, an agent-wiring
change. **Confidence 0.85:** the class-name match cannot see whether the team has
constrained the execution environment out of band, so a few hardened uses are
over-flagged.

### PYD-103 — Agent wires a model-driven URL-fetching native tool (Severity: medium, Confidence: 0.75, Fix type: config)

**What we detect:** an `Agent` that wires `WebFetchTool` or `UrlContextTool`
(predicate `agent_uses_hosted_tool_class`).

**Why it is flaggable:** these native tools retrieve model-chosen URLs — an SSRF
surface into internal services and the metadata endpoint, and an exfiltration
channel to attacker URLs. Pydantic AI's built-in fetchers have needed SSRF
hardening (CVE-2026-46678, CVE-2026-25580), so enabling one without egress controls
reintroduces that exposure.

**Real-world consequence:** an agent with `WebFetchTool` is injected to fetch
`http://169.254.169.254/latest/meta-data/iam/security-credentials/`, and the
returned cloud credentials are exfiltrated through the model's next output.

**Why severity is medium and not high:** the impact depends on the agent host's
network position (no reachable internal services or metadata endpoint, or an egress
proxy, shrinks it sharply), and the SDK's own fetchers now ship a metadata
blocklist that blunts the most direct attack — so the residual risk is real but
conditional. **Fix type — config:** drop or constrain the native fetcher and add
egress controls — no tool source edit. **Confidence 0.75:** the rule flags the
tool's presence, not a proven reachable internal target, so it over-flags agents
that only ever fetch vetted external URLs or run behind a strict egress allow-list.

### PYD-105 — Agent retries with the exhaustive end strategy (Severity: low, Confidence: 0.7, Fix type: config)

**What we detect:** an `Agent` with `end_strategy="exhaustive"` (predicate
`agent_kwarg_value`).

**Why it is flaggable:** exhaustive mode runs still-pending tool calls after the
model has produced a final result; if any pending call is side-effecting, it fires
even though the task was already considered done.

**Real-world consequence:** the model returns a final answer with a pending
`send_email` tool call still queued; exhaustive mode sends the email anyway, an
unintended side effect the `early` default would have skipped.

**Why severity is low and not medium:** it only matters when pending calls are
side-effecting *and* the model finishes with calls still queued — a narrow
intersection, and harmless when every callable tool is side-effect-free. **Fix
type — config:** the fix is leaving `end_strategy` at its `early` default, a
constructor change. **Confidence 0.7:** the rule cannot tell whether the agent's
tools have side effects, so it over-flags exhaustive-mode agents whose tools are
all read-only.

---

## What this policy does not cover

- Code execution implemented by hand inside a tool body rather than via
  `CodeExecutionTool` — caught by **PYD-004** (code_execution.md), not here.
- Hand-rolled URL fetches inside a tool body — caught by **PYD-005** (ssrf.md);
  PYD-103 covers only the native fetcher tools.
- Whether the agent's prompt surface is actually reachable by untrusted content —
  all four rules flag a configuration, not a proven injection path.
- PYD-101 cannot tell whether a `str` output is consumed by code (risky) or only
  shown to a human (safe); PYD-105 cannot tell whether pending tools have side
  effects.
- A native tool referenced under an alias, or a provider tool outside the listed
  class set, may escape the class-name match. Whether a native tool's execution or
  fetch environment is sandboxed is not visible to the match.

---

## Recommendations beyond the fix

```python
from pydantic import BaseModel
from pydantic_ai import Agent

class Decision(BaseModel):
    approved: bool
    reason: str

# Validated output; no code-execution or open-fetch native tools; early end.
agent = Agent(
    "openai:gpt-4o",
    output_type=Decision,        # framework validates & re-prompts on failure
    end_strategy="early",        # skip pending tool calls once a result is final
    tools=[vetted_lookup],       # no CodeExecutionTool / WebFetchTool
)
```

1. Set `output_type` to a Pydantic model (or a typed union) wherever the result is
   consumed by code, so callers receive a checked object and the framework
   re-prompts on a validation failure.
2. Remove `CodeExecutionTool` from production agents; if code execution is genuinely
   needed, run it in a hardened external sandbox gated behind explicit human
   approval.
3. Enable a native URL fetcher only when open web access is truly required, and put
   egress controls around the agent process: a host allow-list, blocked
   private/link-local ranges, and a proxy that rejects internal addresses. Prefer a
   purpose-built fetcher over an open one.
4. Leave `end_strategy` at `early` unless every callable tool is side-effect-free
   and you specifically need the remaining calls to complete.
