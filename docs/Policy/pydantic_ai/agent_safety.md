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
  - id: PYD-106
    severity: low
    confidence: 0.6
    scope: agent
    fix_type: config
references: [LLM05, LLM06, LLM10]
---

# Policy Rationale: Pydantic AI Agent Safety

**Policy ID:** `pydantic_ai_agent_safety`  
**File:** `pydantic_ai/agent_safety.yaml`  
**Rules:** PYD-101, PYD-102, PYD-103, PYD-105, PYD-106  
**Severities:** low, high, medium, low, low  
**Fix types:** config, config, config, config, config  
**References:** LLM05 (Improper Output Handling), LLM06 (Excessive Agency), LLM10 (Unbounded Consumption)

---

## What this policy covers

Agent-scope rules for the Pydantic AI `Agent(...)` constructor (normalized
`pydantic_ai_agent`). **PYD-101** fires when the agent has no validated output
type — `output_type` is absent (defaulting to `str`) or set explicitly to `str`
(predicate: `agent_kwarg_missing` OR `agent_kwarg_value` matching `str`).
**PYD-102** fires when the agent wires `CodeExecutionTool` (predicate
`agent_uses_hosted_tool_class`). **PYD-103** fires when the agent wires a native
web-retrieval tool — `WebFetchTool`, `UrlContextTool`, or `WebSearchTool` (same
predicate). **PYD-105** fires when `end_strategy="exhaustive"` (predicate
`agent_kwarg_value`). **PYD-106** is different in kind from the four above: it
does not read the constructor at all, but correlates this agent's construction
site to the `run`/`run_sync`/`run_stream` call(s) that execute it and fires
when none of them sets `usage_limits` — an execution-limit / cost concern
(LLM10, Unbounded Consumption), distinct from the output-validation and
excessive-agency framing of the rules above it.

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

PYD-106 sits in the same LLM10 territory as PYD-105's reliability edge, but is
architecturally different from every rule above it: none of PYD-101/102/103/105
look past the `Agent(...)` constructor, while PYD-106 correlates this agent's
construction to the call that actually runs it — `agent.run`/`run_sync`/
`run_stream` — and asks whether any of those calls sets `usage_limits`. Left
unset, Pydantic AI falls back to a bare `UsageLimits()`, which caps request
count but leaves token and cost usage completely unbounded. A model that loops
or oscillates, or a single run whose tool-calling chain balloons unexpectedly,
can burn far more tokens and cost than the task warrants before the request
cap is ever reached — nothing in the default stops a single expensive run from
running the bill up. This is the Pydantic AI analogue of the OpenAI Agents
SDK's OAI-112 (`max_turns`), CrewAI's CREW-110 (`max_iter`), and the Claude
Agent SDK's CSDK-204 (`max_turns` on `ClaudeAgentOptions`): a missing explicit,
task-sized execution bound, not a capability grant.

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

### PYD-103 — Agent wires a model-driven web-fetching or search native tool (Severity: medium, Confidence: 0.75, Fix type: config)

**What we detect:** an `Agent` that wires `WebFetchTool`, `UrlContextTool`, or
`WebSearchTool` (predicate `agent_uses_hosted_tool_class`). `WebSearchTool` is
matched alongside the URL fetchers because it is the fourth member of discovery's
native-tool set and shares the retrieval threat model — before this, an agent
wiring it was silent while the equivalent grants fired in the OpenAI and ADK
packs.

**Why it is flaggable:** the URL fetchers retrieve model-chosen URLs — an SSRF
surface into internal services and the metadata endpoint, and an exfiltration
channel to attacker URLs. For `WebSearchTool`, the model-chosen query is itself an
exfiltration channel, and the returned results are attacker-reachable text that
re-enters the context as a second-order prompt-injection channel. Pydantic AI's
built-in fetchers have needed SSRF hardening (CVE-2026-46678, CVE-2026-25580), so
enabling one without egress controls reintroduces that exposure.

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

### PYD-106 — Pydantic AI agent has no explicit usage_limits set (Severity: low, Confidence: 0.6, Fix type: config)

**What we detect:** this agent has at least one resolvable `<agent>.run` /
`run_sync` / `run_stream` call that executes it — found by a second,
independent discovery pass that matches the call's method **receiver**
identifier to this agent's `VarName`, in the same file — and none of those
calls sets `usage_limits` (predicate
`agent_run_call_usage_limits_missing`). Like OAI-112, this correlates two
separately discovered structures — the agent's `AgentDef` and one or more
`AgentRunCallDef`s — by same-file variable name, rather than reading kwargs
off a single constructor call as PYD-101/102/103/105 do. Pydantic AI has no
fixed "Runner" class the way the OpenAI Agents SDK does, so the discoverer
treats any `<identifier>.run(...)`/`run_sync(...)`/`run_stream(...)` in a file
that imports Pydantic AI as a candidate call; over-capturing here is safe
because a receiver name that does not correspond to any discovered agent in
the same file simply never correlates to a finding. A call whose receiver is
not a plain identifier is skipped, and an agent with no matching run call at
all never fires.

**Why it is flaggable:** with no `usage_limits` on any call that runs it, the
agent falls back to a bare `UsageLimits()` — capping request count but leaving
token and cost usage completely unbounded. A model that loops or oscillates,
or a single run that balloons into an unexpectedly long tool-calling chain,
can burn far more tokens and cost than the task warrants before the request
cap is ever reached, and nothing stops a single expensive run from running the
bill up.

**Real-world consequence:** an agent is run via `agent.run_sync(user_input)`
with no `usage_limits`; a tool that returns increasingly large context on each
retry drives the run's token spend far past what the task justifies, with only
the bare request cap left to eventually stop it — a silent cost overrun rather
than a clean, observable `UsageLimitExceeded`.

**Why severity is low and not medium:** the default `UsageLimits()` still caps
request count, so this is not a fully unbounded run — it is a missing
*explicit, task-sized* bound on token and cost spend specifically. That places
it alongside OAI-112, CREW-110, and CSDK-204: a generic partial ceiling
already limits part of the damage, so the finding is real but modest.

**Fix type — config:** pass `usage_limits=UsageLimits(...)` to
`agent.run`/`run_sync`/`run_stream`, sized to the task — `request_limit` for a
hard step count, and `total_tokens_limit` or
`input_tokens_limit`/`output_tokens_limit` to bound token spend directly. Like
OAI-112, this fix lands on the call that executes the agent, not the
`Agent(...)` constructor — the only rule in this policy that reaches past the
constructor. Treat hitting the limit as a signal to surface and handle rather
than to raise it.

**Confidence 0.6:** lower than PYD-101/102/103/105 because the predicate
correlates two separately discovered structures — `AgentDef` and
`AgentRunCallDef` — by same-file variable name, instead of reading kwargs off
one constructor call. Cross-file correlation is not attempted: an agent
constructed in one file and run via `.run(...)` in another is invisible to
this rule and never fires — a false negative the rule does not attempt to
close. And because the check only asks whether *any* matching run call sets
`usage_limits`, an agent run multiple times with inconsistent settings goes
silent on the strength of a single compliant call, even though another call
that executes the same agent may leave usage completely unbounded. The
remaining gaps mirror CSDK-204's own 0.6: a call built with `**` unpacking is
skipped as unresolvable (`Opaque: true`), a cap enforced by a wrapper or retry
harness outside the call itself is invisible, and a `usage_limits` value
passed via a variable the scanner cannot resolve to a literal reads as absent.

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
- For PYD-106: an agent constructed in one file and executed via `.run(...)` in
  another — the `AgentDef`-to-`AgentRunCallDef` correlation is same-file-VarName
  only, so a cross-file execution site is invisible and the rule stays silent.
  An agent run multiple times where only one call sets `usage_limits` also
  escapes detection: any single matching call that sets it silences the
  finding entirely, even if other calls that execute the same agent leave
  usage unbounded. Pydantic AI's default `UsageLimits()` `request_limit` value
  is not independently verified or asserted as a specific number in this doc,
  beyond the language already present in the shipped rule's own explanation
  text.

---

## Recommendations beyond the fix

```python
from pydantic import BaseModel
from pydantic_ai import Agent
from pydantic_ai.usage import UsageLimits

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

result = agent.run_sync(
    user_input,
    usage_limits=UsageLimits(request_limit=10, total_tokens_limit=20_000),  # PYD-106
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
5. Pass `usage_limits=UsageLimits(...)` sized to the task on whichever
   `run`/`run_sync`/`run_stream` call executes the agent, and keep it
   consistent across every call site that runs the same agent.
