---
policy_id: pydantic_ai_tracing
category: pydantic_ai
topic: tracing
rules:
  - id: PYD-202
    severity: low
    confidence: 0.75
    scope: repo
    fix_type: config
  - id: PYD-107
    severity: low
    confidence: 0.7
    scope: agent
    fix_type: code
references: [LLM10]
---
# Policy Rationale: Pydantic AI Observability Configuration

**Policy ID:** `pydantic_ai_tracing`  
**File:** `pydantic_ai/tracing.yaml`  
**Rules:** PYD-202, PYD-107  
**Severities:** low, low  
**Fix types:** config, code  
**References:** LLM10 (Unbounded Consumption)

---

## What this policy covers

Two checks for Pydantic AI projects: whether the project wires any
observability at all (PYD-202), and whether an individual `Agent(...)` is left
uninstrumented while the rest of the project reports (PYD-107).

---

## Why observability is a distinct concern in Pydantic AI projects

Pydantic AI's defining feature is structured output: the model's
response is validated against a schema, and on failure the agent retries with the
validation error fed back to the model. That retry loop is where the cost and the
latency live, and it is invisible from the outside — the caller sees one result,
not the three attempts that produced it.

The SDK emits OpenTelemetry GenAI spans natively once instrumentation is switched
on, so this data is available essentially for free. A project with no
instrumentation is not missing a hard-to-build capability; it is discarding one
that ships in the box.

---

## Rule-by-rule defense

### PYD-202 — Pydantic AI project wires no observability (Severity: low, Confidence: 0.75, Fix type: config)

**What we detect:**  
PYD-202: Pydantic AI code is present, no observability signal was
found, and the repo is inspectable. No observability package is declared in a hand-edited dependency manifest
either (`repo_observability_declared: false`): a repo that ships a tracing
dependency it never wired draws OBS-005 at medium instead, since it has
claimed coverage it does not have. PYD-107: the repo has observability, but this
`Agent(...)` sets no `instrument` kwarg (`agent_kwarg_missing: [instrument]`).

**Why it is flaggable:**  
Without instrumentation the validation-retry loop leaves no record: a
run that retried three times and one that succeeded immediately are
indistinguishable in the application's own logs. For PYD-107, a project-level
`logfire.instrument_pydantic_ai()` would cover every agent; an agent relying on
per-instance `instrument=` that was never set is silently excluded from an
otherwise complete trace view.

**Real-world consequence:**  
- An `output_type` is tightened and a model starts failing validation on 30% of
  runs. Token spend rises and latency doubles; with no traces the symptom looks
  like a slow provider.
- A batch agent is added without `instrument=True` alongside instrumented
  siblings. Its failures never surface, and the dashboard reads as healthy while
  the batch job silently degrades.

**Why severity is low and not medium:**  
Missing observability degrades diagnosis; it does not itself cause incorrect
behavior or expose data. Examples, tutorials, internal libraries, and prototypes
legitimately ship without it, and at medium this rule would exit 1 and fail CI on
every one of them. Low keeps the gap visible and scored without turning "no
tracing" into a build break. Contrast OBS-001, which is medium because it
describes instrumentation that is present and provably broken.

**Fix type — config:**  
PYD-202 is startup wiring (`config`). PYD-107 changes the agent
construction, or adds a process-wide instrument call (`code`).

**Confidence 0.75:**  
The 0.25 gap is detection reach, not judgement. False positives: instrumentation
configured entirely through environment variables or an auto-instrumentation
agent with no call site in the repo; a provider initialized in a deployment
wrapper outside the scanned tree; a vendor SDK absent from the detection table.
False negatives are structurally excluded — the rule fires only when *zero*
signals were found, and the `repo_observability_inspectable` gate suppresses it
in languages the pass does not read, so "we did not look" is never reported as
"you have none".

### PYD-107 — Agent is not instrumented while the rest of the project is (Severity: low, Confidence: 0.7, Fix type: code)

**What we detect:**  
PYD-202: Pydantic AI code is present, no observability signal was
found, and the repo is inspectable. PYD-107: the repo has observability, but this
`Agent(...)` sets no `instrument` kwarg (`agent_kwarg_missing: [instrument]`).

**Why it is flaggable:**  
Without instrumentation the validation-retry loop leaves no record: a
run that retried three times and one that succeeded immediately are
indistinguishable in the application's own logs. For PYD-107, a project-level
`logfire.instrument_pydantic_ai()` would cover every agent; an agent relying on
per-instance `instrument=` that was never set is silently excluded from an
otherwise complete trace view.

**Real-world consequence:**  
- An `output_type` is tightened and a model starts failing validation on 30% of
  runs. Token spend rises and latency doubles; with no traces the symptom looks
  like a slow provider.
- A batch agent is added without `instrument=True` alongside instrumented
  siblings. Its failures never surface, and the dashboard reads as healthy while
  the batch job silently degrades.

**Why severity is low and not medium:**  
This rule fires only in repos that already have observability, so it reports an
inconsistency rather than an absence. The inconsistency is worth surfacing — a
trace view that silently omits one agent is more misleading than one that is
plainly empty — but it does not change agent behavior or expose data, and a
project may have deliberately excluded this agent. Low keeps it visible without
failing the build.

**Fix type — code:**  
PYD-202 is startup wiring (`config`). PYD-107 changes the agent
construction, or adds a process-wide instrument call (`code`).

**Confidence 0.7:**  
The 0.30 gap is about intent and about kwarg reach. False positives: the agent is
instrumented through a process-wide call rather than its own kwarg; the kwarg is
set indirectly through a config object or a spread/**kwargs the discovery pass
does not resolve; the agent is deliberately excluded (a local debug path, a test
fixture). False negatives: the kwarg is present but set to a falsy value, which
this predicate reads as instrumented.

---

## What this policy does not cover

- **Declarative instrumentation.** `opentelemetry-instrument`, `OTEL_*`
  environment configuration, a collector sidecar, or a platform-injected agent
  leaves no call site, so a fully instrumented deployment can still fire the
  absence rule.
- **Languages the pass does not parse.** Phase 1 reads Python and
  TypeScript/JavaScript. The `repo_observability_inspectable` gate keeps the
  rule silent elsewhere rather than guessing from an empty result.
- **Whether the wiring works.** Any signal at all silences the absence rule,
  even if the instrumentation is never initialized (OBS-001), exports only to
  the console (OBS-002), or samples at zero.
- **Trace quality.** Nothing here checks GenAI semantic-convention compliance,
  token/cost attributes, or error status recording.

---

## Recommendations beyond the fix

```python
import logfire
from pydantic_ai import Agent

logfire.configure(service_name="triage")
logfire.instrument_pydantic_ai()   # instruments every agent in the process

agent = Agent(
    "openai:gpt-4o",
    output_type=TriageResult,
    instrument=True,               # PYD-107: explicit per-agent opt-in
)
```

1. **Alert on retry count, not just latency.** Validation retries are the
   earliest signal that a prompt and an `output_type` have drifted apart.
2. **Keep `include_content` off in production.** Pydantic AI can attach message
   bodies to spans; that is OBS-003 territory once it is on.
3. **Prefer the process-wide instrument call** over per-agent kwargs, so a newly
   added agent is instrumented by default rather than by memory.
