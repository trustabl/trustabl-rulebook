---
policy_id: google_adk_tracing
category: google_adk
topic: tracing
rules:
  - id: ADK-202
    severity: low
    confidence: 0.75
    scope: repo
    fix_type: config
references: [LLM10]
---
# Policy Rationale: Google ADK Observability Configuration

**Policy ID:** `google_adk_tracing`  
**File:** `google_adk/tracing.yaml`  
**Rules:** ADK-202  
**Severities:** low  
**Fix types:** config  
**References:** LLM10 (Unbounded Consumption)

---

## What this policy covers

A repo-scoped check: the project defines Google ADK agents in code, no
observability signal was found, and the repo contains a language the
observability pass parses.

---

## Why observability is a distinct concern in Google ADK projects

Google ADK composes agents structurally: `SequentialAgent`,
`ParallelAgent`, and `LoopAgent` wrap `LlmAgent` instances into a control-flow
graph. The composition is declared in source, but which branch actually executed,
how many iterations a `LoopAgent` ran, and which parallel child failed are all
runtime facts.

That is the specific gap here. A reader of the source knows the shape of the
graph and nothing about the run. Without traces, a `LoopAgent` that iterated to
its limit and one that exited on the first pass produce identical evidence.

---

## Rule-by-rule defense

### ADK-202 — Google ADK project wires no observability (Severity: low, Confidence: 0.75, Fix type: config)

**What we detect:**  
Google ADK code is present (`repo_has_sdk_in_code: [google_adk]`), no
observability signal of any kind was found, and the repo is inspectable. No observability package is declared in a hand-edited dependency manifest
either (`repo_observability_declared: false`): a repo that ships a tracing
dependency it never wired draws OBS-005 at medium instead, since it has
claimed coverage it does not have.

**Why it is flaggable:**  
Workflow agents multiply model calls per invocation, and the multiplier
is decided at runtime. Cost, latency, and failure all attribute to a node in a
graph that is never recorded, so a regression cannot be localized to the child
agent that caused it.

**Real-world consequence:**  
- A `LoopAgent` begins hitting its iteration cap because a sub-agent stopped
  meeting the exit condition. Latency triples; with no traces the cap looks like a
  slow model.
- One child of a `ParallelAgent` fails intermittently. The aggregate output
  degrades, and nothing in the logs says which child.

**Why severity is low and not medium:**  
Missing observability degrades diagnosis; it does not itself cause incorrect
behavior or expose data. Examples, tutorials, internal libraries, and prototypes
legitimately ship without it, and at medium this rule would exit 1 and fail CI on
every one of them. Low keeps the gap visible and scored without turning "no
tracing" into a build break. Contrast OBS-001, which is medium because it
describes instrumentation that is present and provably broken.

**Fix type — config:**  
Provider or vendor initialization at process start, before agents are
constructed. No agent definition changes.

**Confidence 0.75:**  
The 0.25 gap is detection reach, not judgement. False positives: instrumentation
configured entirely through environment variables or an auto-instrumentation
agent with no call site in the repo; a provider initialized in a deployment
wrapper outside the scanned tree; a vendor SDK absent from the detection table.
False negatives are structurally excluded — the rule fires only when *zero*
signals were found, and the `repo_observability_inspectable` gate suppresses it
in languages the pass does not read, so "we did not look" is never reported as
"you have none".

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
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from google.adk.agents import LlmAgent, SequentialAgent

provider = TracerProvider()
provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
trace.set_tracer_provider(provider)     # before the agents are built

pipeline = SequentialAgent(name="triage", sub_agents=[classify, resolve])
```

1. **Name spans after the workflow node** so the executed path through the graph
   is reconstructable.
2. **Record loop iteration counts as a span attribute**; a `LoopAgent` at its cap
   is a distinct failure from one that exited normally.
3. **Trace parallel children individually**, or a `ParallelAgent` failure cannot
   be attributed to a child.
