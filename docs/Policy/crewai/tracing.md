---
policy_id: crewai_tracing
category: crewai
topic: tracing
rules:
  - id: CREW-202
    severity: low
    confidence: 0.75
    scope: repo
    fix_type: config
references: [LLM10]
---
# Policy Rationale: CrewAI Observability Configuration

**Policy ID:** `crewai_tracing`  
**File:** `crewai/tracing.yaml`  
**Rules:** CREW-202  
**Severities:** low  
**Fix types:** config  
**References:** LLM10 (Unbounded Consumption)

---

## What this policy covers

A repo-scoped check: the project defines a CrewAI crew in code, no
observability signal was found, and the repo contains a language the
observability pass parses.

---

## Why observability is a distinct concern in CrewAI projects

A CrewAI crew is a hand-off chain. A researcher agent produces notes, a
writer agent consumes them, a reviewer agent checks the result. A defect surfaces
at the end of that chain but is usually introduced several hand-offs earlier —
the researcher hallucinated a figure, and everything downstream faithfully
propagated it.

With no per-agent traces, the only visible artifact is the crew's final output.
There is no way to attribute the defect to the agent that introduced it, which is
precisely the attribution the multi-agent design was adopted to get.

---

## Rule-by-rule defense

### CREW-202 — CrewAI project wires no observability (Severity: low, Confidence: 0.75, Fix type: config)

**What we detect:**  
CrewAI code is present (`repo_has_sdk_in_code: [crewai]`), no
observability signal of any kind was found, and the repo is inspectable. No observability package is declared in a hand-edited dependency manifest
either (`repo_observability_declared: false`): a repo that ships a tracing
dependency it never wired draws OBS-005 at medium instead, since it has
claimed coverage it does not have.

**Why it is flaggable:**  
Delegation multiplies model calls: each agent runs its own loop, and
`kickoff()` returns only the last one's output. Token spend and latency are
aggregates over a tree that is never recorded, so neither cost regressions nor
quality regressions can be traced to an agent.

**Real-world consequence:**  
- A crew's output quality drops after a prompt tweak to one agent. With no
  per-agent traces, the team A/B-tests the whole crew instead of reading the one
  agent's runs.
- A delegation loop forms between two agents and burns tokens until the process
  is killed. Nothing records the loop, so the trigger stays unknown.

**Why severity is low and not medium:**  
Missing observability degrades diagnosis; it does not itself cause incorrect
behavior or expose data. Examples, tutorials, internal libraries, and prototypes
legitimately ship without it, and at medium this rule would exit 1 and fail CI on
every one of them. Low keeps the gap visible and scored without turning "no
tracing" into a build break. Contrast OBS-001, which is medium because it
describes instrumentation that is present and provably broken.

**Fix type — config:**  
Initialization at process start, before `kickoff()`. No crew or agent
definition changes.

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
import agentops
from crewai import Crew

agentops.init(default_tags=["research-crew"])   # before kickoff()

crew = Crew(agents=[researcher, writer], tasks=[research_task, write_task])
result = crew.kickoff()
```

1. **Attribute spans per agent and per task**, not per crew, or the trace
   collapses into a single opaque run.
2. **Record delegation edges.** The hand-off is the unit of failure in a crew;
   a trace that omits it cannot answer "who introduced this".
3. **Bound the run and alert on turn count**, so a delegation loop surfaces as an
   alert rather than as a bill.
