---
policy_id: langchain_tracing
category: langchain
topic: tracing
rules:
  - id: LC-202
    severity: low
    confidence: 0.75
    scope: repo
    fix_type: config
  - id: LC-112
    severity: low
    confidence: 0.7
    scope: agent
    fix_type: code
references: [LLM10]
---
# Policy Rationale: LangChain Observability Configuration

**Policy ID:** `langchain_tracing`  
**File:** `langchain/tracing.yaml`  
**Rules:** LC-202, LC-112  
**Severities:** low, low  
**Fix types:** config, code  
**References:** LLM10 (Unbounded Consumption)

---

## What this policy covers

Two repo- and agent-scoped checks for LangChain / LangGraph projects:
whether the project wires any observability at all (LC-202), and whether an
individual agent is left out of instrumentation the rest of the project has
(LC-112).

---

## Why observability is a distinct concern in LangChain projects

A LangChain chain or a LangGraph graph is a tree of steps: a retriever,
a prompt, a model call, an output parser, a tool, then often another model call
over the result. A wrong final answer is almost always produced by one
intermediate step — a retriever that returned nothing, a parser that silently
coerced a malformed response, a tool that errored and was swallowed by a
fallback.

Reading the final output tells you nothing about which step failed. The framework
records the intermediate steps only if a callback handler is attached, so a
project with no handler discards exactly the data that makes a failure
diagnosable. LangGraph sharpens this: the executed path through the graph is
decided at runtime by state, so the source cannot tell you which branch ran.

---

## Rule-by-rule defense

### LC-202 — LangChain project wires no observability (Severity: low, Confidence: 0.75, Fix type: config)

**What we detect:**  
LC-202: LangChain or LangGraph code is present, no observability
signal was found, and the repo is inspectable. No observability package is declared in a hand-edited dependency manifest
either (`repo_observability_declared: false`): a repo that ships a tracing
dependency it never wired draws OBS-005 at medium instead, since it has
claimed coverage it does not have. LC-112: the repo *does* have
observability (`repo_has_observability: true`) but this agent is constructed with
no `callbacks` kwarg (`agent_kwarg_missing: [callbacks]`).

**Why it is flaggable:**  
LangChain emits its step-level events through the callback system. No
handler means the events are generated and dropped. For LC-112 the consequence is
sharper than plain absence: sibling agents report through the project's handler,
so the trace view looks complete while silently omitting this agent's runs.

**Real-world consequence:**  
- A RAG chain begins answering from stale context. With no callback handler,
  there is no record of what the retriever returned, so the team debugs the
  prompt for a week before finding the index.
- One `AgentExecutor` in a service is constructed without `callbacks` while three
  others have them. Its failures never appear on the dashboard, and the gap is
  discovered only when someone counts runs against request logs.

**Why severity is low and not medium:**  
Missing observability degrades diagnosis; it does not itself cause incorrect
behavior or expose data. Examples, tutorials, internal libraries, and prototypes
legitimately ship without it, and at medium this rule would exit 1 and fail CI on
every one of them. Low keeps the gap visible and scored without turning "no
tracing" into a build break. Contrast OBS-001, which is medium because it
describes instrumentation that is present and provably broken.

**Fix type — config:**  
LC-202 is provider/handler wiring at startup (`config`). LC-112
requires changing the agent's construction to pass the handler (`code`).

**Confidence 0.75:**  
The 0.25 gap is detection reach, not judgement. False positives: instrumentation
configured entirely through environment variables or an auto-instrumentation
agent with no call site in the repo; a provider initialized in a deployment
wrapper outside the scanned tree; a vendor SDK absent from the detection table.
False negatives are structurally excluded — the rule fires only when *zero*
signals were found, and the `repo_observability_inspectable` gate suppresses it
in languages the pass does not read, so "we did not look" is never reported as
"you have none".

### LC-112 — Agent has no callbacks while the rest of the project is instrumented (Severity: low, Confidence: 0.7, Fix type: code)

**What we detect:**  
LC-202: LangChain or LangGraph code is present, no observability
signal was found, and the repo is inspectable. LC-112: the repo *does* have
observability (`repo_has_observability: true`) but this agent is constructed with
no `callbacks` kwarg (`agent_kwarg_missing: [callbacks]`).

**Why it is flaggable:**  
LangChain emits its step-level events through the callback system. No
handler means the events are generated and dropped. For LC-112 the consequence is
sharper than plain absence: sibling agents report through the project's handler,
so the trace view looks complete while silently omitting this agent's runs.

**Real-world consequence:**  
- A RAG chain begins answering from stale context. With no callback handler,
  there is no record of what the retriever returned, so the team debugs the
  prompt for a week before finding the index.
- One `AgentExecutor` in a service is constructed without `callbacks` while three
  others have them. Its failures never appear on the dashboard, and the gap is
  discovered only when someone counts runs against request logs.

**Why severity is low and not medium:**  
This rule fires only in repos that already have observability, so it reports an
inconsistency rather than an absence. The inconsistency is worth surfacing — a
trace view that silently omits one agent is more misleading than one that is
plainly empty — but it does not change agent behavior or expose data, and a
project may have deliberately excluded this agent. Low keeps it visible without
failing the build.

**Fix type — code:**  
LC-202 is provider/handler wiring at startup (`config`). LC-112
requires changing the agent's construction to pass the handler (`code`).

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
from langchain.agents import AgentExecutor
from langfuse.callback import CallbackHandler

handler = CallbackHandler()

executor = AgentExecutor(
    agent=agent,
    tools=tools,
    max_iterations=10,
    callbacks=[handler],   # LC-112: this agent reports like its siblings
)
```

1. **Prefer a globally configured handler** over per-constructor wiring, so a
   new chain inherits instrumentation instead of needing to remember it.
2. **Trace the retriever, not only the model call.** In a RAG failure the
   retrieved documents are the evidence; a trace that records only the LLM span
   omits the cause.
3. **Record the graph node name on LangGraph spans** so the executed path is
   reconstructable from the trace.
