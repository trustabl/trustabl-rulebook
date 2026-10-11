---
policy_id: vercel_ai_tracing
category: vercel_ai
topic: tracing
rules:
  - id: VAI-201
    severity: low
    confidence: 0.75
    scope: repo
    fix_type: config
  - id: VAI-101
    severity: low
    confidence: 0.7
    scope: agent
    fix_type: code
references: [LLM10]
---
# Policy Rationale: Vercel AI SDK Observability Configuration

**Policy ID:** `vercel_ai_tracing`  
**File:** `vercel_ai/tracing.yaml`  
**Rules:** VAI-201, VAI-101  
**Severities:** low, low  
**Fix types:** config, code  
**References:** LLM10 (Unbounded Consumption)

---

## What this policy covers

Two checks for Vercel AI SDK projects: whether the project registers
any observability at all (VAI-201), and whether an individual generation call
omits `experimental_telemetry` while the project has a provider registered
(VAI-101).

---

## Why observability is a distinct concern in Vercel AI SDK projects

The Vercel AI SDK has a two-part telemetry contract that is unusually
easy to half-satisfy: a provider must be registered once at startup, **and**
telemetry must be enabled on each call via `experimental_telemetry`. Satisfying
only the first produces no spans at all, which is the trap — the setup step that
feels like "turning on tracing" is not sufficient on its own.

The SDK's common deployment shape makes this worse. Generations run in serverless
handlers and stream to the client, so a run that fails mid-stream terminates a
response the user already started reading. Tool round-trips inside that stream
leave no record unless telemetry was enabled on the call that made them.

---

## Rule-by-rule defense

### VAI-201 — Vercel AI SDK project wires no observability (Severity: low, Confidence: 0.75, Fix type: config)

**What we detect:**  
VAI-201: Vercel AI SDK code is present, no observability signal was
found, and the repo is inspectable. No observability package is declared in a hand-edited dependency manifest
either (`repo_observability_declared: false`): a repo that ships a tracing
dependency it never wired draws OBS-005 at medium instead, since it has
claimed coverage it does not have. VAI-101: the repo has observability
(`repo_has_observability: true`) but this call passes no `experimental_telemetry`
(`agent_kwarg_missing: [experimental_telemetry]`).

**Why it is flaggable:**  
A registered `NodeSDK` or `registerOTel()` sets up the pipeline; the SDK
still emits nothing for a call that did not opt in. VAI-101 therefore fires on
exactly the configuration that looks correct from the setup file and produces no
data at the call site.

**Real-world consequence:**  
- A team adds `registerOTel()` and confirms the collector is receiving spans
  from HTTP instrumentation, then assumes the AI calls are covered. No generation
  span ever arrives, and the gap is found during an outage.
- One route's `streamText` omits `experimental_telemetry` while the rest of the
  app has it. That route's tool errors are invisible, and its token spend is
  missing from cost dashboards.

**Why severity is low and not medium:**  
Missing observability degrades diagnosis; it does not itself cause incorrect
behavior or expose data. Examples, tutorials, internal libraries, and prototypes
legitimately ship without it, and at medium this rule would exit 1 and fail CI on
every one of them. Low keeps the gap visible and scored without turning "no
tracing" into a build break. Contrast OBS-001, which is medium because it
describes instrumentation that is present and provably broken.

**Fix type — config:**  
VAI-201 is startup wiring (`config`). VAI-101 changes the call's
options object (`code`).

**Confidence 0.75:**  
The 0.25 gap is detection reach, not judgement. False positives: instrumentation
configured entirely through environment variables or an auto-instrumentation
agent with no call site in the repo; a provider initialized in a deployment
wrapper outside the scanned tree; a vendor SDK absent from the detection table.
False negatives are structurally excluded — the rule fires only when *zero*
signals were found, and the `repo_observability_inspectable` gate suppresses it
in languages the pass does not read, so "we did not look" is never reported as
"you have none".

### VAI-101 — Call has no experimental_telemetry while the project is instrumented (Severity: low, Confidence: 0.7, Fix type: code)

**What we detect:**  
VAI-201: Vercel AI SDK code is present, no observability signal was
found, and the repo is inspectable. VAI-101: the repo has observability
(`repo_has_observability: true`) but this call passes no `experimental_telemetry`
(`agent_kwarg_missing: [experimental_telemetry]`).

**Why it is flaggable:**  
A registered `NodeSDK` or `registerOTel()` sets up the pipeline; the SDK
still emits nothing for a call that did not opt in. VAI-101 therefore fires on
exactly the configuration that looks correct from the setup file and produces no
data at the call site.

**Real-world consequence:**  
- A team adds `registerOTel()` and confirms the collector is receiving spans
  from HTTP instrumentation, then assumes the AI calls are covered. No generation
  span ever arrives, and the gap is found during an outage.
- One route's `streamText` omits `experimental_telemetry` while the rest of the
  app has it. That route's tool errors are invisible, and its token spend is
  missing from cost dashboards.

**Why severity is low and not medium:**  
This rule fires only in repos that already have observability, so it reports an
inconsistency rather than an absence. The inconsistency is worth surfacing — a
trace view that silently omits one agent is more misleading than one that is
plainly empty — but it does not change agent behavior or expose data, and a
project may have deliberately excluded this agent. Low keeps it visible without
failing the build.

**Fix type — code:**  
VAI-201 is startup wiring (`config`). VAI-101 changes the call's
options object (`code`).

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

```typescript
import { registerOTel } from "@vercel/otel";
import { generateText } from "ai";

registerOTel({ serviceName: "support-agent" });   // VAI-201: register once

const result = await generateText({
  model,
  prompt,
  tools,
  experimental_telemetry: {                        // VAI-101: enable per call
    isEnabled: true,
    functionId: "support-answer",
    // recordInputs/recordOutputs stay off: prompt bodies would flow to the
    // backend verbatim (OBS-003).
  },
});
```

1. **Wrap the call site.** A thin helper that always sets
   `experimental_telemetry` removes the per-call opt-in as a thing to remember.
2. **Set `functionId` per call site** so spans are attributable to a route rather
   than pooled under one anonymous generation.
3. **Verify spans survive the serverless lifecycle.** A function frozen before
   the exporter flushes drops its spans; use the platform's flush hook.
