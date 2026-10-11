---
policy_id: openai_sdk_tracing
category: openai_sdk
topic: tracing
rules:
  - id: OAI-201
    severity: medium
    confidence: 0.8
    scope: repo
    fix_type: config
  - id: OAI-203
    severity: low
    confidence: 0.75
    scope: repo
    fix_type: config
references: [LLM02, LLM10]
---

# Policy Rationale: Tracing Configuration

**Policy ID:** `openai_sdk_tracing`  
**File:** `openai_sdk/tracing.yaml`  
**Rules:** OAI-201, OAI-203  
**Severities:** medium, low  
**Fix types:** config, config  
**References:** LLM02 (Sensitive Information Disclosure), LLM10 (Unbounded Consumption)

---

## What this policy covers

A repo-scoped check: the project uses the OpenAI Agents SDK in code AND leaves
tracing at its default (`repo_has_sdk_in_code: [openai_agents]` AND
`repo_uses_default_tracing: true`). `UsesDefaultTracing` is true when the scanner
finds no `add_trace_processor(...)` call and no `OPENAI_AGENTS_DISABLE_TRACING`
anywhere in the parsed Python. It fires once per scan, not per agent.

---

## Why default tracing is a distinct concern in agent tools

The OpenAI Agents SDK ships tracing **on by default**, and the default destination
is OpenAI's hosted tracing backend. What gets traced is not metadata — it is the
substance of the run: user inputs, tool call arguments, tool outputs, and agent
responses. For an agent that handles PII, credentials, internal documents, or
proprietary data, that is a continuous data-egress channel leaving the process for
a third-party service, established by doing nothing.

It is a distinct concern precisely because it is *silent and default-on*. There is
no dangerous call site to spot in a tool body; the data leaves because no one
turned the export off or inserted a redacting processor. In a conventional app, a
logging/telemetry integration is a deliberate, reviewable dependency; here it is the
out-of-the-box behavior. This maps to OWASP LLM02 (Sensitive Information
Disclosure): sensitive run content is disclosed to an external backend as a
side effect of the default configuration.

The fix is *config* — an environment variable or a one-line processor
registration, no tool or agent code change.

---

## Rule-by-rule defense

### OAI-201 — Project uses default OpenAI tracing (Severity: medium, Confidence: 0.8, Fix type: config)

**What we detect:** the repo uses the OpenAI Agents SDK in code and neither disables
tracing (`OPENAI_AGENTS_DISABLE_TRACING`) nor registers a custom trace processor
(`add_trace_processor`).

**Why it is flaggable:** default tracing exports run inputs, tool I/O, and responses
to OpenAI's hosted backend — an easy-to-miss egress of potentially sensitive data.

**Real-world consequence:** an agent that reads internal documents or handles
customer PII sends that content to the hosted tracing backend on every run, with no
redaction, simply because the default was never changed.

**Why severity is medium and not high:** it is a privacy/compliance and data-egress
issue rather than a direct compromise, and it is benign for projects that handle no
sensitive data or have an enterprise data agreement. It is not low because for
regulated or sensitive workloads the egress can be a real disclosure.

**Fix type — config:** set `OPENAI_AGENTS_DISABLE_TRACING=1`, or register a custom
trace processor that redacts sensitive fields before export.

**Confidence 0.8:** the gap covers projects where the hosted egress is acceptable
(no sensitive data, or a data-processing agreement in place) — there the finding is
informational rather than a defect — and the rare case where tracing is disabled by
a mechanism the scanner does not recognize.

### OAI-203 — OpenAI Agents SDK project wires no observability (Severity: low, Confidence: 0.75, Fix type: config)

**What we detect:**  
The repo uses the OpenAI Agents SDK in code (`repo_has_sdk_in_code:
[openai_agents]`), the scanner found no observability signal of any kind
(`repo_has_observability: false`), and the repo contains at least one language
the observability pass actually parses (`repo_observability_inspectable: true`),
and no observability package is declared in a hand-edited dependency manifest
(`repo_observability_declared: false`) — a repo that ships a tracing dependency
it never wired draws OBS-005 at medium instead, since it has claimed coverage it
does not have.
No OpenTelemetry provider, and no Langfuse, Logfire, Phoenix, Braintrust, Weave,
OpenLLMetry, MLflow, or AgentOps import or initialization appears anywhere in
the parsed source.

**Why it is flaggable:**  
An OpenAI Agents SDK run is a loop: the model selects a tool, the SDK executes
it, the result re-enters the context, and the loop repeats until a stop
condition. Which branch ran is decided at runtime by the model, so the source
does not record it. Without a trace there is no record of the tool sequence, the
arguments the model synthesized, whether a guardrail tripped, or how many turns
were consumed — and re-running the same input does not reproduce the run.

**Real-world consequence:**  
- An agent starts issuing the same search tool call repeatedly against a paid
  API. The bill is the first signal, and there is no per-run record showing
  which input triggers the loop.
- A guardrail rejects an input in production. The user reports "it just said it
  couldn't help"; with no trace, there is no way to tell a guardrail trip from a
  model refusal from a tool error.

**Why severity is low and not medium:**  
Missing observability degrades the ability to diagnose failures; it does not
itself cause incorrect behavior or expose data. Repos legitimately ship without
it — examples, tutorials, internal libraries, and prototypes — and at medium
this rule would exit 1 and fail CI on all of them. Low keeps it visible and
scored without turning "no tracing" into a build break. Contrast OBS-001, which
is medium because it describes instrumentation that is present and provably
broken.

**Fix type — config:**  
The SDK traces natively; the fix registers a processor or installs a provider at
startup. No tool or agent logic changes.

**Confidence 0.75:**  
The 0.25 gap is detection reach, not judgement. False positives: instrumentation
configured entirely through environment variables or an auto-instrumentation
agent with no call site in the repo; a provider initialized in a deployment
wrapper outside the scanned tree; a vendor SDK not in the detection table. False
negatives are structurally excluded here — the rule only fires when *zero*
signals were found, and the `repo_observability_inspectable` gate suppresses it
in languages the pass does not read, so "we did not look" is never reported as
"you have none".

---

## What this policy does not cover

OAI-203 specifically does not cover:

- **Declarative instrumentation.** `opentelemetry-instrument`, `OTEL_*`
  environment configuration, a collector sidecar, or a platform-injected agent
  leaves no call site, so a fully instrumented deployment can still fire this
  rule.
- **Languages the pass does not parse.** Phase 1 reads Python and
  TypeScript/JavaScript; the inspectable gate keeps the rule silent elsewhere
  rather than guessing.
- **Whether the wiring works.** A repo that has instrumentation silences this
  rule even if it is never initialized (OBS-001) or exports only to the console
  (OBS-002).

- Whether the traced data is actually sensitive — the rule cannot classify the
  content, only detect that default export is active.
- A custom trace processor that is registered but does **not** redact — it satisfies
  the rule yet still leaks.
- Tracing disabled at runtime by means the scanner cannot see (a config service, a
  conditional env set outside the parsed code).
- Other egress channels (logging, metrics, third-party SDKs) — this rule is scoped
  to the Agents SDK tracing backend.

---

## Recommendations beyond the fix

```python
# Option A — turn it off entirely (set in the environment):
#   OPENAI_AGENTS_DISABLE_TRACING=1

# Option B — keep tracing but redact before export:
from agents.tracing import add_trace_processor

class RedactingProcessor:
    def on_span_end(self, span):
        span.redact(fields=["input", "output"])  # strip PII/credentials
        return span

add_trace_processor(RedactingProcessor())
```

1. For sensitive workloads, disable the hosted export (`OPENAI_AGENTS_DISABLE_TRACING=1`)
   or route to a self-hosted sink via a custom processor.
2. If you keep tracing, register a processor that redacts inputs, tool arguments, and
   outputs before they leave the process — and verify it actually strips the fields.
3. Document the tracing decision and, for regulated data, confirm a data-processing
   agreement covers the destination.
