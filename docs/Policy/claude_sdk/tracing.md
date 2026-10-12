---
policy_id: claude_sdk_tracing
category: claude_sdk
topic: tracing
rules:
  - id: CSDK-208
    severity: low
    confidence: 0.75
    scope: repo
    fix_type: config
references: [LLM10]
---
# Policy Rationale: Claude Agent SDK Observability Configuration

**Policy ID:** `claude_sdk_tracing`  
**File:** `claude_sdk/tracing.yaml`  
**Rules:** CSDK-208  
**Severities:** low  
**Fix types:** config  
**References:** LLM10 (Unbounded Consumption)

---

## What this policy covers

A repo-scoped check: the project uses the Claude Agent SDK in code
(`repo_has_sdk_in_code: [claude_agent_sdk]`), no observability signal of any kind
was found (`repo_has_observability: false`), and the repo contains at least one
language the observability pass parses (`repo_observability_inspectable: true`),
and no observability package is declared in a hand-edited dependency manifest
(`repo_observability_declared: false`) — a repo that ships a tracing dependency
it never wired draws OBS-005 at medium instead, since it has claimed coverage it
does not have.

---

## Why observability is a distinct concern in Claude Agent SDK projects

A Claude Agent SDK application delegates: `query()` runs a main-thread
agent, subagents declared in `.claude/agents/*.md` take over sub-tasks, and hooks
and permission modes decide what each may touch. None of that routing is visible
in the source, because the model chooses it at runtime.

Without traces there is no record of which subagent handled a request, which
tools it was granted, or whether a permission prompt was bypassed. The failure
modes that matter most on this SDK — a subagent granted broader tools than its
description implies, a run that silently exhausts its turns, a hook that
rewrote a tool call — all leave the same evidence in a repo with no
instrumentation: none.

---

## Rule-by-rule defense

### CSDK-208 — Claude Agent SDK project wires no observability (Severity: low, Confidence: 0.75, Fix type: config)

**What we detect:**  
No OpenTelemetry provider and no third-party instrumentation
(Langfuse, Logfire, Braintrust, Phoenix, Weave, OpenLLMetry, MLflow, AgentOps)
appears in any parsed file, while Claude Agent SDK code does.

**Why it is flaggable:**  
A `query()` call can fan out across subagents and dozens of tool
invocations. The SDK does not persist that tree anywhere by default, so once the
process exits the only record is whatever the application logged — and
application logs capture the outcome, not the decision path that produced it.

**Real-world consequence:**  
- A subagent with `Bash` access runs a destructive command. The repo shows the
  subagent's markdown grant; nothing shows which run invoked it, with what input,
  or how the model was persuaded.
- An agent stops responding mid-task after exhausting its turn budget. Without a
  trace the team cannot tell an exhausted budget from a hung tool call.

**Why severity is low and not medium:**  
Missing observability degrades diagnosis; it does not itself cause incorrect
behavior or expose data. Examples, tutorials, internal libraries, and prototypes
legitimately ship without it, and at medium this rule would exit 1 and fail CI on
every one of them. Low keeps the gap visible and scored without turning "no
tracing" into a build break. Contrast OBS-001, which is medium because it
describes instrumentation that is present and provably broken.

**Fix type — config:**  
The SDK's telemetry is wiring, not logic: install a provider or a
vendor SDK at startup. No tool or agent source changes.

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
import logfire
from claude_agent_sdk import query

logfire.configure(service_name="support-agent")

async def main():
    async for message in query(prompt="Summarise today's incidents"):
        print(message)
```

1. **Record the session identifier on every span** so a user report maps to one
   `query()` run rather than to a time window.
2. **Attribute spans per subagent.** A trace that flattens subagent work into the
   main thread loses exactly the attribution the multi-agent design creates.
3. **Assert one span reaches the backend in CI**, so instrumentation that stops
   running after a refactor fails the build rather than going unnoticed.
