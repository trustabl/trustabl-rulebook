---
policy_id: autogen_tracing
category: autogen
topic: tracing
rules:
  - id: AG2-202
    severity: low
    confidence: 0.75
    scope: repo
    fix_type: config
references: [LLM10]
---
# Policy Rationale: AutoGen Observability Configuration

**Policy ID:** `autogen_tracing`  
**File:** `autogen/tracing.yaml`  
**Rules:** AG2-202  
**Severities:** low  
**Fix types:** config  
**References:** LLM10 (Unbounded Consumption)

---

## What this policy covers

A repo-scoped check: the project defines AutoGen / AG2 agents in code,
no observability signal was found, and the repo contains a language the
observability pass parses.

---

## Why observability is a distinct concern in AutoGen projects

An AutoGen group chat runs until a termination condition is met. The
conversation between agents *is* the computation, and its length is decided at
runtime by the agents themselves. Two failure modes follow directly: the chat
that never terminates cleanly and burns tokens in a loop, and the chat that
terminates too early and returns a confidently incomplete answer.

Both are conversation-shaped failures. They are diagnosable only from the message
sequence — who spoke, in what order, and what triggered the terminate — which is
exactly what a repo with no instrumentation does not keep.

---

## Rule-by-rule defense

### AG2-202 — AutoGen project wires no observability (Severity: low, Confidence: 0.75, Fix type: config)

**What we detect:**  
AutoGen code is present (`repo_has_sdk_in_code: [autogen]`), no
observability signal of any kind was found, and the repo is inspectable. No observability package is declared in a hand-edited dependency manifest
either (`repo_observability_declared: false`): a repo that ships a tracing
dependency it never wired draws OBS-005 at medium instead, since it has
claimed coverage it does not have.

**Why it is flaggable:**  
Each turn in a group chat is a model call, so an unbounded conversation
is unbounded spend. Without traces the only artifact is the final message, which
carries no information about how many turns preceded it or why the chat
stopped.

**Real-world consequence:**  
- Two agents fall into a politeness loop, each deferring to the other, until the
  turn limit is hit. The bill shows the cost; nothing shows the trigger.
- A `UserProxyAgent` auto-replies its way to an early termination and returns a
  partial answer. Without the message sequence the result looks like a model
  quality problem.

**Why severity is low and not medium:**  
Missing observability degrades diagnosis; it does not itself cause incorrect
behavior or expose data. Examples, tutorials, internal libraries, and prototypes
legitimately ship without it, and at medium this rule would exit 1 and fail CI on
every one of them. Low keeps the gap visible and scored without turning "no
tracing" into a build break. Contrast OBS-001, which is medium because it
describes instrumentation that is present and provably broken.

**Fix type — config:**  
Initialization at process start, before the chat begins. No agent
definitions change.

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
from autogen import AssistantAgent, UserProxyAgent

agentops.init(default_tags=["support-chat"])    # before initiate_chat()

assistant = AssistantAgent("assistant", llm_config=llm_config)
user = UserProxyAgent("user", human_input_mode="NEVER", max_consecutive_auto_reply=5)
user.initiate_chat(assistant, message="Summarise the incident")
```

1. **Record the turn index and speaker on every span**, so a loop is visible as
   a pattern rather than as a token total.
2. **Trace the termination check.** Knowing *why* a chat stopped separates a
   clean finish from an early exit.
3. **Alert on turn count per conversation**, the earliest signal of a loop.
