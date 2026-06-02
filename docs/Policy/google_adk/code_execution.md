---
policy_id: google_adk_code_execution
category: google_adk
topic: code_execution
rules:
  - id: ADK-011
    severity: high
    confidence: 0.9
    scope: tool
    fix_type: code
references: [LLM06, LLM05]
---

# Policy Rationale: Dynamic Code Execution

**Policy ID:** `google_adk_code_execution`  
**File:** `google_adk/code_execution.yaml`  
**Rules:** ADK-011  
**Severities:** high  
**Fix types:** code  
**References:** LLM06, LLM05

> **Read [openai_sdk/code_execution.md](../openai_sdk/code_execution.md) for the full threat model.**
> This document covers Google ADK–specific differences only.

---

## What this policy covers

Google ADK `FunctionTool`-wrapped functions whose body invokes Python's `eval`,
`exec`, or `compile`. Detection is the same `has_code_exec_call` AST predicate
described in the OpenAI doc: it matches the bare builtin callee only, so attribute
calls such as `re.compile(...)` do not fire.

---

## Why dynamic code execution is a distinct concern in agent tools

The mechanism is identical to the OpenAI case (when any input flows from the
model, `eval`/`exec`/`compile` is arbitrary code execution inside the agent
process, with no OS sandbox between the call and the runtime's imports, file
handles, and in-memory credentials); see
[openai_sdk/code_execution.md](../openai_sdk/code_execution.md#why-dynamic-code-execution-is-a-distinct-concern-in-agent-tools).

The ADK-specific sharpening is that the in-memory credentials reachable from an
`exec` are typically GCP service-account tokens fetched via the metadata server,
and the runtime often has the Google client libraries already imported. A model
that controls the exec'd string can call those libraries directly — no outbound
HTTP needed — to read Storage, BigQuery, or Secret Manager within the service
account's grants.

---

## Rule-by-rule defense

### ADK-011 — Tool body calls eval/exec/compile on dynamic input (Severity: high, Confidence: 0.9, Fix type: code)

**What we detect:**
A `FunctionTool`-wrapped function whose body calls the bare `eval`, `exec`, or
`compile` builtin (predicate `has_code_exec_call`, an AST callee match —
`re.compile` and similar attribute calls do not fire).

**Why it is flaggable:**
Dynamic evaluation in an agent-callable tool is arbitrary-code-execution surface
whenever any part of the evaluated string originates with the model. The presence
of the call is the signal.

**Real-world consequence:**
- An ADK `calculate(expr: str)` "calculator" tool implemented as `eval(expr)` is
  driven into `__import__('google.auth').default()` to grab the service-account
  credential object directly.
- A `run_formula(formula)` tool `exec`s a model-supplied snippet that imports the
  BigQuery client and exfiltrates a dataset.

**Why severity is high and not medium:**
Same reasoning as OAI-013 — there is no in-band sandbox; a restricted-globals
`exec` is still escapable via `__builtins__` unless explicitly stripped, so the
only reliable fix is removing dynamic evaluation. Not above high because
exploitation still requires model-controlled input reaching the call.

**Fix type — code:**
Removing or replacing `eval`/`exec`/`compile` is a tool-source edit.

**Confidence 0.9:**
Same profile as OAI-013 — the bare-callee match avoids the `re.compile` false
positive, but a dynamic-eval helper defined in another module, or evaluation via
`ast.literal_eval`-lookalikes / `types.FunctionType`, escapes the body-only walk.

---

## What this policy does not cover

Identical to [openai_sdk/code_execution.md](../openai_sdk/code_execution.md#what-this-policy-does-not-cover):
`eval`/`exec` reached through a helper in another module, alternative dynamic-code
primitives (`types.FunctionType`, `marshal.loads`, `pickle.loads`,
`importlib`-driven loading), and the question of whether a given evaluation is
safe because its input is fully constant. ADK note: the rule does not inspect the
service-account scope, so it cannot weight impact by the agent's GCP grants.

---

## Recommendations beyond the fix

The safe pattern — `ast.literal_eval` for arithmetic, a constrained interpreter
only where genuinely required, and a sacrificial single-use process for
intentional code-execution surfaces — is in
[openai_sdk/code_execution.md](../openai_sdk/code_execution.md#recommendations-beyond-the-fix).
ADK/GCP-specific additions:

1. If an evaluation surface is truly required, run it in a separate process with a
   stripped environment and **no** application-default credentials, so a hostile
   snippet cannot reach `google.auth.default()`.
2. Block the metadata CIDR at the VPC egress level so even a successful exec
   cannot fetch a fresh token.
3. Scope the service account minimally so a leaked credential's reach is small.
