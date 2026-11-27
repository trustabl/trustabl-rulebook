---
policy_id: raw_llm_sdk_model_output_sinks
category: raw_llm_sdk
topic: model_output_sinks
rules:
  - id: RAW-003
    severity: medium
    confidence: 0.3
    scope: repo
    fix_type: code
references: [LLM05, LLM06]
---

# Policy Rationale: Model Output That Reaches a Shell or Code Execution Call

**Policy ID:** `raw_llm_sdk_model_output_sinks`  
**File:** `raw_llm_sdk/model_output_sinks.yaml`  
**Rules:** RAW-003  
**Severities:** medium  
**Fix types:** code  
**References:** LLM05 (Improper Output Handling), LLM06 (Excessive Agency)

> **Verification status.** The arXiv abstract for 2610.24545 was read through the arXiv API on 2026-11-27. **Not read:** the full text, so the pack cites the abstract alone and not the study's sink list. **Not found, and therefore not assumed:** a true positive in public code. Python files with model calls in `AgentOps-AI/agentops` (`f8e907b`), `yaalalabs/agent-kernel`, `evalstate/fast-agent` and others in the shared cache produced no finding; precision and recall are not measured.

---

## What this policy covers

RAW-003 reads `RepoInventory.RepoFlows` from `analysis.DiscoverRepoFlows`: the result of a chat-model SDK call from a fixed list reaches a `shell` or `code_exec` sink in the same function. The predicate is `repo_source_reaches_sink` with source `llm_output`. It does not overlap RAW-001 and RAW-002, which read tool output built into a system prompt.

---

## Why these flows are flaggable

The arXiv study "When Code Becomes an LLM Call" (arXiv:2610.24545) traced model outputs in 496 call sites of 40 open-source agentic systems and reports that 48% reach control flow or execution and 73% of those do not reach a person. The pack cites it for that finding, and nothing more.

---

## Rule-by-rule defense

### RAW-003 — Model output reaches a shell, eval, exec or compile call (Severity: medium, Confidence: 0.3, Fix type: code)

**What we detect:** a Python function in which the result of a chat-model call reaches a subprocess call, `os.system`, `eval`, `exec` or `compile`, through assignments, string wrappers, `json.loads` and attribute or index reads. An `if` test that raises or returns ends the flow.

**Why it is flaggable:** model text can be steered by its input and then runs as a command or as code.

**Real-world consequence:** arbitrary command or code execution with the permissions of the process.

**Severity:** the pack sets medium and states no reasoning for it.

**Fix type — code:** ask for structured output, validate it against an enum of operations and map each operation to a fixed function, or sandbox the code and put a person before any action that cannot be undone.

**Confidence 0.3:** The pack sets 0.3. The pack's explanation states these limits: a single function is read; a value passed to a helper is not followed; model calls are matched by name from a fixed list; an `if` test counts as a guard without a check that it is an allowlist; a tool built to run model-written code in a sandbox is flagged; branches on model output are not read.

---

## What this policy does not cover

- Branches that act on model output without reaching a shell or code sink; the study's branch case is left out.
- SQL, file path and query sinks.
- TypeScript.
- Model output passed through a helper, a field or a framework callback.

---

## Recommendations beyond the fix

1. Treat model output as untrusted input and validate it before it selects an action.

---

## Sources

- "When Code Becomes an LLM Call: An Empirical Study of Call-Site Contracts in Agentic Systems", arXiv:2610.24545 (abstract read through the arXiv API). Retrieved 2026-11-27. Cited for the finding that a large share of model outputs reach control flow or execution and mostly do not reach a person, and nothing more.
