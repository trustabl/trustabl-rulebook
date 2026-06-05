---
policy_id: crewai_tool_behavior
category: crewai
topic: tool_behavior
rules:
  - id: CREW-108
    severity: medium
    confidence: 0.6
    scope: tool
    fix_type: config
references: [LLM05]
---

# Policy Rationale: CrewAI Tool Behavior Safety

**Policy ID:** `crewai_tool_behavior`  
**File:** `crewai/tool_behavior.yaml`  
**Rules:** CREW-108  
**Severities:** medium  
**Fix types:** config  
**References:** LLM05 (Improper Output Handling)

---

## What this policy covers

CrewAI tools that alter the agent's control flow by returning their output as the
final answer. **CREW-108** fires when a `@tool` is configured with
`result_as_answer=True` (predicate `tool_decorator_kwarg_value` matching the
literal `True`). The rule reads the decorator argument, not the tool body.

---

## Why short-circuiting the agent is a distinct concern in CrewAI

Normally the model reviews a tool's output before deciding what to do with it: it
can validate, summarize, reject, or combine it with other context. Setting
`result_as_answer=True` removes that step entirely — CrewAI takes the tool's raw
output as the agent's final answer and stops. No model reasoning runs after the
tool, no post-tool validation step executes, and nothing sanitizes the result
before it reaches the caller. When the tool returns content that is influenced by
the model or an attacker — a scraped page, a file read, a search result — that
unvalidated, possibly-injected content flows straight to whoever consumes the
agent's answer. This is the CrewAI analog of LangChain's `return_direct`:
convenient for a deterministic passthrough whose output is already trusted,
dangerous the moment the tool's output is not. It is an Improper Output Handling
(LLM05) problem — the agent emits a tool result as authoritative without the
validation layer that would normally stand between the tool and the caller.

---

## Rule-by-rule defense

### CREW-108 — Tool returns its output as the final answer (Severity: medium, Confidence: 0.6, Fix type: config)

**What we detect:** a `@tool` decorated with `result_as_answer=True` (predicate
`tool_decorator_kwarg_value`).

**Why it is flaggable:** the flag short-circuits the agent so the tool's raw
output becomes the final answer with no model review or post-tool validation. If
that output is model- or attacker-influenced, unvalidated content reaches the
caller.

**Real-world consequence:** a `fetch_page` tool with `result_as_answer=True` is
pointed by a prompt injection at an attacker page; the page's contents — including
any injected instructions or misinformation — are returned to the user verbatim
as the agent's answer, with the model never given a chance to flag them.

**Why severity is medium and not high:** the flag is dangerous only when the
tool's output is untrusted; with a tool whose output is already trusted and
sanitized it is a legitimate, safe optimization, so the impact is conditional
rather than inherent. **Fix type — config:** the fix is flipping a decorator
keyword, no tool-body change. **Confidence 0.6:** the rule cannot tell whether
the tool's output is trusted, so it fires on every `result_as_answer=True`
including the many deliberate, safe uses — the largest source of false positives,
which is why confidence sits at 0.6.

---

## What this policy does not cover

- Whether the tool's output is actually trusted. The rule flags the
  control-flow flag, not the trust level of what flows through it, so a
  deterministic passthrough of safe data fires (a deliberate false positive).
- The same short-circuit reached by other means — a tool that simply *is* the
  last call the model makes achieves a similar effect without the flag and is not
  matched.
- Whether the tool body sanitizes its own output before returning. A tool that
  cleans its result internally still fires on the flag.
- `result_as_answer` set to a non-literal (a variable resolved at runtime) may
  not match the literal-value predicate.

---

## Recommendations beyond the fix

```python
from crewai.tools import tool

# Default (result_as_answer omitted / False): the model reviews the output.
@tool("fetch_summary")
def fetch_summary(doc_id: str) -> str:
    """Return the stored summary for a document. Output is reviewed by the
    agent before it becomes the final answer."""
    return load_trusted_summary(doc_id)
```

1. Leave `result_as_answer` at its default (`False`) unless you specifically
   intend to short-circuit the agent with a tool whose output is already trusted
   and sanitized.
2. If you do use it, shape and sanitize the tool's output inside the tool body —
   no model step or guardrail runs after it, so the body is the last line of
   defense.
3. Never combine `result_as_answer=True` with a tool that fetches external
   content, reads arbitrary files, or otherwise returns model-/attacker-
   influenced data.
