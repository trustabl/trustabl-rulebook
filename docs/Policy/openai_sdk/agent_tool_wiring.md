---
policy_id: openai_sdk_agent_tool_wiring
category: openai_sdk
topic: agent_tool_wiring
rules:
  - id: OAI-206
    severity: high
    confidence: 0.7
    scope: agent
    fix_type: code
references: [LLM06]
---

# Policy Rationale: OpenAI Agents SDK Handoff Target Tool Wiring

**Policy ID:** `openai_sdk_agent_tool_wiring`  
**File:** `openai_sdk/agent_tool_wiring.yaml`  
**Rules:** OAI-206  
**Severities:** high  
**Fix types:** code  
**References:** OWASP LLM Top 10:2025 — LLM06 (Excessive Agency)

> **Verification status.** The SDK guardrails page was read on 2026-11-25 as raw page text. **Not verified, and therefore not assumed:** how tool guardrails interact with a handoff target; and how many handoff targets with shell tools exist outside the repositories sampled for the report.

---

## What this policy covers

**OAI-206** reads the `Agent(...)` call and the resolved tool and handoff graph, and flags an agent that is the target of another agent's `handoffs=[...]` and holds a shell tool. It re-lands an ID that was removed on 2026-09-11 in a bulk revert of a rule-pack reconcile; the revert states no reason specific to this rule.

---

## Rule-by-rule defense

### OAI-206 — Handoff-target agent wires shell tools (Severity: high, Confidence: 0.7, Fix type: code)

**What we detect:** `agent_is_subagent_of_any` (the agent is a resolved target in another agent's handoffs) and `agent_uses_tool_kind: [shell_invocation]` (a resolved shell tool, a decorated tool that shells out, or a hosted shell tool). Applies to `openai_agent` and `openai_sandbox_agent`.

**Why it is flaggable.** The SDK guardrails page states that input guardrails run for the first agent in the chain, and its input-guardrail note says an agent's guardrails run when the agent is the first agent. The page also states that tool guardrails run on each guarded function-tool call. The page is cited for those statements and nothing more. A handoff target therefore runs its shell tool on a turn that its own input guardrails did not inspect, unless a tool guardrail is set.

**Real-world consequence:** a parent agent can pass attacker-influenced input to the child, and the child runs a shell command on it.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Fix type — code:** the fix moves or removes the tool, or adds an input filter or a tool guardrail, and gates the tool with `needs_approval`.

**Confidence 0.7:** the pack's explanation states these limits of the check:

- It reads the agent graph in the source; a handoff built in another module or in a loop, and an unresolved agent variable, are not seen.
- Tools that run shell commands count; file read and write tools are not judged.
- Tool guardrails are not read, so an agent whose shell tool has its own guardrail still matches.
- OAI-104 flags a plain Agent with shell tools whether or not it is a handoff target, and both can report one agent.

**Field check, run on 2026-11-25** (prototype of the detector over cloned public repositories at the commits listed in the report `~/trustabl-reports/static-batch-3.md`; not a random sample). 6 repositories with handoffs (345 handoff edges): 1 finding, in `openai/openai-agents-python` `tests/test_agent_scoped_approvals.py` (a test path): a handoff target holding a hosted `ShellTool` that sets `needs_approval=True`. It matches the rule as written; the rule does not read `needs_approval` on a hosted shell tool, so this finding is a match whose risk is reduced by the approval gate. 0 findings outside test paths.

---

## What this policy does not cover

- File read and write tools on a handoff target.
- Tool guardrails and `needs_approval` on a hosted shell tool.

---

## Recommendations beyond the fix

1. Keep privileged tools on the agent that receives the user input.
2. Gate shell tools with `needs_approval`.

---

## Sources

- OpenAI Agents SDK, Guardrails: https://openai.github.io/openai-agents-python/guardrails/ Retrieved 2026-11-25. Cited for where input guardrails run and for tool guardrails, and nothing more.
