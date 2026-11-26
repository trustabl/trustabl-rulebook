---
policy_id: openai_sdk_handoff_input_filter
category: openai_sdk
topic: handoff_input_filter
rules:
  - id: OAI-204
    severity: medium
    confidence: 0.4
    scope: agent
    fix_type: code
references: [LLM06]
---

# Policy Rationale: OpenAI Agents SDK Handoff Without an Input Filter

**Policy ID:** `openai_sdk_handoff_input_filter`  
**File:** `openai_sdk/handoff_input_filter.yaml`  
**Rules:** OAI-204  
**Severities:** medium  
**Fix types:** code  
**References:** OWASP LLM Top 10:2025 — LLM06 (Excessive Agency)

> **Verification status.** The OpenAI Agents SDK handoffs pages for Python and JavaScript were read on 2026-11-26 as raw page text. Neither arXiv paper named in the backlog (2610.05640 and 2607.19430) mentions the OpenAI SDK, `handoff()` or `input_filter`, so neither is cited. **Not verified, and therefore not assumed:** that a shell tool on a handoff target is a privilege boundary; and how many handoff targets with shell tools exist outside the repositories sampled.

---

## What this policy covers

**OAI-204** reads the `handoffs` list of an OpenAI agent in Python and TypeScript and flags an entry with no input filter whose target, defined in the same file, holds a shell tool, unless a run configuration sets `handoff_input_filter`.

---

## Rule-by-rule defense

### OAI-204 — Handoff to an agent with a shell tool sets no input filter (Severity: medium, Confidence: 0.4, Fix type: code)

**What we detect:** `agent_handoff_missing_input_filter` (a `handoffs` entry that is a bare agent or a `handoff(...)` call with no `input_filter` or `inputFilter`, whose same-file target satisfies `agent_uses_tool_kind: [shell_invocation]`, with no `handoff_input_filter` anywhere in the scanned code). Applies to `openai_agent` and `openai_sandbox_agent`.

**Why it is flaggable.** The SDK handoffs page states that "when a handoff occurs, it's as though the new agent takes over the conversation, and gets to see the entire previous conversation history. If you want to change this, you can set an input_filter", and that the per-handoff filter takes precedence over the run-level one. The JavaScript page states that "by default a handoff receives the entire conversation history". The pages are cited for those statements and nothing more. The choice of a shell tool as the privilege is the rule's, not the pages'.

**Real-world consequence:** the target receives all earlier messages, including tool output and content from other sources, before it runs a shell command.

**Why severity is medium:** The pack sets medium and states no reasoning for it.

**Fix type — code:** the fix sets an input filter on the handoff or the run configuration, or keeps the shell tool off the target.

**Confidence 0.4:** the pack's explanation states these limits of the check:

- It reads bare agent entries and `handoff(...)` calls, and targets defined in the same file; imported targets, loops and `Handoff` objects held in variables are not seen.
- Shell tools are the one kind of privilege read; file, network and side-effect tools are not judged.
- An entry that sets a filter is not judged and the rule does not check what the filter removes; any `handoff_input_filter` argument in the scanned code silences the rule for the repository.
- OAI-206 reports the same target for holding a shell tool, and both rules can report one agent.

**Field check, run on 2026-11-26** (prototype of the detector over cloned public repositories at the commits listed in the report `~/trustabl-reports/static-batch-2.md`; not a random sample; each repository was scanned once, with a 120 second cap). Sample: 5 repositories with `handoffs` were scanned (`yusuf-eren/openai-agents-js` 3c5b2bb, `jkmaina/openai-agents-blueprint` 76cbbcb, `alirezadir/Agentic-AI-Systems` 43e62b5, `TencentCloudADP/youtu-agent` 631ee33, `AgentOps-AI/agentops` f8e907b). 0 hits. **0 hits: precision is not measured.**


---

## What this policy does not cover

- File, network and side-effect tools on a handoff target.
- Targets defined in another module.

---

## Recommendations beyond the fix

1. Filter the history that a privileged target receives.
2. Gate shell tools with `needs_approval`.

---

## Sources

- OpenAI Agents SDK, Handoffs (Python): https://openai.github.io/openai-agents-python/handoffs/ Retrieved 2026-11-26. Cited for the full-history default, `input_filter` and its precedence over the run-level filter, and nothing more.
- OpenAI Agents SDK, Handoffs (JavaScript): https://openai.github.io/openai-agents-js/guides/handoffs/ Retrieved 2026-11-26. Cited for the full-history default and `inputFilter`, and nothing more.
