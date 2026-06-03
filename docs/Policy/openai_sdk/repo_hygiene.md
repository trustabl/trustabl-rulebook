---
policy_id: openai_sdk_repo_hygiene
category: openai_sdk
topic: repo_hygiene
rules:
  - id: OAI-202
    severity: low
    confidence: 0.9
    scope: repo
    fix_type: config
references: [LLM06]
---

# Policy Rationale: Repository Hygiene

**Policy ID:** `openai_sdk_repo_hygiene`  
**File:** `openai_sdk/repo_hygiene.yaml`  
**Rules:** OAI-202  
**Severities:** low  
**Fix types:** config  
**References:** LLM06

> **Read [claude_sdk/repo_hygiene.md](../claude_sdk/repo_hygiene.md) for the full rationale.**
> This document covers OpenAI Agents SDK–specific differences only.

---

## What this policy covers

The repository uses the OpenAI Agents SDK in code
(`repo_has_sdk_in_code: [openai_agents]`) but ships no agent-guidance doc — neither
an AGENTS.md nor a CLAUDE.md (`not repo_component_present: [agents_md, claude_md]`).
Fires once per scan. For an OpenAI project, AGENTS.md is the natural choice (it is
the convention OpenAI's own tooling reads), but a CLAUDE.md equally satisfies the
rule.

---

## Why a missing agent-guidance doc is a distinct concern in agent projects

The mechanism is identical to the Claude case — an editing agent has only what is
in the tree. See
[claude_sdk/repo_hygiene.md](../claude_sdk/repo_hygiene.md#why-a-missing-agent-guidance-doc-is-a-distinct-concern-in-agent-projects).

OpenAI-specific guidance worth capturing: whether the project uses `Agent` or
`SandboxAgent`, the handoff topology, required `input_guardrails` /
`output_guardrails`, `tool_choice` conventions, tracing policy, and the local
test/build commands. Without these, generated code tends to bypass the project's
safety contracts (e.g. wiring a privileged tool with no guardrail).

---

## Rule-by-rule defense

### OAI-202 — OpenAI Agents project ships no agent-guidance doc (Severity: low, Confidence: 0.9, Fix type: config)

**What we detect:** OpenAI Agents SDK usage observed in code, and neither an
`agents_md` nor a `claude_md` component present.

**Why it is flaggable:** an editing agent has no in-tree guidance on the project's
agent-wiring and guardrail conventions.

**Real-world consequence:** generated code wires a shell tool onto a plain `Agent`
with no `input_guardrails` because nothing told it the project requires them.

**Why severity is low and not medium:** a reliability/onboarding gap, not a
security defect; one AGENTS.md or CLAUDE.md resolves it.

**Fix type — config:** add an AGENTS.md (or CLAUDE.md) — a documentation artifact,
no source change.

**Confidence 0.9:** direct presence test; false positives limited to projects that
deliberately keep guidance elsewhere. Accepting either convention means an OpenAI
project that ships AGENTS.md is no longer flagged for lacking a Claude-branded file.

---

## What this policy does not cover

Same gaps as [claude_sdk/repo_hygiene.md](../claude_sdk/repo_hygiene.md#what-this-policy-does-not-cover):
the quality of a present guidance doc, monorepo per-directory layouts, and whether
the agent actually reads it.

---

## Recommendations beyond the fix

Add a root `AGENTS.md` (or `CLAUDE.md`) stating whether the project uses `Agent` or
`SandboxAgent`, the required guardrails and `tool_choice` conventions, any
handoff/tracing policy, and the exact test, lint, and build commands. See
[claude_sdk/repo_hygiene.md](../claude_sdk/repo_hygiene.md#recommendations-beyond-the-fix).
