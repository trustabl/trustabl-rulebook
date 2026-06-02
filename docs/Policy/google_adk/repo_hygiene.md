---
policy_id: google_adk_repo_hygiene
category: google_adk
topic: repo_hygiene
rules:
  - id: ADK-201
    severity: low
    confidence: 0.9
    scope: repo
    fix_type: config
references: [LLM06]
---

# Policy Rationale: Repository Hygiene

**Policy ID:** `google_adk_repo_hygiene`  
**File:** `google_adk/repo_hygiene.yaml`  
**Rules:** ADK-201  
**Severities:** low  
**Fix types:** config  
**References:** LLM06

> **Read [claude_sdk/repo_hygiene.md](../claude_sdk/repo_hygiene.md) for the full rationale.**
> This document covers Google ADK–specific differences only.

---

## What this policy covers

The repository uses the Google ADK in code (`repo_has_sdk_in_code: [google_adk]`)
but ships no top-level CLAUDE.md (`not repo_component_present: [claude_md]`).
Fires once per scan.

---

## Why a missing CLAUDE.md is a distinct concern in agent projects

The mechanism is identical to the Claude case — an editing agent has only what is
in the tree, so a missing CLAUDE.md means no project guidance. See
[claude_sdk/repo_hygiene.md](../claude_sdk/repo_hygiene.md#why-a-missing-claudemd-is-a-distinct-concern-in-agent-projects).

ADK-specific guidance worth capturing in the file: which agent classes the project
uses and why (`LlmAgent` vs `SequentialAgent` vs `ParallelAgent` vs `LoopAgent`),
the `sub_agents` composition rules, how tools must be wrapped (`FunctionTool`
conventions), required guardrails/callbacks, and the local test/build commands.
Without these, generated code tends to violate the project's tool and agent
contracts.

---

## Rule-by-rule defense

### ADK-201 — Google ADK project missing CLAUDE.md (Severity: low, Confidence: 0.9, Fix type: config)

**What we detect:** ADK usage observed in code, no `claude_md` component present.

**Why it is flaggable:** an editing agent has no in-tree guidance on the project's
ADK conventions.

**Real-world consequence:** generated code picks the wrong agent class or skips a
required `before_tool_callback` because nothing told it the local rules.

**Why severity is low and not medium:** a reliability/onboarding gap, not a
security defect; one CLAUDE.md resolves it.

**Fix type — config:** add a CLAUDE.md — a documentation artifact, no source
change.

**Confidence 0.9:** direct presence test; false positives limited to projects that
deliberately keep guidance elsewhere.

---

## What this policy does not cover

Same gaps as [claude_sdk/repo_hygiene.md](../claude_sdk/repo_hygiene.md#what-this-policy-does-not-cover):
the quality of a present CLAUDE.md, monorepo per-directory layouts, and whether the
agent actually reads it.

---

## Recommendations beyond the fix

Add a root `CLAUDE.md` stating which ADK agent classes the project uses and why,
how tools must be wrapped, any required guardrails or sandboxing, and the exact
test, lint, and build commands — short and concrete. See
[claude_sdk/repo_hygiene.md](../claude_sdk/repo_hygiene.md#recommendations-beyond-the-fix).
