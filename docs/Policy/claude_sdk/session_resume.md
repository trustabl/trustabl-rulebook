---
policy_id: claude_sdk_session_resume
category: claude_sdk
topic: session_resume
rules:
  - id: CSDK-209
    severity: high
    confidence: 0.35
    scope: repo
    fix_type: code
references: [LLM05, LLM06]
---

# Policy Rationale: Claude Agent SDK Session Resume

**Policy ID:** `claude_sdk_session_resume`  
**File:** `claude_sdk/session_resume.yaml`  
**Rules:** CSDK-209  
**Severities:** high  
**Fix types:** code  
**References:** LLM05 (Improper Output Handling), LLM06 (Excessive Agency)

> **Verification status.** GitHub advisory GHSA-h4mw-j7qp-8mwm (CVE-2026-96620) was read through the GitHub advisories API on 2026-11-27. **Not found, and therefore not assumed:** a true positive in public code. `yaalalabs/agent-kernel` (`7c7e61e`) and `zenml-io/kitaru` (`3b789f1`) use `ClaudeAgentOptions` and gave no hit; precision and recall are not measured.

---

## What this policy covers

CSDK-209 reads `RepoInventory.RepoFlows`, built by `analysis.DiscoverRepoFlows` (Python, outside test paths): a parameter of a function (other than `self`, `cls` and a parameter typed int, float, bool, Literal or Enum) reaches the `resume` keyword of `ClaudeAgentOptions` in the same function. The predicate is `repo_source_reaches_sink` with source `handler_param` and sink `claude_resume`.

---

## Why these flows are flaggable

The advisory states that the Claude Agent SDK for Python passed `resume` to the Claude CLI without validation, so a value beginning with `-` was read as a flag; an attacker who controlled it could inject `--mcp-config` with a stdio MCP server and run commands at startup outside the SDK's permission controls; exploitation needs an application that passes untrusted input as the session ID; versions below 0.2.121 are affected. The pack cites it for that mechanism, and nothing more.

---

## Rule-by-rule defense

### CSDK-209 — Python function passes a parameter to ClaudeAgentOptions resume (Severity: high, Confidence: 0.35, Fix type: code)

**What we detect:** a function in Python code whose parameter reaches `ClaudeAgentOptions(resume=...)`. `str(uuid.UUID(...))`, a lookup that returns another value and an `if` test that raises or returns end the flow.

**Why it is flaggable:** a session identifier that the caller controls can carry a command-line flag.

**Real-world consequence:** command execution outside the SDK's permission controls on a vulnerable SDK release.

**Severity:** the pack sets high and states no reasoning for it.

**Fix type — code:** check the identifier with `uuid.UUID` or look it up among sessions the current user owns, and use SDK 0.2.121 or later.

**Confidence 0.35:** The pack sets 0.35. The pack's explanation states these limits: the rule cannot tell whether a caller passes untrusted input, so any parameter counts; a value in a field or returned by another function is not followed; the check does not judge whether an `if` test is sound; and TypeScript is not read.

---

## What this policy does not cover

- The TypeScript SDK and any other way to set the session identifier.
- The SDK version; dependency advisories cover it.
- A value that reaches `resume` through a helper, a field or a dictionary key.

---

## Recommendations beyond the fix

1. Treat a session identifier as untrusted input at the edge of the application.

---

## Sources

- GitHub advisory GHSA-h4mw-j7qp-8mwm, "Claude Agent SDK: Argument Injection via resume Option Allows Arbitrary Command Execution" (CVE-2026-96620). Retrieved 2026-11-27. Cited for the mechanism of an unvalidated `resume` value reaching the CLI, and nothing more.
