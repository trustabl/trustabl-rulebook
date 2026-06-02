---
policy_id: openai_sdk_path_safety
category: openai_sdk
topic: path_safety
rules:
  - id: OAI-006
    severity: high
    confidence: 0.7
    scope: tool
    fix_type: code
references: [LLM02, LLM06]
---

# Policy Rationale: Path Safety

**Policy ID:** `openai_sdk_path_safety`  
**File:** `openai_sdk/path_safety.yaml`  
**Rules:** OAI-006  
**Severities:** high  
**Fix types:** code  
**References:** LLM02, LLM06

> **Read [claude_sdk/path_safety.md](../claude_sdk/path_safety.md) for the full threat model.**
> This document covers OpenAI Agents SDK–specific differences only.

---

## What this policy covers

OpenAI Agents SDK `@function_tool` bodies that pass a path-like parameter into a
filesystem call without normalizing it. Same `call_uses_unnormalized_path_param`
predicate, per-parameter tracking, and threat model as the Claude path-safety
policy.

---

## Why path safety is a distinct concern in agent tools

Identical to the Claude case — the model supplies the path, so an unnormalized
path is an arbitrary-file read/overwrite primitive (traversal or symlink), and
normalization without a containment check is the common way to satisfy the rule
yet stay vulnerable. See
[claude_sdk/path_safety.md](../claude_sdk/path_safety.md#why-path-safety-is-a-distinct-concern-in-agent-tools).

OpenAI-specific note: confine privileged file tools to a `SandboxAgent` (see
agent_safety, OAI-104) so even a traversal is bounded by the sandbox's filesystem
view, and surface rejections through `failure_error_function` (OAI-004) so the
model gets a structured "path not allowed" rather than a raw exception.

---

## Rule-by-rule defense

### OAI-006 — Tool accepts path without normalization (Severity: high, Confidence: 0.7, Fix type: code)

**What we detect:** a path-shaped parameter flowing into `open` / `Path` /
`shutil.*` / `os.*` without a `.resolve()` / `realpath()` applied to that
parameter in the same function.

**Why it is flaggable:** an unnormalized model-supplied path can traverse out of
the intended directory or follow a symlink to an arbitrary target.

**Real-world consequence:** a `read_file(path)` tool is asked to open `../../.env`
or `~/.aws/credentials`; the contents return into the model context and leak.

**Why severity is high and not medium:** arbitrary-file read/overwrite — credential
theft or corruption. Conditional on what the tool does with the handle, so not
critical.

**Fix type — code:** resolve and containment-check the path in the tool source.

**Confidence 0.7:** moderate by design — normalization in a cross-module helper is
invisible (false positive), and a tool that resolves but never checks containment
passes yet stays unsafe (false negative). Same calibration as CSDK-004.

---

## What this policy does not cover

Same gaps as [claude_sdk/path_safety.md](../claude_sdk/path_safety.md#what-this-policy-does-not-cover):
the missing containment check, out-of-module normalization, path-like values that
miss the name heuristic, and symlink TOCTOU races.

---

## Recommendations beyond the fix

The safe pattern — join under a fixed root, `.resolve()` + `is_relative_to(root)`,
reject symlinks, cap bytes — is in
[claude_sdk/path_safety.md](../claude_sdk/path_safety.md#recommendations-beyond-the-fix).
For the OpenAI SDK, run such tools under a `SandboxAgent` and return rejections via
`failure_error_function` as structured, retryable=false errors.
