---
policy_id: google_adk_path_safety
category: google_adk
topic: path_safety
rules:
  - id: ADK-004
    severity: high
    confidence: 0.7
    scope: tool
    fix_type: code
references: [LLM02, LLM06]
---

# Policy Rationale: Path Safety

**Policy ID:** `google_adk_path_safety`  
**File:** `google_adk/path_safety.yaml`  
**Rules:** ADK-004  
**Severities:** high  
**Fix types:** code  
**References:** LLM02, LLM06

> **Read [claude_sdk/path_safety.md](../claude_sdk/path_safety.md) for the full threat model.**
> This document covers Google ADK–specific differences only.

---

## What this policy covers

Google ADK `FunctionTool`-wrapped functions that pass a path-like parameter into a
filesystem call without normalizing it (`call_uses_unnormalized_path_param`,
per-parameter). Same predicate and threat model as the Claude path-safety policy.

---

## Why path safety is a distinct concern in agent tools

Identical to the Claude case — the model supplies the path, so an unnormalized path
is an arbitrary-file read/overwrite primitive, and normalization without a
containment check still leaves the tool exploitable. See
[claude_sdk/path_safety.md](../claude_sdk/path_safety.md#why-path-safety-is-a-distinct-concern-in-agent-tools).

ADK-specific note: on a managed runtime the readable filesystem includes mounted
secrets and the service-account ambient environment, so an arbitrary-read path
tool is a credential-exposure path as well as a data one.

---

## Rule-by-rule defense

### ADK-004 — Path parameter used in I/O without normalization (Severity: high, Confidence: 0.7, Fix type: code)

**What we detect:** a path-shaped parameter flowing into `open`/`Path`/`shutil.*`/
`os.*` with no `.resolve()`/`realpath()` applied to it in the same function.

**Why it is flaggable:** an unnormalized model-supplied path can traverse out of the
intended directory or follow a symlink.

**Real-world consequence:** a `read_file(path)` ADK tool is asked to open
`../../secrets.json` or a mounted credential file; contents return into the loop.

**Why severity is high and not medium:** arbitrary read/overwrite — data or
credential exposure. Conditional on the handle's use, so not critical.

**Fix type — code:** resolve and containment-check the path in the tool source.

**Confidence 0.7:** moderate by design — out-of-module normalization is invisible,
and resolve-without-containment passes the rule yet stays unsafe. Same calibration
as CSDK-004.

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
For ADK, keep mounted secrets outside any directory an agent file tool can reach,
and gate file tools with a `before_tool_callback` that re-checks the resolved path.
