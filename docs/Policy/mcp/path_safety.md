---
policy_id: mcp_path_safety
category: mcp
topic: path_safety
rules:
  - id: MCP-005
    severity: high
    confidence: 0.7
    scope: tool
    fix_type: code
references: [LLM02, LLM06]
---

# Policy Rationale: MCP Filesystem Path Safety

**Policy ID:** `mcp_path_safety`  
**File:** `mcp/path_safety.yaml`  
**Rules:** MCP-005  
**References:** LLM02 (Sensitive Information Disclosure), LLM06 (Excessive Agency)

> Shares the path-traversal threat model with
> [openai_sdk/path_safety.md](../openai_sdk/path_safety.md). MCP-specific angle
> only.

---

## What this policy covers

A caller-supplied path-like parameter flowing into an I/O call inside an MCP tool
handler without containment, detected per-parameter by
`call_uses_unnormalized_path_param` (callees `open` / `Path`, callee-prefixes
`shutil.` / `os.`). Per-parameter means a handler that resolves one path but not
another still fires on the unresolved one.

## Rule-by-rule defense

### MCP-005 — Path parameter used in I/O without validation (Severity: high, Confidence: 0.7, Fix type: code)

**What we detect:** a path-like parameter passed to a file or directory operation
with no intervening `.resolve()` / containment check.

**Why it is flaggable:** MCP tool arguments are supplied by a connecting client
and chosen by a model from conversation context. A `../../etc/passwd` traversal
payload reaches real filesystem state the server can read or write, outside any
intended root — sensitive-information disclosure (LLM02) driven by the tool's
excessive filesystem agency (LLM06). High severity because the exposure is direct
file read/write; confidence 0.7 because the param-is-pathish heuristic can flag a
parameter that is not actually attacker-influenced, so the finding asks for
confirmation that the parameter is caller-supplied.

**Fix type — code:** resolving the path and asserting an allowed root is a source
edit to the handler.

---

## What this policy does not cover

Whether a given parameter is genuinely caller-controlled; containment performed
by a helper in another module; symlink-escape after a correct `.resolve()`; and
the TypeScript MCP path surface (no TS path-normalization predicate exists yet —
TS filesystem risk is approximated only by the shell and code-exec rules).
