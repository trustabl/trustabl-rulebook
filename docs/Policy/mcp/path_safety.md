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

---

## Recommendations beyond the fix

```python
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("docs")

# The root comes from the server's own configuration — never from a parameter.
_ROOT = Path("/srv/agent-docs").resolve()


def _contained(candidate: str) -> Path:
    """Resolve candidate under _ROOT, or raise if it escapes."""
    # An absolute candidate makes `/` discard _ROOT entirely; resolve() plus the
    # containment check is what catches that, and traversal, and symlinks.
    resolved = (_ROOT / candidate).resolve()
    if not resolved.is_relative_to(_ROOT):
        raise ValueError("path escapes the document root")
    return resolved


@mcp.tool()
def read_doc(relative_path: str) -> dict:
    """Read a UTF-8 document from the server's document root."""
    try:
        target = _contained(relative_path)
    except ValueError:
        return {"error": "path is outside the document root", "code": "forbidden",
                "retryable": False}
    if not target.is_file():
        return {"error": "no such document", "code": "not_found", "retryable": False}
    return {"content": target.read_text(encoding="utf-8", errors="replace")[:500_000]}
```

The traversal rationale is in
[openai_sdk/path_safety.md](../openai_sdk/path_safety.md#recommendations-beyond-the-fix).
MCP-specific additions:

1. Take the root from server configuration, never from a second parameter. The
   connecting client chooses every argument, so a `root=` parameter alongside a
   `path=` parameter is not containment — it is a traversal with extra steps.
2. Treat a client-advertised root as a narrowing, never a widening. MCP lets a
   client tell the server where it believes work should happen; that is useful
   for intersecting with the server's own root, and is not a grant. The server
   is the party that owns its filesystem.
3. Validate every path parameter, not the first one. MCP-005 is per-parameter
   precisely because a handler that resolves `src` and forwards `dest`
   untouched is still a traversal, and the resolved parameter makes the code
   look careful.
4. Compare with `is_relative_to`, not a string prefix. `/srv/agent-docs-evil`
   passes `startswith("/srv/agent-docs")`.
5. Remember that extracting the guard into a helper can stop the rule firing
   without changing the risk — the predicate stops seeing the raw parameter
   reach I/O. That is a reason to unit-test the helper against `..`, absolute
   paths, and a symlink pointing out of the root, rather than to inline it.
6. Bound the read. Containment decides *which* file the caller reaches; it says
   nothing about a 4GB one.
