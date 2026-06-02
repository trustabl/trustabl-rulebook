---
policy_id: claude_sdk_path_safety
category: claude_sdk
topic: path_safety
rules:
  - id: CSDK-004
    severity: high
    confidence: 0.7
    scope: tool
    fix_type: code
references: [LLM02, LLM06]
---

# Policy Rationale: Path Safety

**Policy ID:** `claude_sdk_path_safety`  
**File:** `claude_sdk/path_safety.yaml`  
**Rules:** CSDK-004  
**Severities:** high  
**Fix types:** code  
**References:** LLM02, LLM06

---

## What this policy covers

Claude Agent SDK tools that take a path-like parameter and pass it into a
filesystem call without normalizing it first. The predicate
`call_uses_unnormalized_path_param` tracks, per parameter, whether a path-shaped
argument (`path`, `file`, `*_path`, `*_dir`, …) flows into an I/O callee
(`open`, `Path`, `shutil.*`, `os.*`) **without** having been run through
`.resolve()` / `os.path.realpath()` in the same function. It is per-parameter: a
tool that resolves one path but not another still fires on the unresolved one.

---

## Why path safety is a distinct concern in agent tools

The path argument is supplied by the model. A tool `read_file(path: str)` that
opens `path` directly trusts the model — and therefore anything that can
influence the model, including prompt-injected content — to choose which file on
disk to read or write. Without normalization, `../../../../etc/passwd`,
`/home/user/.ssh/id_rsa`, or a symlink that points outside the intended directory
all resolve to real targets. A read tool becomes an arbitrary-file *exfiltration*
primitive (the contents flow back into the model context, then into logs or the
next turn); a write tool becomes arbitrary-file *overwrite*.

This is worse than classic path traversal because there is no fixed, developer-
authored path with only a filename substituted — the entire path is
attacker-influenceable through the model. Normalization alone is necessary but
not sufficient: the resolved path must also be confirmed to live inside an
intended root. The rule flags the missing-normalization precondition because that
is the structurally detectable half; the containment check is the author's
responsibility (see recommendations).

The cluster anchors to OWASP LLM02 (Sensitive Information Disclosure — reading
arbitrary files) and LLM06 (Excessive Agency — the tool reaches beyond its
intended scope).

---

## Rule-by-rule defense

### CSDK-004 — Path parameter used in I/O without validation (Severity: high, Confidence: 0.7, Fix type: code)

**What we detect:**
A path-shaped parameter that flows into a filesystem call (`open`, `Path`,
`shutil.*`, `os.*`) in the tool body without a `.resolve()` / `realpath()` having
been applied to that parameter in the same function.

**Why it is flaggable:**
An unnormalized model-supplied path can traverse out of the intended directory or
follow a symlink to an arbitrary target.

**Real-world consequence:**
`read_file(path)` doing `open(path)` is asked to open `../../.env` or
`~/.aws/credentials`; the secret's contents return into the conversation and
leak downstream.

**Why severity is high and not medium:**
The outcome is arbitrary-file read or overwrite — credential theft or
corruption. It is not bumped further because exploitation depends on what the
tool then does with the handle and on the process's own file permissions.

**Fix type — code:**
Resolve the path and enforce a containment check in the tool source.

**Confidence 0.7:**
The confidence is deliberately moderate: the predicate sees normalization only
when it happens in the same function via a recognized call. A tool that validates
the path through a helper in another module, or with `is_relative_to()` against a
root *without* a literal `.resolve()` the predicate recognizes, is a false
positive. Conversely, a tool that calls `.resolve()` but never checks containment
passes the rule yet is still unsafe — a false negative the rule cannot close,
which is why containment lives in the recommendations.

---

## What this policy does not cover

- Containment: a tool that resolves the path but never checks it is inside an
  allowed root satisfies the rule and remains exploitable.
- Normalization performed in a helper in another module (the body-only walk does
  not follow it) — a false positive.
- Path-like values that do not match the name heuristic (e.g. a parameter called
  `target` or `name` that is actually a path).
- Symlink races (TOCTOU) between the resolve and the open.

---

## Recommendations beyond the fix

```python
from pathlib import Path
from claude_agent_sdk import tool

_ROOT = Path("/srv/agent/workspace").resolve()

@tool
def read_file(path: str) -> dict:
    """Read a UTF-8 text file from inside the agent workspace."""
    p = (_ROOT / path).resolve()
    if not p.is_relative_to(_ROOT):       # containment, not just normalization
        return {"error": "path escapes the workspace", "retryable": False}
    if p.is_symlink():
        return {"error": "symlinks are not allowed", "retryable": False}
    return {"content": p.read_text(encoding="utf-8", errors="replace")[:500_000]}
```

1. Always pair `.resolve()` with `is_relative_to(root)` — normalization without a
   containment check is the most common way to satisfy the rule yet stay
   vulnerable.
2. Join under a fixed root (`_ROOT / path`) instead of trusting an absolute path
   the model supplies.
3. Reject symlinks explicitly, and cap the bytes read so a large or device file
   cannot exhaust memory.
