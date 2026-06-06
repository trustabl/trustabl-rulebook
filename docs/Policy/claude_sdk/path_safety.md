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
  - id: CSDK-012
    severity: low
    confidence: 0.5
    scope: tool
    fix_type: code
references: [LLM02, LLM06]
---

# Policy Rationale: Path Safety

**Policy ID:** `claude_sdk_path_safety`  
**File:** `claude_sdk/path_safety.yaml`  
**Rules:** CSDK-004, CSDK-012  
**Severities:** high, low  
**Fix types:** code, code  
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

### CSDK-012 — TypeScript Claude SDK tool writes to the filesystem (Severity: low, Confidence: 0.5, Fix type: code)

**What we detect:**
A TypeScript Claude SDK `tool(...)` whose handler body invokes a filesystem-write
API — `writeFile`, `writeFileSync`, `appendFile`, `appendFileSync`, or
`createWriteStream`, bare or under an `fs.*` / `fsPromises.*` namespace — detected
by the structured `has_write_call` predicate (during discovery `tsHandlerFacts`
stamps a `writes_fs` fact on the recognized callees; `has_write_call` reads it for
TypeScript). It is a callee match, not a substring scan, so the name in a comment
or string literal does not fire it. The signal is still deliberately **coarse**:
it fires on the *presence of a filesystem write*, not on a write of an
unnormalized or model-controlled path. Unlike the Python sibling CSDK-004 there is
**no** path-flow analysis behind it — TS per-parameter path-normalization tracking
is not wired, so the rule cannot tell a write to a fixed, safe path from a write to
a model-supplied one.

**Why it is flaggable:**
A filesystem write inside a model-callable tool is a candidate arbitrary-file
*overwrite* primitive: if the path or contents derive from a tool argument, a
prompt-injected agent can overwrite files the host process can reach — source,
config, or `.claude/settings.json`. The threat model overlaps the Python sibling's
write half (see
[CSDK-004](#csdk-004--path-parameter-used-in-io-without-validation-severity-high-confidence-07-fix-type-code))
but the detection is far weaker: CSDK-004 confirms an *unnormalized path
parameter* flows into the write, whereas CSDK-012 only confirms a *write API is
present*.

**Real-world consequence:**
A `saveNote(name, body)` tool doing `writeFileSync(name, body)` is steered into
`writeFileSync("../../.bashrc", payload)` or into overwriting a config file to
widen the agent's own permissions.

**Why severity is low:**
This is the weakest detector in the file. It fires on *any* write — including
writes to a hard-coded safe path with no model influence — and has no path-flow
analysis behind it, so a large fraction of hits are not exploitable. Pairing a
low-precision detector with anything above low would overstate a lead that is
about as likely benign as not; low marks it as a prompt to confirm the path or
contents are model-influenced, not a defect.

**Fix type — code:**
Confining writes to a working directory and resolving/validating the final path is
an edit to the tool's own source.

**Confidence 0.5:**
The lowest in this file, and honestly so — but the reason is the *absence of
path-flow analysis*, not substring imprecision (the structured callee match means
a `writeFile(` in a comment or string literal no longer fires). The rule confirms
a write API is present, not that its path is model-influenced, so a write to a
fixed literal path or a fully developer-controlled path still fires. The 0.5
encodes "about half of these are likely benign — confirm the path or contents are
model-influenced before acting." False negatives remain: a write reached through a
renamed alias whose callee text is not recognized, `fs.open` + `write`, `fs.cp`,
`fs.rename`, or a stream piped to a file escape the recognized-callee set. This is
the weakest rule of the TS Claude rules and is labelled as such.

---

## What this policy does not cover

- Containment: a tool that resolves the path but never checks it is inside an
  allowed root satisfies the rule and remains exploitable.
- Normalization performed in a helper in another module (the body-only walk does
  not follow it) — a false positive.
- Path-like values that do not match the name heuristic (e.g. a parameter called
  `target` or `name` that is actually a path).
- Symlink races (TOCTOU) between the resolve and the open.
- (TypeScript, CSDK-012) Reads — the rule matches *write* APIs only, so a
  `readFileSync(modelPath)` arbitrary-read primitive does not fire.
- (TypeScript, CSDK-012) Write APIs outside the recognized callee set — `fs.cp`,
  `fs.rename`, `fs.open` + `write`, a write reached through a renamed alias, or a
  `pipe()` to a write stream. (`appendFile`/`appendFileSync` and the `fs.*` /
  `fsPromises.*` namespaced forms of the recognized writes are now caught.)
- (TypeScript, CSDK-012) Path normalization or containment is **not** assessed at
  all: a TS tool that resolves and gates its write path correctly still fires
  (false positive), and a write to a model-controlled path satisfies nothing the
  rule can verify — the rule only knows a write API is present.

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
