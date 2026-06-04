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

# Policy Rationale: Path Safety

**Policy ID:** `mcp_path_safety`  
**File:** `mcp/path_safety.yaml`  
**Rules:** MCP-005  
**Severities:** high  
**Fix types:** code  
**References:** LLM02, LLM06

---

## What this policy covers

MCP tool handlers that take a path-like parameter and pass it into a filesystem
call without normalizing it first. The predicate
`call_uses_unnormalized_path_param` tracks, per parameter, whether a path-shaped
argument (`path`, `file`, `*_path`, `*_dir`, …) flows into an I/O callee — `open`
or `Path`, or anything under the `shutil.` / `os.` namespaces — **without** having
been run through `.resolve()` / `os.path.realpath()` in the same handler. It is
per-parameter: a handler that resolves one path but not another still fires on the
unresolved one. The rule is scoped to `mcp_tool` — it fires on functions
registered as MCP tools (`@server.tool` / `@mcp.tool` / `.register_tool`), not on
arbitrary file-touching code.

---

## Why path safety is a distinct concern in agent tools

An MCP tool handler runs on the far side of a trust boundary that is wider than an
in-process SDK tool's. Its arguments are **fully model-controlled inputs**: they
arrive over the protocol from a connecting client, are chosen by a model from
conversation context, and reach the handler with **no human in the loop** to vet
them. A handler `read_file(path: str)` that opens `path` directly therefore trusts
the calling orchestrator — and, transitively, anything that can influence that
model, including content prompt-injected upstream — to choose which file on disk
the server reads or writes. There is no fixed, developer-authored path with only a
basename substituted; the *entire* path string is attacker-influenceable. A
payload like `../../etc/passwd`, an absolute `/home/user/.ssh/id_rsa`, or a symlink
pointing outside the intended directory all resolve to real targets.

This is worse on the server side than the same gap inside an in-process SDK tool
for two compounding reasons. First, the MCP server is a long-lived process that
commonly runs with **broad filesystem access shared across clients** — one
poisoned request can read or clobber files that belong to a different session,
project, or tenant connected to the same server. Second, the result crosses the
boundary back: a read handler is an arbitrary-file **exfiltration** primitive (the
file's bytes flow back into the model context, then into transcripts, logs, or the
next tool call), while a write handler is an arbitrary-file **overwrite** primitive
(the model can drop content at any path the server process can reach, including the
server's own config or a `.claude/settings.json` that widens its later
permissions).

Normalization alone is necessary but not sufficient: `.resolve()` collapses the
`../` and dereferences symlinks, but the resolved path must *also* be confirmed to
live inside an intended root before any I/O touches it. The rule flags the
missing-normalization precondition because that is the structurally detectable
half; the containment check is the author's responsibility (see recommendations).

The cluster anchors to OWASP LLM02 (Sensitive Information Disclosure — reading
arbitrary files such as credentials and secrets) and LLM06 (Excessive Agency — the
tool reaches filesystem state far beyond its intended scope).

---

## Rule-by-rule defense

### MCP-005 — Path parameter used in I/O without validation (Severity: high, Confidence: 0.7, Fix type: code)

**What we detect:**  
A path-shaped parameter of an MCP tool handler that flows into a filesystem call —
`open`, `Path`, or any `shutil.*` / `os.*` callee — in the handler body **without**
a `.resolve()` / `realpath()` having been applied to that parameter earlier in the
same function. The match is `call_uses_unnormalized_path_param` with
`callees: [open, Path]` and `callee_prefixes: [shutil., os.]`, evaluated
per-parameter, so a handler that normalizes one path argument but passes a second
straight through still fires on the unresolved one.

**Why it is flaggable:**  
An unnormalized, model-supplied path can traverse out of the intended directory
(`../../`), name an absolute path anywhere on the volume, or follow a symlink to an
arbitrary target. Because the handler never collapses or contains the path before
the I/O call, whatever the model passes is what the server process opens — the gap
between "a path the author intended" and "any path the model can express" is
exactly the un-normalized argument.

**Real-world consequence:**  
An MCP `read_file(path)` tool doing `open(path)` is asked by a (possibly
prompt-injected) client to open `../../etc/passwd`, `../../../.env`, or
`~/.aws/credentials`; the file's contents return across the protocol into the model
context and leak into transcripts and logs. The write direction is symmetric: a
`save_report(path, body)` handler doing `Path(path).write_text(body)` is steered
into `save_report("../../.bashrc", payload)` or into overwriting a shared config
file — on a server with filesystem access spanning multiple clients, that write can
land in another session's workspace.

**Why severity is high and not medium:**  
The outcome is arbitrary-file read or overwrite reachable directly from
model-controlled input with no human in the loop — credential theft or file
corruption, the LLM02/LLM06 core. It is not bumped to critical because exploitation
is still conditioned on what the handler does with the open handle and on the
server process's own filesystem permissions (a server confined to a per-session
chroot or running as an unprivileged user bounds the blast radius even when the
handler is buggy). It is not lowered to medium because, unlike a coarse
"writes-the-filesystem" signal, this predicate confirms an *unnormalized path
parameter actually flows into the I/O call* — the detected pattern is the
vulnerability, not merely a lead.

**Fix type — code:**  
The fix — resolve the path and assert it sits under an allowed root before any I/O
— is an edit to the tool handler's own source. It cannot be applied purely through
a guardrail, hook, or sandbox policy without changing the handler, so it is `code`,
not `config`. (A server-level sandbox bounds the damage but does not satisfy the
rule, because the handler still passes an unnormalized path into I/O.)

**Confidence 0.7:**  
Moderate by design, and below 0.80 for two specific reasons. *False positive:* the
detection is a parameter-name heuristic over a same-function body walk. It fires on
any parameter whose name looks path-like, so a `path` that is not a filesystem path
at all — a URL path component, a dotted attribute path, a JSON pointer — flagged
because it reaches a callee like `os.path.join` is a false positive. The body-only
walk is also local: a handler that hands its path argument to a shared
`validate_under_root()` helper in **another module** and only then opens the
returned value has no `.resolve()` visible in its own body, so it fires even though
it is safe (the cross-module-validation false negative-for-the-author /
false-positive-for-the-rule case). *False negative:* the rule confirms only that
*no recognized normalization call* is present — a handler that calls `.resolve()`
to clear the predicate but never checks containment against a root passes the rule
yet remains fully exploitable. The 0.7 encodes "very likely a real traversal
primitive — confirm the parameter is genuinely a caller-supplied filesystem path,
and that no out-of-module guard sits in front of it, before acting."

---

## What this policy does not cover

Written adversarially — these are the patterns a developer could point to in
arguing a finding is a false positive, and the equivalent risks that escape the
predicate entirely:

- **Containment.** A handler that calls `.resolve()` but never confirms the result
  is inside an allowed root satisfies the rule and remains exploitable — the most
  common way to clear the rule yet stay vulnerable. The rule detects
  missing-normalization, not missing-containment.
- **Out-of-module normalization.** Validation performed in a helper in another
  module (or a shared `pathutil` package) is invisible to the body-only walk, so a
  safe handler that delegates its check fires anyway — a false positive.
- **Path-like values that miss the name heuristic** — a parameter called `target`,
  `name`, `dest`, or `loc` that is in fact a filesystem path will *not* fire, so a
  genuine traversal primitive behind an off-vocabulary parameter name is a false
  negative.
- **Non-path parameters that match the name heuristic** — a `path` that is a URL
  route, an XPath/JSON-pointer, or an object attribute path is flagged when it
  reaches an `os.*` / `shutil.*` callee even though no filesystem traversal is
  possible.
- **I/O through unrecognized sinks.** The callee set is `open` / `Path` /
  `shutil.*` / `os.*`. A path that flows into `io.open`, `aiofiles.open`,
  `codecs.open`, `pathlib.Path(...).open()` reached through an alias, a
  `tempfile`-rooted join, a third-party storage client, or `subprocess`/shell file
  redirection is outside the matched set and does not fire.
- **Symlink races (TOCTOU).** Even a handler that resolves and containment-checks
  correctly can be defeated by a symlink swapped between the check and the `open()`;
  the rule does not model time-of-check/time-of-use windows.
- **Server-level confinement is not assessed.** Whether the MCP server runs in a
  chroot, a container, or as an unprivileged user — the controls that actually bound
  the blast radius across clients — is invisible to a tool-scope rule; it neither
  raises nor lowers the finding.

---

## Recommendations beyond the fix

```python
from pathlib import Path
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("files")

# One fixed root per server (ideally per-session/per-client when the server is
# multi-tenant), resolved once at import.
_ROOT = Path("/srv/mcp/workspace").resolve()


@mcp.tool()
def read_file(path: str) -> dict:
    """Read a UTF-8 text file from inside the server workspace."""
    candidate = (_ROOT / path).resolve()          # join under the root, then collapse ../ and symlinks
    if not candidate.is_relative_to(_ROOT):       # containment, not just normalization
        return {"error": "path escapes the workspace", "retryable": False}
    if candidate.is_symlink():                     # belt-and-suspenders before the final open
        return {"error": "symlinks are not allowed", "retryable": False}
    return {"content": candidate.read_text(encoding="utf-8", errors="replace")[:500_000]}
```

1. **Always pair `.resolve()` with `is_relative_to(root)`.** Normalization without
   a containment check is the single most common way to satisfy the rule yet stay
   vulnerable — the resolved path must be *proven* to live under the root.
2. **Join under a fixed root (`_ROOT / path`) instead of trusting an absolute
   path** the model supplies; an absolute `/etc/passwd` joined under a root and then
   resolved still escapes unless containment is checked, so do both.
3. **Use `is_relative_to()`, not a string `startswith(_ROOT)` prefix match** — the
   string form is defeated by a sibling directory whose name shares the prefix
   (`/srv/mcp/workspace-evil`).
4. **Scope the root per session/client on a multi-tenant server**, not one shared
   workspace, so a traversal in one connection cannot reach another client's files
   even within the allowed root.
5. **Reject symlinks explicitly and cap the bytes read** so a symlink to a device
   file or an enormous file cannot exhaust the server's memory.
6. **Run the MCP server unprivileged and confined** (container, chroot, or a
   dedicated low-permission user) so even a handler bug is bounded by the OS — this
   does not satisfy the rule, but it shrinks the worst case.
7. **Log every resolved read/write path with the client/session identifier** for
   audit, since the model — not a human — chose the path and there is no interactive
   confirmation step to capture.
