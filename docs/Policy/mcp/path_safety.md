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
**Severities:** high  
**Fix types:** code  
**References:** LLM02 (Sensitive Information Disclosure), LLM06 (Excessive Agency)

> Shares the path-traversal threat model with
> [openai_sdk/path_safety.md](../openai_sdk/path_safety.md). This document
> covers the MCP-specific mechanism: the path is chosen by a model reading
> untrusted content, and the server process has no filesystem sandbox around it.

---

## What this policy covers

Python MCP tool handlers (`applies_to: mcp_tool`, `language: python`) where a
path-like parameter reaches a filesystem operation without being resolved or
gated first. The match is `call_uses_unnormalized_path_param` over the callees
`open` and `Path`, plus anything prefixed `shutil.` or `os.`.

The predicate is evaluated **per parameter**, not per handler. A tool that
accepts two path arguments and calls `.resolve()` on one of them still fires on
the other. That design choice matters: it means partial hardening does not
silence the rule, which is the common shape when a handler grows a second path
argument later.

---

## Why path containment is a distinct concern in agent tools

Path traversal is one of the oldest bugs there is, and the mechanism has not
changed. `../` walks up a directory. What changes under MCP is where the string
comes from, and what sits between the handler and the disk.

In a conventional web application the untrusted path arrives in a request an
attacker sent, and there are usually layers between it and the filesystem. The
process runs as a low-privilege user, often in a container with a small mounted
volume, and the framework routes file access through a helper with a configured
root. The attacker has to defeat those layers.

An MCP server typically has none of that. It runs as the developer's own user,
on a workstation or a build host, with the whole filesystem visible. That is not
an oversight; it is what the tool is for. A tool called `read_file` is useful
precisely because it can read files. The containment has to live inside the
handler, because there is nowhere else for it to live.

The argument itself is filled in by the model, from context assembled out of
sources the tool author does not control: a fetched page, an uploaded document,
an issue body, the output of a previous tool call. An attacker who can place
text into any of those can influence the path this tool receives. They never
connect to the server. They write something a model will later read and act on.

That makes this a confused-deputy problem. The server holds filesystem access
the attacker does not have; the model holds that access by proxy and the
attacker's intent by injection, and it cannot separate the two, because
instructions and data arrive through the same channel. The handler then executes
correctly. Every layer behaves as designed and a file outside the intended root
is still read.

What follows depends on the direction of the I/O, and both directions are in
scope because the callee set includes `shutil.` and `os.`. On read, the content
is returned into the conversation, which is LLM02: `.env` files, SSH private
keys, cloud credential files, and `~/.aws/credentials` all sit at predictable
paths relative to a home directory. On write, the handler can place content at a
chosen location, which is LLM06 and considerably worse than disclosure: writing
to a shell profile, a crontab, or a config file the host reads on startup
converts a file operation into code execution on the next login or reboot. An
`os.remove` or `shutil.rmtree` with an escaping path is destructive with no
recovery path at all.

---

## Rule-by-rule defense

### MCP-005 — Path parameter used in I/O without validation (Severity: high, Confidence: 0.7, Fix type: code)

**What we detect:**  
A parameter the analyzer identifies as path-like, reaching a call to `open` or
`Path`, or to any callee prefixed `shutil.` or `os.`, with no intervening
`.resolve()` or containment check on that parameter. Detection is per-parameter,
so each path argument is evaluated on its own.

**Why it is flaggable:**  
A path that has not been resolved is not the path it appears to be. `..`
segments, absolute paths supplied where a relative one was expected, and `~`
expansion all mean the string the handler received and the location it will
touch are different things. Resolving is the step that collapses them into one,
and until it happens no check on the string is meaningful.

**Real-world consequence:**

- A `read_file(path)` tool intended for a project directory is given
  `../../../.ssh/id_rsa` by a model that just summarized a page containing
  injected instructions. The key is returned into the transcript.
- A `save_note(path, content)` tool writes to `~/.bashrc`. The next shell the
  developer opens executes whatever was written.
- A `cleanup(path)` tool calling `shutil.rmtree` receives a path that escapes
  its intended directory and deletes work that was never backed up.

**Why severity is high and not medium:**  
The write case has no partial mitigation. Once content is placed at an
attacker-chosen path on a host that executes shell profiles or scheduled jobs,
the outcome is code execution under the developer's own account, and nothing
downstream of the handler is positioned to prevent it. The read case is
comparably severe in practice because credential files sit at well-known paths
relative to `~`, so a single successful traversal is often a full credential
disclosure rather than an incremental leak. Medium would imply a precondition
that caps the damage; on a server running as the developer's user with no
sandbox, there is not one.

**Fix type — code:**  
Containment must happen inside the handler: resolve the path, then assert it
sits under an allowed root before any I/O. No sandbox policy or agent
constructor parameter can retrofit a root onto a handler that opens whatever
string it is given. OS-level containment would help, but it is not something the
tool author configures from here, and it is not what the rule is asking for.

**Confidence 0.7:**  
The gap is that "path-like parameter" is a heuristic, and the containment check
is structural rather than semantic. **False positives:** a parameter named
`path` that is not a filesystem path at all, such as a URL path segment, an
object key, or a dotted attribute path, fires on shape alone. A path that is
author-controlled rather than caller-controlled, read from configuration or
constructed from a constant, fires identically because the rule does not know
where the value came from. A handler that validates correctly using an approach
the rule does not recognise, such as `is_relative_to()` on an already-resolved
base or a lookup against an allow-list of known filenames, fires anyway.
**False negatives:** containment performed by a helper in another module leaves
the handler with a bare parameter and no visible `.resolve()`, so the rule sees
an unguarded path and, more importantly, a genuinely unguarded handler that
delegates its I/O elsewhere presents the same shape and is also missed. The
rule's own explanation asks the reader to confirm the parameter is caller-
supplied, which is an accurate statement of what the 0.3 gap represents.

---

## What this policy does not cover

- **Whether the parameter is genuinely caller-controlled.** The predicate is
  structural. A path built from an environment variable or a constant elsewhere
  in the module is author-controlled and fires identically to one taken straight
  from a tool argument.
- **Whether the parameter is a filesystem path at all.** URL paths, S3 keys,
  dotted config paths, and XPath expressions all look path-like by name and
  shape.
- **Containment done outside the handler body.** A helper that resolves and gates
  before returning a safe path satisfies the intent completely and leaves no
  `.resolve()` at the call site.
- **Symlink escape after a correct resolution.** `Path(...).resolve()` follows
  symlinks, so a path that resolves inside the allowed root can still point at a
  target outside it if an attacker controls a link within the root. Checking
  containment after resolution does not catch this.
- **TOCTOU races.** The path is checked, then used. A path that is valid at
  check time and replaced before the open is not detectable at this level, and
  is not addressed by the recommended fix either.
- **I/O through callees outside the set.** The set is `open`, `Path`, and
  anything prefixed `shutil.` or `os.`. `io.open`, `pathlib` operations reached
  through an alias, `tempfile`, `glob`, `zipfile` extraction, and third-party
  filesystem libraries are not inspected. Archive extraction is worth calling
  out separately, since a malicious archive can write outside the extraction
  root through entry names alone without any parameter looking suspicious.
- **Whether the allowed root is sensibly chosen.** A handler that resolves
  correctly and asserts containment under `/` passes the rule and contains
  nothing.
- **TypeScript MCP tools.** MCP-005 is `language: python`. There is no
  TypeScript path-normalization predicate in `mcp/path_safety.yaml`, so TS
  filesystem risk is currently approximated only by the shell and code-execution
  rules, which do not cover a plain `fs.readFile` with a caller-supplied path.

---

## Recommendations beyond the fix

```python
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("workspace")

WORKSPACE_ROOT = Path("/srv/workspace").resolve()


@mcp.tool()
def read_file(relative_path: str) -> dict:
    """Read a file from the workspace. The path is resolved first, then checked
    for containment, so traversal segments and absolute paths cannot escape the
    root."""
    candidate = (WORKSPACE_ROOT / relative_path).resolve()

    if not candidate.is_relative_to(WORKSPACE_ROOT):
        return {"ok": False, "error": "path_outside_workspace"}

    if candidate.is_symlink():
        return {"ok": False, "error": "symlink_not_allowed"}

    if not candidate.is_file():
        return {"ok": False, "error": "not_a_file"}

    try:
        text = candidate.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return {"ok": False, "error": "not_text"}
    except OSError:
        return {"ok": False, "error": "read_failed"}

    return {"ok": True, "path": str(candidate.relative_to(WORKSPACE_ROOT)),
            "text": text}
```

1. Resolve before checking, never after. A containment test on an unresolved
   string is testing the wrong value, and string-prefix comparison against a
   root is defeated by `..` segments the resolution would have collapsed.
2. Use `is_relative_to()` rather than `str(path).startswith(root)`. Prefix
   matching accepts `/srv/workspace-backup` as being inside `/srv/workspace`.
3. Reject symlinks explicitly if the root can contain attacker-writable
   directories. Resolution follows links, so containment alone does not stop a
   link inside the root pointing outward.
4. Return a path relative to the root rather than the absolute one. The absolute
   path discloses the deployment layout into the conversation for no benefit to
   the caller.
5. Separate read and write tools, and give the write tool a narrower root. Most
   handlers that need to read broadly do not need to write at all, and the write
   case is where the damage ceiling sits.
6. Where the set of legitimate files is known, take an identifier rather than a
   path and look the real location up server-side. As with SSRF, the strongest
   version of this fix removes the caller's ability to name a destination at all.