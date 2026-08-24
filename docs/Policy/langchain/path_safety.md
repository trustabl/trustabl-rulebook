---
policy_id: langchain_path_safety
category: langchain
topic: path_safety
rules:
  - id: LC-008
    severity: high
    confidence: 0.7
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: LangChain Filesystem Path Safety

**Policy ID:** `langchain_path_safety`  
**File:** `langchain/path_safety.yaml`  
**Rules:** LC-008  
**Severities:** high  
**Fix types:** code  
**References:** LLM06 (Excessive Agency)

> Shares the path-containment threat model with
> [mcp/path_safety.md](../mcp/path_safety.md). LangChain-specific angle only.

---

## What this policy covers

A LangChain tool — a `@tool`-decorated function, or the function wrapped by `StructuredTool` / `Tool` — that takes a path-like parameter and passes it to a
filesystem call (`open`, `Path`, any `os.*` or `shutil.*`) without resolving it
first. Detected by `call_uses_unnormalized_path_param`, which is evaluated
per-parameter: a tool with two path parameters and one `.resolve()` correctly
fires on the unresolved one.

---

## Why path containment is a distinct concern in agent tools

In a conventional service the caller is a client you authenticate. In an agent
the caller is the model, and the model's arguments are synthesized from its
context. So the question "is this parameter attacker-controlled?" is not answered
by looking at the tool's signature — it is answered by asking what can reach the
context, which is usually more than the tool author had in mind.

LangChain fills a tool's arguments from the model's context, and that context is
assembled from whatever the chain put there: retrieved documents, previous tool
output, and user text. Any of those can be untrusted, and none of them is
distinguishable from the others by the time the model writes the argument. A
retriever that indexes user-submitted content is enough — the traversal string
travels from document, to context, to tool argument, to `open()`.

The consequence is ordinary path traversal with an unusual trigger. A tool that
means to read from `/srv/docs` will read `/etc/passwd`, or `~/.aws/credentials`,
or `.git/config`, because `open("../../etc/passwd")` is a perfectly valid call
and nothing in the tool disagrees. Where the call writes rather than reads, the
same argument overwrites files outside the intended root. The agent was granted
the capability to touch the filesystem; without containment it was granted the
capability to touch *the* filesystem (excessive agency, LLM06).

Prompt injection is what turns this from a robustness issue into a security one.
The attacker does not need to reach the tool — they need to reach a document the
agent will read.

---

## Rule-by-rule defense

### LC-008 — LangChain tool uses a caller-supplied path without containment (Severity: high, Confidence: 0.7, Fix type: code)

**What we detect:** a parameter whose name looks path-like flowing into `open`,
`Path`, or any `os.*` / `shutil.*` call, with no `.resolve()` applied to it
first.

**Why it is flaggable:** the tool's filesystem reach is whatever string the model
supplies. There is no root, so there is nothing for a traversal payload to escape
from — the tool's intended directory exists only in the author's head, not in the
code.

**Real-world consequence:**

- A `read_doc(path)` tool intended for `/srv/docs` is called with
  `../../../etc/passwd`. The contents enter the model's context, and from there
  the transcript and any downstream summary.
- The same shape against `~/.aws/credentials` or `.env` turns a document-reading
  tool into a credential-exfiltration primitive, with the credentials arriving
  somewhere they will be logged.
- A writing variant — `shutil.copy(src, path)` — places attacker-chosen content
  outside the root. Pointed at a config file or a script the host later executes,
  the traversal becomes code execution.

**Why severity is high and not critical:** exploitation needs a reachable
untrusted input in the agent's context, and the damage is bounded by the process's
own filesystem permissions — a tool running as a low-privilege user with a
read-only mount is meaningfully contained even with this defect. Critical is
reserved for patterns with no such precondition. It is not medium: no additional
misconfiguration is required, the payload is a string anyone can write, and the
blast radius is the process's entire filesystem view.

**Fix type — code:** resolving the path and asserting containment is a source
edit inside the tool body. No guardrail or agent-constructor setting substitutes.

**Confidence 0.7:** detection is heuristic on both sides. False positives: a
parameter that *looks* path-like but is supplied by the application rather than
the model, or is constrained upstream by a wrapper or a validator the body-local
read cannot see. False negatives: a path built by joining the parameter to a
constant prefix before the call, or passed through a helper function, escapes the
per-parameter match — and `os.path.join(ROOT, path)` in particular is a common
non-fix, since an absolute `path` discards `ROOT` entirely.

---

## What this policy does not cover

- Containment applied outside the tool body — in a wrapper, a decorator, a
  validator, or a sandbox/mount policy the static read cannot see.
- `os.path.join(ROOT, path)` and similar prefix-joins, which *look* like
  containment and are not: an absolute `path` discards the prefix.
- Paths reaching I/O through a helper function rather than directly, or built by
  string concatenation before the call.
- `.resolve()` applied but its result never checked against a root. The rule sees
  the resolve and goes silent; resolving alone contains nothing.
- Symlinks inside an allowed root pointing outside it, where the resolved path
  passes the check but the target does not.
- Whether the process should have had filesystem access at all — a sandbox or
  read-only mount is a stronger control and out of scope here.

---

## Recommendations beyond the fix

```python
from pathlib import Path

ROOT = Path("/srv/docs").resolve()


def _contained(candidate: str) -> Path:
    p = (ROOT / candidate).resolve()
    if not p.is_relative_to(ROOT):
        raise ValueError("path escapes the allowed root")
    return p
```

1. Resolve first, check second, and check the *resolved* path. Any validation of
   the raw string is defeated by `..` and by symlinks.
2. Do not use `os.path.join(ROOT, path)` as the containment — an absolute `path`
   discards `ROOT`. Join, then resolve, then compare.
3. Put the root in one helper and route every filesystem tool through it, so the
   containment cannot be present in one tool and forgotten in the next.
4. Treat the process boundary as the real control: run the agent with a read-only
   mount, or a bind-mount of just the intended root, so a missed check in a tool
   is not the only thing standing between the model and the filesystem.
5. Do the check on the *resolved* path. Validating the raw string still lets
symlinks and `..` segments through.
