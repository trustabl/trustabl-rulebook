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
  - id: ADK-014
    severity: low
    confidence: 0.5
    scope: tool
    fix_type: code
references: [LLM02, LLM06]
---

# Policy Rationale: Path Safety

**Policy ID:** `google_adk_path_safety`  
**File:** `google_adk/path_safety.yaml`  
**Rules:** ADK-004, ADK-014  
**Severities:** high, low  
**Fix types:** code, code  
**References:** LLM02, LLM06

> **Read [claude_sdk/path_safety.md](../claude_sdk/path_safety.md) for the full threat model.**
> This document covers Google ADK–specific differences only.

---

## What this policy covers

Python Google ADK `FunctionTool`-wrapped functions that pass a path-like
parameter into a filesystem call without normalizing it
(`call_uses_unnormalized_path_param`, per-parameter), matched by ADK-004. Same
predicate and threat model as the Claude path-safety policy.

TypeScript ADK `FunctionTool`s are covered by ADK-014 (`language:
typescript`), which matches a single predicate, `has_write_call: true`. The
pack calls it a coarse signal: it flags any filesystem write, not only
unnormalized paths, because TypeScript path-normalization analysis is not yet
wired.

---

## Why path safety is a distinct concern in agent tools

Identical to the Claude case — the model supplies the path, so an unnormalized path
is an arbitrary-file read/overwrite primitive, and normalization without a
containment check still leaves the tool exploitable. See
[claude_sdk/path_safety.md](../claude_sdk/path_safety.md#why-path-safety-is-a-distinct-concern-in-agent-tools).

ADK-specific note: on a managed runtime the readable filesystem includes mounted
secrets and the service-account ambient environment, so an arbitrary-read path
tool is a credential-exposure path as well as a data one.

ADK-014 covers writes from TypeScript tools. If the path or the contents of a
write derive from the tool's arguments, the model chooses both, and a prompt
injection carried in retrieved content or an earlier tool result can steer the
write at any file the host process can reach. A `before_tool_callback` does not
close this by default. The pack's explanation says ADK-102 and ADK-107 (both
declared `language: python`) are about the callback being present at all, and
that a callback that is present still has to inspect the path itself and know
which root is allowed. It adds that agent composition widens the reach, since
any branch of the agent tree that lists the tool can reach it.

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

### ADK-014 — TypeScript FunctionTool writes to the filesystem (Severity: low, Confidence: 0.5, Fix type: code)

**What we detect:**
A TypeScript ADK `FunctionTool` that writes to the filesystem
(`has_write_call: true`). The rule has no other predicate: it does not look at
where the path comes from or whether it was normalized.

**Why it is flaggable:**
The mechanism is the one stated
[above](#why-path-safety-is-a-distinct-concern-in-agent-tools): when the path
or the contents come from the tool's arguments, the model chooses where the
write lands and what it contains, and a prompt injection can steer that choice.

**Real-world consequence:**
A tool takes a file path from the model. The model reads a retrieved page
carrying an injected instruction, and the tool writes over a file the host
process can reach. Any branch of the agent tree that lists the tool can make
the same write.

**Why severity is low:**
The pack sets low and states no reasoning for it. The explanation makes the
risk conditional on something the rule does not check, that the path or the
contents derive from the tool's arguments, and asks the reader to confirm the
path is genuinely model-supplied before acting.

**Fix type — code:**
The pack's fix is a change inside the tool: confine writes to a dedicated
working directory, resolve the final path, verify it stays under that root
before writing, and reject absolute paths and any input containing `..`. The
pack puts the check in the tool rather than in a `before_tool_callback`, and
says that way it holds for each agent in the tree that lists the tool.

**Confidence 0.5:**
The pack sets 0.5 and states the limit itself: the rule is a coarse signal that
flags any filesystem write, not only unnormalized paths, because TypeScript
path-normalization analysis is not yet wired. A write whose path is normalized
and contained therefore fires the same as one that is not, including the
example under [Recommendations beyond the fix](#recommendations-beyond-the-fix).
The explanation asks the reader to confirm the path is genuinely model-supplied
before acting. The pack names no other false-positive or false-negative
scenarios.

---

## What this policy does not cover

Same gaps as [claude_sdk/path_safety.md](../claude_sdk/path_safety.md#what-this-policy-does-not-cover):
the missing containment check, out-of-module normalization, path-like values that
miss the name heuristic, and symlink TOCTOU races.

For ADK-014:

- **Whether the path or the contents are model-supplied.** The rule flags the
  write, and the pack asks the reader to confirm the path is genuinely
  model-supplied before acting.
- **Whether the path was normalized or contained.** TypeScript
  path-normalization analysis is not yet wired, so a contained write and an
  escaping one produce the same finding.
- **Reads in TypeScript tools.** ADK-014 matches writes (`has_write_call`), and
  ADK-004 is declared for `language: python`.
- The pack states no other limits for ADK-014.

---

## Recommendations beyond the fix

The safe pattern — join under a fixed root, `.resolve()` + `is_relative_to(root)`,
reject symlinks, cap bytes — is in
[claude_sdk/path_safety.md](../claude_sdk/path_safety.md#recommendations-beyond-the-fix).
For ADK, keep mounted secrets outside any directory an agent file tool can reach,
and gate file tools with a `before_tool_callback` that re-checks the resolved path.

The TypeScript equivalent for ADK-014 puts the check inside the tool. It still
fires ADK-014, which flags any filesystem write:

```typescript
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import { FunctionTool } from "@google/adk";
import { z } from "zod";

const REPORTS_ROOT = path.resolve("/srv/app-data/reports");

export const saveReport = new FunctionTool({
  name: "save_report",
  description:
    "Save a Markdown report under the reports directory and return its relative path. Takes a relative file name such as q3/summary.md.",
  parameters: z.object({
    relativePath: z
      .string()
      .min(1)
      .max(200)
      .describe("File name relative to the reports directory, e.g. q3/summary.md."),
    markdown: z.string().max(100_000).describe("The report body as Markdown text."),
  }),
  execute: async ({ relativePath, markdown }) => {
    if (path.isAbsolute(relativePath) || relativePath.includes("..")) {
      return { status: "error", error: "invalid_path" };
    }
    const target = path.resolve(REPORTS_ROOT, relativePath);
    const rel = path.relative(REPORTS_ROOT, target);
    if (rel === "" || rel.startsWith("..") || path.isAbsolute(rel)) {
      return { status: "error", error: "path_outside_root" };
    }
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, markdown, "utf8");
    return { status: "ok", path: rel };
  },
});
```

1. Confine writes to a dedicated working directory: resolve the final path,
   verify it stays under that root before writing, and reject absolute paths
   and any input containing `..`.
2. Keep that check inside the tool rather than relying on a
   `before_tool_callback`, so it holds for each agent in the tree that lists
   the tool.
3. Where the tool writes generated names alone, derive the filename from an
   id rather than accepting a path from the model.
