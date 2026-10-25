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
  - id: OAI-029
    severity: low
    confidence: 0.5
    scope: tool
    fix_type: code
references: [LLM02, LLM06]
---

# Policy Rationale: Path Safety

**Policy ID:** `openai_sdk_path_safety`  
**File:** `openai_sdk/path_safety.yaml`  
**Rules:** OAI-006, OAI-029  
**Severities:** high, low  
**Fix types:** code, code  
**References:** LLM02, LLM06

> **Read [claude_sdk/path_safety.md](../claude_sdk/path_safety.md) for the full threat model.**
> This document covers OpenAI Agents SDK–specific differences only.

---

## What this policy covers

OpenAI Agents SDK `@function_tool` bodies that pass a path-like parameter into a
filesystem call without normalizing it. Same `call_uses_unnormalized_path_param`
predicate, per-parameter tracking, and threat model as the Claude path-safety
policy.

OAI-029 covers TypeScript Agents SDK tools (`language: typescript`) that write
to the filesystem. The match is a single predicate, `has_write_call: true`. The
pack calls it a coarse signal: it flags any filesystem write, not only
unnormalized paths, because TypeScript path-normalization analysis is not yet
wired.

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

The TypeScript side is OAI-029. If the path or the contents of a write derive
from the tool's arguments, the model chooses both, and a prompt injection
carried in retrieved content or an earlier tool result can steer the write at
any file the host process can reach. Where the tool runs in the same server
process as the request handler rather than in a sandbox, the write inherits the
application's own filesystem permissions. OAI-104 and OAI-004, named in the
note above, are Python rules in the pack.

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

### OAI-029 — TypeScript tool writes to the filesystem (Severity: low, Confidence: 0.5, Fix type: code)

**What we detect:** a TypeScript Agents SDK tool that writes to the filesystem
(`has_write_call: true`). The rule has no other predicate: it does not look at
where the path comes from or whether it was normalized.

**Why it is flaggable:** the mechanism is the TypeScript one stated
[above](#why-path-safety-is-a-distinct-concern-in-agent-tools): when the path
or the contents come from the tool's arguments, the model chooses where the
write lands and what it contains, and a prompt injection can steer that choice.

**Real-world consequence:** a tool takes a file path from the model. The model
reads a retrieved page carrying an injected instruction, and the tool writes
over a file the application reads. If the tool runs in the request handler's
process, the write carries the application's own filesystem permissions.

**Why severity is low:** the pack sets low and states no reasoning for it. The
explanation makes the risk conditional on something the rule does not check,
that the path or the contents derive from the tool's arguments, and asks the
reader to confirm the path is genuinely model-supplied before acting.

**Fix type — code:** the pack's fix is a change to the tool's handler: confine
writes to a dedicated working directory, resolve the final path, verify it
stays under that root before writing, and reject absolute paths and any input
containing `..`. Where the tool only ever writes generated names, derive the
filename server-side from an id rather than accepting a path from the model at
all.

**Confidence 0.5:** the pack sets 0.5 and states the limit itself: the rule is a
coarse signal that flags any filesystem write, not only unnormalized paths,
because TypeScript path-normalization analysis is not yet wired. A write whose
path is normalized and contained therefore fires the same as one that is not.
The explanation asks the reader to confirm the path is genuinely model-supplied
before acting. The pack names no other false-positive or false-negative
scenarios.

---

## What this policy does not cover

For OAI-006, the same gaps as [claude_sdk/path_safety.md](../claude_sdk/path_safety.md#what-this-policy-does-not-cover):
the missing containment check, out-of-module normalization, path-like values that
miss the name heuristic, and symlink TOCTOU races.

For OAI-029:

- **Whether the path or the contents are model-supplied.** The rule flags the
  write, and the pack asks the reader to confirm the path is genuinely
  model-supplied before acting.
- **Whether the path was normalized or contained.** TypeScript
  path-normalization analysis is not yet wired, so a contained write and an
  escaping one produce the same finding.
- **TypeScript reads.** OAI-029 matches writes (`has_write_call`), and
  `openai_sdk/path_safety.yaml` has no TypeScript rule for reads.
- The pack states no other limits for this rule.

---

## Recommendations beyond the fix

The safe pattern — join under a fixed root, `.resolve()` + `is_relative_to(root)`,
reject symlinks, cap bytes — is in
[claude_sdk/path_safety.md](../claude_sdk/path_safety.md#recommendations-beyond-the-fix).
For the OpenAI SDK, run such tools under a `SandboxAgent` and return rejections via
`failure_error_function` as structured, retryable=false errors.

For a TypeScript tool that writes, let the server choose the filename and keep
the write under a fixed root. This example still matches OAI-029. The pack
describes the rule as a coarse signal that flags any filesystem write, so a
tool that writes is flagged even when it confines the path. The fix reduces the
exposure the rule is about, but it does not clear the finding:

```typescript
import { randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import { tool } from "@openai/agents";
import { z } from "zod";

const REPORTS_ROOT = path.resolve("/srv/app-data/reports");

export const saveReport = tool({
  name: "save_report",
  description: "Save a Markdown report under the reports directory and return the generated file name. The server chooses the name; the model never passes a path.",
  parameters: z.object({ markdown: z.string().max(100_000) }),
  execute: async ({ markdown }) => {
    const fileName = `${randomUUID()}.md`;
    const target = path.resolve(REPORTS_ROOT, fileName);
    const rel = path.relative(REPORTS_ROOT, target);
    if (rel === "" || rel.startsWith("..") || path.isAbsolute(rel)) {
      return { ok: false, error: "path_outside_root" };
    }
    await mkdir(REPORTS_ROOT, { recursive: true });
    await writeFile(target, markdown, { encoding: "utf8", flag: "wx" });
    return { ok: true, fileName };
  },
});
```

1. Confine writes to a dedicated working directory: resolve the final path,
   verify it stays under that root before writing, and reject absolute paths
   and any input containing `..`.
2. Where the tool only ever writes generated names, derive the filename
   server-side from an id, as above, rather than accepting a path from the
   model at all.
