---
policy_id: vercel_ai_path_safety
category: vercel_ai
topic: path_safety
rules:
  - id: VAI-015
    severity: low
    confidence: 0.5
    scope: tool
    fix_type: code
references: []
---

# Policy Rationale: Vercel AI SDK Filesystem Path Safety

**Policy ID:** `vercel_ai_path_safety`  
**File:** `vercel_ai/path_safety.yaml`  
**Rules:** VAI-015  
**Severities:** low  
**Fix types:** code  
**References:** none

---

## What this policy covers

Vercel AI SDK tools (`applies_to: vercel_ai_tool`, `language: typescript`)
whose `execute()` handler writes to the filesystem. The match is a single
predicate, `has_write_call: true`. The pack calls it a coarse signal: it flags
any filesystem write, not only unnormalized paths, because TypeScript
path-normalization analysis is not yet wired.

---

## Why filesystem writes are a distinct concern in Vercel AI SDK tools

If the path or the contents of a write derive from the tool's arguments, the
model chooses both. A prompt injection carried in retrieved content or an
earlier tool result can then steer the write at any file the host process can
reach: a config file, a build artifact, source in the deployed bundle. The
policy states the outcome directly: a write whose path or contents derive from
model-supplied arguments lets a prompt-injected agent overwrite anything the
host process can reach.

Where a Vercel AI tool runs inside the same server process as the request
handler, not in a sandbox, the write inherits the application's own filesystem
permissions rather than a restricted set.

---

## Rule-by-rule defense

### VAI-015 — Vercel AI tool writes to the filesystem (Severity: low, Confidence: 0.5, Fix type: code)

**What we detect:**  
A Vercel AI SDK tool whose `execute()` handler writes to the filesystem
(`has_write_call: true`). The rule has no other predicate: it does not look at
where the path comes from or whether it was normalized.

**Why it is flaggable:**  
The mechanism is in
[the section above](#why-filesystem-writes-are-a-distinct-concern-in-vercel-ai-sdk-tools):
when the path or the contents come from the tool's arguments, the model
chooses where the write lands and what it contains, and a prompt injection can
steer that choice.

**Real-world consequence:**  
A tool that takes a file path from the model reads a retrieved page carrying an
injected instruction, and writes over a config file the application reads,
with the application's own filesystem permissions.

**Why severity is low:**  
The pack sets low and states no reasoning for it. The explanation makes the
risk conditional on something the rule does not check, that the path or the
contents derive from the tool's arguments, and asks the reader to confirm the
path is genuinely model-supplied before acting.

**Fix type — code:**  
The pack's fix is a change to the handler: confine writes to a dedicated
working directory, resolve the final path, verify it stays under that root
before writing, and reject absolute paths and any input containing `..`.

**Confidence 0.5:**  
The pack sets 0.5 and states the limit itself: the rule is a coarse signal that
flags any filesystem write, not only unnormalized paths, because TypeScript
path-normalization analysis is not yet wired. A write whose path is normalized
and contained therefore fires the same as one that is not. The explanation asks
the reader to confirm the path is genuinely model-supplied before acting. The
pack names no other false-positive or false-negative scenarios.

---

## What this policy does not cover

- **Whether the path or the contents are model-supplied.** The rule flags the
  write, and the pack asks the reader to confirm the path is genuinely
  model-supplied before acting.
- **Whether the path was normalized or contained.** TypeScript
  path-normalization analysis is not yet wired, so a contained write and an
  escaping one produce the same finding.
- **Reads.** VAI-015 is the only rule in `vercel_ai/path_safety.yaml`, and it
  matches writes (`has_write_call`).
- The pack states no other limits for this rule.

---

## Recommendations beyond the fix

```typescript
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import { tool } from "ai";
import { z } from "zod";

const REPORTS_ROOT = path.resolve("/srv/app-data/reports");

export const saveReport = tool({
  description:
    "Save a Markdown report under the reports directory and return its " +
    "relative path. Takes a relative file name such as q3/summary.md.",
  inputSchema: z.object({
    relativePath: z.string().min(1).max(200),
    markdown: z.string().max(100_000),
  }),
  execute: async ({ relativePath, markdown }) => {
    if (path.isAbsolute(relativePath) || relativePath.includes("..")) {
      return { ok: false, error: "invalid_path" };
    }
    const target = path.resolve(REPORTS_ROOT, relativePath);
    const rel = path.relative(REPORTS_ROOT, target);
    if (rel === "" || rel.startsWith("..") || path.isAbsolute(rel)) {
      return { ok: false, error: "path_outside_root" };
    }
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, markdown, "utf8");
    return { ok: true, path: rel };
  },
});
```

1. Confine writes to a dedicated working directory: resolve the final path,
   verify it stays under that root before writing, and reject absolute paths
   and any input containing `..`.
2. Where the tool only ever writes to generated names, derive the filename
   server-side from an id rather than accepting a path from the model at all.
