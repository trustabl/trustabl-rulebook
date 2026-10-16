---
policy_id: langchain_path_safety
category: langchain
topic: path_safety
rules:
  - id: LC-009
    severity: high
    confidence: 0.7
    scope: tool
    fix_type: code
  - id: LC-023
    severity: low
    confidence: 0.5
    scope: tool
    fix_type: code
references: []
---

# Policy Rationale: LangChain Filesystem Path Safety

**Policy ID:** `langchain_path_safety`  
**File:** `langchain/path_safety.yaml`  
**Rules:** LC-009, LC-023  
**Severities:** high, low  
**Fix types:** code, code  
**References:** none

---

## What this policy covers

LangChain tools (`applies_to: langchain_tool`, `scope: tool`) where a
model-supplied path can reach the filesystem.

- **LC-009** (`language: python`) matches a tool that takes a path-like
  parameter and hands it to a file or directory operation without resolving it
  or checking it against an allowed root. The match is a single predicate,
  `call_uses_unnormalized_path_param`, with the callees `open` and `Path` and
  the callee prefixes `shutil.` and `os.`. The pack's comment on the rule says
  the predicate is per parameter: a tool with two path parameters and one
  `.resolve()` fires on the unresolved one.
- **LC-023** (`language: typescript`) matches a LangChain.js tool that writes to
  the filesystem, with the single predicate `has_write_call: true`. The pack's
  explanation calls it a coarse signal: it flags any filesystem write, not only
  unnormalized paths, because TypeScript path-normalization analysis is not yet
  wired.

---

## Why path containment is a distinct concern in LangChain tools

The pack's policy description says a traversal payload like `../../etc/passwd`
reaches real filesystem state if the tool does not resolve the path and check
it against an allowed root.

**Python (LC-009).** The pack's explanation says the tool's `args_schema` does
not close this: a Pydantic field typed `str` or `Path` validates a traversal
payload, because the schema constrains the argument's type and not the region of
the filesystem it points at. It also says a retrieved document or a page fetched
mid-run can carry the path the model then passes to the tool, so the argument
should be treated as hostile even when the user is not.

**TypeScript (LC-023).** The pack's explanation says that if the path or the
contents derive from the tool's arguments, the model chooses both, and a prompt
injection can steer the write at any file the Node process can reach. It says a
retrieval chain feeds fetched documents into the same context the model plans
from, so text in a page or a knowledge-base record can supply the filename, and
that the Zod schema constrains the argument's type and not the region of the
filesystem it points at.

---

## Rule-by-rule defense

### LC-009 — LangChain tool uses a path parameter in I/O without validation (Severity: high, Confidence: 0.7, Fix type: code)

**What we detect:**  
A Python LangChain tool that passes a path parameter that has not been
normalized to `open`, `Path`, or a callee starting with `shutil.` or `os.`,
matched by the predicate `call_uses_unnormalized_path_param`. The check is per
parameter. The pack's comment says why: a body-wide check would suppress the
finding if any normalization appears, masking real exposure on the other
parameter.

**Why it is flaggable:**  
The mechanism is the one stated
[above](#why-path-containment-is-a-distinct-concern-in-langchain-tools): the
unresolved path goes into a file or directory operation, and the pack's
explanation says the `args_schema` does not constrain which part of the
filesystem it points at.

**Real-world consequence:**  
If a `read_report(path: str)` tool calls `open(path)`, and a page fetched
mid-run carries the path `../../etc/passwd` that the model then passes to the
tool, the value validates as a `str` and the tool can open a file outside the
directory it was meant to serve.

**Why severity is high:**  
The pack sets high and states no reasoning for it.

**Fix type — code:**  
The pack's fix is an edit to the tool source. Resolve the path with
`Path(...).resolve()` and assert the result sits under an allowed root before
touching it, rejecting anything that escapes. Encode the check as a validator on
the `args_schema` field, so containment holds for each tool that accepts the
path rather than being re-implemented per call site.

**Confidence 0.7:**  
The pack sets 0.7 for this rule and states one limit: "Detection is heuristic;
confirm the parameter is genuinely model-supplied before applying the fix." It
names no false-positive or false-negative scenarios.

### LC-023 — TypeScript LangChain tool writes to the filesystem (Severity: low, Confidence: 0.5, Fix type: code)

**What we detect:**  
A LangChain.js tool that writes to the filesystem (`has_write_call: true`). The
rule has no other predicate.

**Why it is flaggable:**  
The mechanism is the one stated
[above](#why-path-containment-is-a-distinct-concern-in-langchain-tools): the
pack's explanation says that if the path or the contents derive from the tool's
arguments, the model chooses both.

**Real-world consequence:**  
If a `save_note` tool takes a file name from the model, and a knowledge-base
record returned by a retrieval chain supplies a name containing `../`, the value
can pass the Zod schema and the write can land outside the directory the tool
was meant to write to.

**Why severity is low:**  
The pack sets low and states no reasoning for it. The costs the explanation
names are a write steered at any file the Node process can reach if the path or
contents derive from the tool's arguments.

**Fix type — code:**  
The pack's fix is an edit to the tool source: confine writes to a dedicated
working directory, resolve the final path, verify it stays under that root
before writing, and reject absolute paths and any input containing `..`. Where
the tool writes nothing but generated names, derive the filename from an id rather
than accepting a path from the model at all.

**Confidence 0.5:**  
The pack sets 0.5 for this rule and states one limit: "Coarse signal — it flags
any filesystem write, not only unnormalized paths, because TypeScript
path-normalization analysis is not yet wired. Confirm the path is genuinely
model-supplied before acting." It names no false-positive or false-negative
scenarios.

**Applying the fix.** Because the pack calls the rule a coarse signal that flags
any filesystem write, the example in
[Recommendations](#recommendations-beyond-the-fix) still matches LC-023 after
the fix. The fix does not clear the finding.

---

## What this policy does not cover

- **Whether the path is model-supplied.** The pack asks the reader to confirm
  this for both rules before acting.
- **Python I/O through other calls.** LC-009 lists the callees `open` and
  `Path` and the callee prefixes `shutil.` and `os.`; the pack names no others.
- **TypeScript reads.** LC-023 matches writes (`has_write_call`), and
  `langchain/path_safety.yaml` has no TypeScript rule for reads.
- The pack states no other limits for either rule.

---

## Recommendations beyond the fix

```python
from pathlib import Path

from langchain_core.tools import tool
from pydantic import BaseModel, Field, field_validator

REPORTS_ROOT = Path("/srv/app-data/reports").resolve()


class ReadReportInput(BaseModel):
    path: Path = Field(description='A path relative to the reports directory, e.g. "q3/summary.md".')

    @field_validator("path")
    @classmethod
    def stay_inside_reports_root(cls, value: Path) -> Path:
        resolved = (REPORTS_ROOT / value).resolve()
        if not resolved.is_relative_to(REPORTS_ROOT):
            raise ValueError("path must stay inside the reports directory")
        return resolved


@tool(args_schema=ReadReportInput)
def read_report(path: Path) -> str:
    """Read a Markdown report from the reports directory and return its text."""
    return path.read_text(encoding="utf-8")
```

1. Resolve the path with `Path(...).resolve()` and check that the result sits
   under an allowed root before touching it, rejecting anything that escapes.
2. Put that check in a validator on the `args_schema` field, so each tool that
   accepts the path gets the same containment instead of re-implementing it per
   call site.

The TypeScript equivalent for LC-023. It still matches LC-023, for the reason
given under Confidence 0.5 above.

```typescript
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

import { tool } from "@langchain/core/tools";
import { z } from "zod";

const NOTES_ROOT = path.resolve("/srv/app-data/notes");

export const saveNote = tool(
  async ({ relativePath, text }) => {
    if (path.isAbsolute(relativePath) || relativePath.includes("..")) {
      return JSON.stringify({ ok: false, error: "invalid_path" });
    }
    const target = path.resolve(NOTES_ROOT, relativePath);
    const rel = path.relative(NOTES_ROOT, target);
    if (rel === "" || rel.startsWith("..") || path.isAbsolute(rel)) {
      return JSON.stringify({ ok: false, error: "path_outside_root" });
    }
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, text, "utf8");
    return JSON.stringify({ ok: true, path: rel });
  },
  {
    name: "save_note",
    description: "Save a note's text under the notes directory and return its relative path. Takes a relative file name such as projects/q3.md.",
    schema: z.object({
      relativePath: z.string().min(1).max(200),
      text: z.string().max(100_000),
    }),
  },
);
```

3. Confine writes to a dedicated working directory: resolve the final path,
   verify it stays under that root before writing, and reject absolute paths
   and any input containing `..`.
4. Where the tool writes nothing but generated names, derive the filename from an
   id rather than accepting a path from the model at all.
