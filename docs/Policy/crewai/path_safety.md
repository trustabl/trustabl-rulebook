---
policy_id: crewai_path_safety
category: crewai
topic: path_safety
rules:
  - id: CREW-009
    severity: high
    confidence: 0.7
    scope: tool
    fix_type: code
references: []
---

# Policy Rationale: CrewAI Filesystem Path Safety

**Policy ID:** `crewai_path_safety`  
**File:** `crewai/path_safety.yaml`  
**Rules:** CREW-009  
**Severities:** high  
**Fix types:** code  
**References:** none

---

## What this policy covers

Python CrewAI tools (`applies_to: crewai_tool`, `language: python`,
`scope: tool`) that take a path-like parameter and hand it to a file or
directory operation without resolving it or checking it against an allowed
root. The match is a single predicate, `call_uses_unnormalized_path_param`,
with the callees `open` and `Path` and the callee prefixes `shutil.` and
`os.`. The pack states that the predicate is per parameter: a tool with two
path parameters and one `.resolve()` fires on the unresolved one.

---

## Why path containment is a distinct concern in CrewAI tools

The path comes from the model. A traversal payload such as `../../etc/passwd`
reaches real filesystem state if the tool does not resolve the path and check
it against an allowed root.

The tool's `args_schema` does not close this. A Pydantic field typed `str` or
`Path` validates fine while still carrying a traversal payload, because the
schema constrains the argument's type and not the region of the filesystem it
points at.

Reach is wider than the agent that owns the tool. A crew shares one process.
In a crew that runs its tasks in sequence, each task's output is threaded
forward as context, so a file read through this tool can land in the
transcript the downstream tasks reason over. With
[CREW-104](agent_safety.md) delegation, an agent that was never granted the
tool can still reach it by asking a peer.

---

## Rule-by-rule defense

### CREW-009 — CrewAI tool uses a path parameter in I/O without validation (Severity: high, Confidence: 0.7, Fix type: code)

**What we detect:**  
A CrewAI tool that passes a path parameter that has not been normalized to
`open`, `Path`, or a callee starting with `shutil.` or `os.`, matched by the
predicate `call_uses_unnormalized_path_param`. The check is per parameter.
The pack states why: a body-wide check would suppress the finding whenever
any normalization appears, masking real exposure on the other parameter.

**Why it is flaggable:**  
The mechanism is the one stated
[above](#why-path-containment-is-a-distinct-concern-in-crewai-tools): the
unresolved path goes into a file or directory operation, so the model
chooses where in the filesystem the tool acts, and the `args_schema` type
does not constrain that choice.

**Real-world consequence:**  
A `read_report(path: str)` tool calls `open(path)`. The model supplies
`../../etc/passwd`. The field is typed `str`, so the `args_schema` accepts
it, and the tool opens a file outside the directory it was meant to serve.
The contents come back to the agent and can be passed forward in its task
output. A peer that delegates to this agent can trigger the same read.

**Why severity is high:**  
The pack sets high and states no reasoning for it.

**Fix type — code:**  
The pack's fix is an edit to the tool source. Resolve the path with
`Path(...).resolve()` and assert the result sits under an allowed root before
touching it, rejecting anything that escapes. Encode the check as a validator
on the `args_schema` field so containment holds wherever the tool is shared
across the crew, rather than being re-implemented per call site.

**Confidence 0.7:**  
The pack sets 0.7 for this rule and names no false-positive or
false-negative scenarios for it. Its one comment on the match explains the
per-parameter design stated above.

---

## What this policy does not cover

- **I/O through other calls.** The match lists the callees `open` and `Path`
  and the callee prefixes `shutil.` and `os.`; the pack names no others.
- **Languages other than Python.** The rule is declared for
  `language: python` only.
- The pack states no other limits for this rule.

---

## Recommendations beyond the fix

```python
from pathlib import Path
from typing import Annotated

from crewai.tools import tool
from pydantic import AfterValidator

REPORTS_ROOT = Path("/srv/app-data/reports").resolve()


def inside_reports_root(value: Path) -> Path:
    resolved = (REPORTS_ROOT / value).resolve()
    if not resolved.is_relative_to(REPORTS_ROOT):
        raise ValueError("path must stay inside the reports directory")
    return resolved


ReportPath = Annotated[Path, AfterValidator(inside_reports_root)]


@tool("read_report")
def read_report(path: ReportPath) -> str:
    """Read a Markdown report from the reports directory and return its text. Takes a path relative to that directory, e.g. "q3/summary.md"."""
    return path.read_text(encoding="utf-8")
```

1. Resolve the path with `Path(...).resolve()` and check that the result sits
   under an allowed root before touching it, rejecting anything that escapes.
2. Put that check in a validator on the `args_schema` field, as the pack's fix
   says. CrewAI builds the argument schema from the parameter type hints, so
   the `AfterValidator` in the `Annotated` type above is that validator. A
   path that escapes the root is rejected during argument validation and the
   function body does not run; a path inside the root reaches the body already
   resolved.
3. Keep file-reading tools off agents that can be reached through
   delegation, as [CREW-104](agent_safety.md)'s fix advises.
