---
policy_id: pydantic_ai_path_safety
category: pydantic_ai
topic: path_safety
rules:
  - id: PYD-009
    severity: high
    confidence: 0.7
    scope: tool
    fix_type: code
references: []
---

# Policy Rationale: Pydantic AI Filesystem Path Safety

**Policy ID:** `pydantic_ai_path_safety`  
**File:** `pydantic_ai/path_safety.yaml`  
**Rules:** PYD-009  
**Severities:** high  
**Fix types:** code  
**References:** none

---

## What this policy covers

Python Pydantic AI tools (`applies_to: pydantic_ai_tool`, `language: python`,
`scope: tool`) that take a path-like parameter and hand it to a file or
directory operation without resolving it or checking it against an allowed
root. The match is a single predicate, `call_uses_unnormalized_path_param`,
with the callees `open` and `Path` and the callee prefixes `shutil.` and
`os.`. The pack states that the predicate is per parameter: a tool with two
path parameters and one `.resolve()` fires on the unresolved one.

---

## Why path containment is a distinct concern in Pydantic AI tools

The path comes from the model. A traversal payload such as `../../etc/passwd`
reaches real filesystem state if the tool does not resolve the path and check
it against an allowed root. Whatever the agent process can read or write, the
model can reach through the tool.

Pydantic AI's type layer does not close this. A parameter annotated `str` or
`Path` validates fine while still carrying a traversal payload, because the
annotation constrains the value's type, not the region of the filesystem it
points at.

---

## Rule-by-rule defense

### PYD-009 — Pydantic AI tool uses a path parameter in I/O without validation (Severity: high, Confidence: 0.7, Fix type: code)

**What we detect:**  
A tool that passes a path parameter that has not been normalized to `open`,
`Path`, or a callee starting with `shutil.` or `os.`, matched by the predicate
`call_uses_unnormalized_path_param`. The check is per parameter. The pack
states why: a body-wide check would suppress the finding whenever any
normalization appears, masking real exposure on the other parameter.

**Why it is flaggable:**  
The mechanism is the one stated
[above](#why-path-containment-is-a-distinct-concern-in-pydantic-ai-tools): the
unresolved path goes straight into a file or directory operation, so the model
chooses where in the filesystem the tool acts, and the type annotation does not
constrain that choice.

**Real-world consequence:**  
A `read_report(path: str)` tool calls `open(path)`. The model supplies
`../../etc/passwd`, the value validates as a `str`, and the tool opens a file
outside the directory it was meant to serve, with the agent process's own
permissions.

**Why severity is high:**  
The pack sets high and states no reasoning for it beyond the explanation:
whatever the agent process can read or write, the model can reach through this
tool.

**Fix type — code:**  
The pack's fix is an edit to the tool source. Resolve the path with
`Path(...).resolve()` and assert the result sits under an allowed root before
touching it, rejecting anything that escapes. Encode that as a validator on
the parameter's type (a Pydantic `AfterValidator` or a custom path type) so
containment holds for every tool that accepts it rather than being
re-implemented per call site.

**Confidence 0.7:**  
The pack sets 0.7 and states the limit itself: detection is heuristic, and the
reader should confirm the parameter is genuinely model-supplied before applying
the fix. A path parameter that the model does not supply fires the same as one
it does. The pack names no other false-positive or false-negative scenarios.

---

## What this policy does not cover

- **Whether the parameter is model-supplied.** The rule flags the call, and the
  pack asks the reader to confirm the parameter is genuinely model-supplied
  before applying the fix.
- **I/O through other calls.** The match lists the callees `open` and `Path`
  and the callee prefixes `shutil.` and `os.`; the pack names no others.
- **Languages other than Python.** The rule is declared for `language: python`
  only.
- The pack states no other limits for this rule.

---

## Recommendations beyond the fix

```python
from pathlib import Path
from typing import Annotated

from pydantic import AfterValidator
from pydantic_ai import Agent

agent = Agent("openai:gpt-4o")

REPORTS_ROOT = Path("/srv/app-data/reports").resolve()


def inside_reports_root(value: Path) -> Path:
    resolved = (REPORTS_ROOT / value).resolve()
    if not resolved.is_relative_to(REPORTS_ROOT):
        raise ValueError("path must stay inside the reports directory")
    return resolved


ReportPath = Annotated[Path, AfterValidator(inside_reports_root)]


@agent.tool_plain
def read_report(path: ReportPath) -> str:
    """Read a Markdown report from the reports directory and return its text.

    Args:
        path: A path relative to the reports directory, e.g. "q3/summary.md".
    """
    return path.read_text(encoding="utf-8")
```

1. Resolve the path with `Path(...).resolve()` and check that the result sits
   under an allowed root before touching it, rejecting anything that escapes.
2. Put that check in a validator on the parameter's type (a Pydantic
   `AfterValidator` or a custom path type), so every tool that accepts the type
   gets the same containment instead of re-implementing it per call site.
