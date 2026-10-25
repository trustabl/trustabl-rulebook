---
policy_id: autogen_path_safety
category: autogen
topic: path_safety
rules:
  - id: AG2-014
    severity: high
    confidence: 0.7
    scope: tool
    fix_type: code
references: []
---

# Policy Rationale: AutoGen Filesystem Path Safety

**Policy ID:** `autogen_path_safety`  
**File:** `autogen/path_safety.yaml`  
**Rules:** AG2-014  
**Severities:** high  
**Fix types:** code  
**References:** none

---

## What this policy covers

Python AutoGen / AG2 tools (`applies_to: autogen_tool`, `language: python`,
`scope: tool`) that take a path-like parameter and hand it to a file or
directory operation without resolving it or checking it against an allowed
root. The match is a single predicate, `call_uses_unnormalized_path_param`,
with the callees `open` and `Path` and the callee prefixes `shutil.` and
`os.`. The pack states that the predicate is per parameter: a tool with two
path parameters and one `.resolve()` fires on the unresolved one.

---

## Why path containment is a distinct concern in AutoGen tools

The path comes from the model. A traversal payload such as `../../etc/passwd`
reaches real filesystem state if the tool does not resolve the path and check
it against an allowed root.

AutoGen's schema generation does not close this. A parameter annotated `str`
or `Path` passes AutoGen's schema generation while still carrying a traversal
payload, because the annotation constrains the argument's type and not the
region of the filesystem it points at.

The code executor's sandbox does not close it either. This is the containment
[AG2-001](agent_safety.md) is about: a conversation may run its generated code
inside a Docker executor, but a tool registered with `register_for_execution`
runs in the host process, with the host's filesystem view, whatever the code
executor is configured to do. Whatever the tool reads is then posted into the
message history both agents keep reasoning over.

---

## Rule-by-rule defense

### AG2-014 — AutoGen tool uses a path parameter in I/O without validation (Severity: high, Confidence: 0.7, Fix type: code)

**What we detect:**  
A registered AutoGen tool that passes a path parameter that has not been
normalized to `open`, `Path`, or a callee starting with `shutil.` or `os.`,
matched by the predicate `call_uses_unnormalized_path_param`. The check is per
parameter. The pack states why: a body-wide check would suppress the finding
whenever any normalization appears, masking real exposure on the other
parameter.

**Why it is flaggable:**  
The mechanism is the one stated
[above](#why-path-containment-is-a-distinct-concern-in-autogen-tools): the
unresolved path goes into a file or directory operation in the host process,
so the model chooses where on the host's filesystem the tool acts, and neither
the type annotation nor the code executor's sandbox constrains that choice.

**Real-world consequence:**  
A `read_report(path: str)` tool registered with `register_for_execution`
calls `open(path)`. The model supplies `../../etc/passwd`. The annotation is
`str`, so the schema does not reject it. The tool opens a file outside the
directory it was meant to serve, in the host process, even when the
conversation's generated code runs in a Docker executor, and the file's
contents are posted into the message history.

**Why severity is high:**  
The pack sets high and states no reasoning for it.

**Fix type — code:**  
The pack's fix is an edit to the tool source. Resolve the path with
`Path(...).resolve()` and assert the result sits under an allowed root before
touching it, rejecting anything that escapes. Keep that check inside the
registered function itself: it is the only boundary the tool path crosses,
since the code executor's sandbox does not apply here.

**Confidence 0.7:**  
The pack sets 0.7 for this rule and names no false-positive or false-negative
scenarios for it. Its one comment on the match explains the per-parameter
design stated above.

---

## What this policy does not cover

- **I/O through other calls.** The match lists the callees `open` and `Path`
  and the callee prefixes `shutil.` and `os.`; the pack names no others.
- **Languages other than Python.** The rule is declared for `language: python`
  only.
- The pack states no other limits for this rule.

---

## Recommendations beyond the fix

```python
from pathlib import Path

from autogen import register_function

REPORTS_ROOT = Path("/srv/app-data/reports").resolve()


def read_report(path: str) -> str:
    """Read a Markdown report, given its path relative to the reports directory (e.g. "q3/summary.md"), and return its text."""
    resolved = (REPORTS_ROOT / path).resolve()
    if not resolved.is_relative_to(REPORTS_ROOT):
        # Reject the escape with a result the assistant can act on (see AG2-013).
        return "Error: path_outside_root. Pass a path inside the reports directory."
    return resolved.read_text(encoding="utf-8")


register_function(
    read_report, caller=assistant, executor=executor,
    description="Read a Markdown report from the reports directory and return its text.",
)
```

1. Resolve the path with `Path(...).resolve()` and check that the result sits
   under an allowed root before touching it, rejecting anything that escapes.
2. Keep that check inside the registered function itself. The tool runs in
   the host process, so the code executor's sandbox does not apply to it.
3. Reject an escaping path with a result the assistant can act on rather than
   a `raise` with no `try`/`except`, which is what
   [AG2-013](error_handling.md) matches.
