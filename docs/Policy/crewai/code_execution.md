---
policy_id: crewai_code_execution
category: crewai
topic: code_execution
rules:
  - id: CREW-003
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: CREW-103
    severity: high
    confidence: 0.85
    scope: agent
    fix_type: config
references: [LLM05]
---

# Policy Rationale: CrewAI Code-Execution Safety

**Policy ID:** `crewai_code_execution`  
**File:** `crewai/code_execution.yaml`  
**Rules:** CREW-003, CREW-103  
**Severities:** high, high  
**Fix types:** code, config  
**References:** LLM05 (Improper Output Handling)

---

## What this policy covers

Two routes to model-selected code execution in CrewAI. **CREW-103** (agent
scope) fires when an `Agent`'s resolved tool set includes `CodeInterpreterTool`,
CrewAI's built-in that runs model-generated Python (predicate
`agent_uses_hosted_tool_class`). **CREW-003** (tool scope) fires when a
`@tool`-decorated CrewAI function's body calls `eval`, `exec`, or `compile`
(predicate `has_code_exec_call`, a bare-builtin AST match — `re.compile` and
other attribute calls do not fire). The two cover the same arbitrary-execution
capability reached two ways: by wiring the built-in, or by hand-rolling it
inside a tool body.

---

## Why dynamic code execution is a distinct concern in CrewAI tools

In a conventional program, `eval`/`exec` runs a string the developer wrote. In
a model-callable tool, the model writes or steers the string. With any
model-influenced input, dynamic evaluation is arbitrary code execution inside
the agent process — no OS sandbox stands between the call and the runtime's
imports, file handles, and in-memory credentials. The blast radius is the whole
process: a single evaluated string can reach `os.environ` for API keys, read or
write any file the process can touch, or spawn a subprocess.

The CrewAI-specific sharpening is that this is the same capability behind
CrewAI's own published advisories. `CodeInterpreterTool` is the built-in form;
the CERT remediation for CVE-2026-2275 (SandboxPython `ctypes` escape) and
CVE-2026-2287 (Docker-availability fallback to host execution) is literally to
remove or disable the Code Interpreter Tool. Hand-rolling `eval`/`exec` inside a
`@tool` body (CREW-003) carries the identical risk while bypassing whatever
sandboxing the built-in would have applied — it is the built-in's danger with
none of its mitigations, hidden inside an ordinary-looking tool.

---

## Rule-by-rule defense

### CREW-003 — Tool body evaluates dynamic code (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:** a CrewAI `@tool`-decorated function whose body calls the
bare `eval`, `exec`, or `compile` builtin (predicate `has_code_exec_call`, an
AST callee match, not a substring scan).

**Why it is flaggable:** dynamic evaluation in a model-callable tool is an
arbitrary-code-execution surface whenever any part of the evaluated string
originates with the model. The presence of the primitive is the signal.

**Real-world consequence:** a `calculate(expr)` tool implemented as
`return eval(expr)` is driven by an injected instruction into
`__import__('os').environ` to read secrets, or into reading/writing files the
process can touch.

**Why severity is high and not critical:** no in-band sandbox stands between the
call and the full runtime, so the only reliable fix is removing dynamic
evaluation; it is not raised to critical because the engine reserves that tier
and because the exposure depends on whether the evaluated string is actually
model-influenced. **Fix type — code:** removing `eval`/`exec`/`compile` is an
edit to the tool's own source. **Confidence 0.85:** the bare-callee match avoids
the `re.compile` false positive, but a dynamic-eval helper in another module, or
evaluation via `types.FunctionType` / `marshal` / `pickle.loads`, escapes the
body-only walk.

### CREW-103 — Agent wires the code-interpreter built-in tool (Severity: high, Confidence: 0.85, Fix type: config)

**What we detect:** an `Agent` whose resolved tool set includes
`CodeInterpreterTool` (predicate `agent_uses_hosted_tool_class`).

**Why it is flaggable:** `CodeInterpreterTool` executes model-generated Python.
Once it is in the tool set, a prompt injection or a confused model can run
attacker-chosen code in the agent process — the same capability
`allow_code_execution=True` auto-injects (CREW-101), reached here by wiring the
tool by hand. It is the documented vector behind CVE-2026-2275 and
CVE-2026-2287.

**Real-world consequence:** an agent's `tools=[search, CodeInterpreterTool()]`
gives a prompt-injected model a direct interpreter; the injection runs arbitrary
Python with the agent's privileges, escaping the sandbox via the ctypes path of
CVE-2026-2275 when the SandboxPython interpreter is in use.

**Why severity is high and not critical:** identical calibration to CREW-101 —
execution passes through CrewAI's sandbox by default, so a successful attack
needs a sandbox escape or the Docker-unavailable host fallback rather than
landing on the host unconditionally. **Fix type — config:** the fix is removing
the tool from the agent's `tools=[...]`, an agent-wiring change, not a tool
source edit. **Confidence 0.85:** the class-name match cannot see whether a team
has wrapped the interpreter in an out-of-band sandbox, so a few legitimately
hardened uses are over-flagged.

---

## What this policy does not cover

- `allow_code_execution=True` and `code_execution_mode="unsafe"` — the
  constructor-flag routes to the same interpreter are caught by **CREW-101 /
  CREW-102** (agent_safety.md), not here.
- For CREW-003: dynamic evaluation reached through a helper in another module
  (the walk sees only the tool body), and alternative dynamic-code primitives
  (`types.FunctionType`, `marshal.loads`, `pickle.loads`, `importlib`-driven
  loading). Evaluations whose argument is provably a constant literal still fire
  — the predicate flags the presence of the primitive, not proof of
  model-control.
- For CREW-103: a custom subclass of `CodeInterpreterTool` under a different
  class name, or a third-party interpreter tool, is not in the matched class
  set. Whether the interpreter is sandboxed out of band is not visible to the
  class-name match.

---

## Recommendations beyond the fix

```python
from crewai.tools import tool
import ast

# Replace `eval(expr)` with a constrained evaluator that runs no code.
@tool("calculate")
def calculate(expr: str) -> str:
    """Evaluate a constant arithmetic expression and return the result.
    Rejects anything that is not a literal/operator tree."""
    try:
        node = ast.parse(expr, mode="eval")
    except SyntaxError:
        return "error: not a valid expression"
    allowed = (ast.Expression, ast.BinOp, ast.UnaryOp, ast.Num,
               ast.Constant, ast.operator, ast.unaryop)
    if not all(isinstance(n, allowed) for n in ast.walk(node)):
        return "error: expression contains disallowed syntax"
    return str(eval(compile(node, "<expr>", "eval")))  # safe: literals only
```

1. Remove `CodeInterpreterTool` from production agents. If code execution is a
   genuine requirement, run it **outside CrewAI** in a hardened external sandbox
   (no filesystem, no network, no credentials, hard timeout) and gate it behind
   explicit human approval.
2. For data math, prefer `ast.literal_eval` (data only, no calls) over any
   evaluator; reserve a constrained AST walk for the rare arithmetic case.
3. Keep application secrets out of the process that hosts any
   evaluation-capable tool — assume an evaluated string can read the whole
   environment.
4. Log every interpreter invocation with the session ID and the model that
   requested it, so an incident can be reconstructed.
