---
policy_id: pydantic_ai_code_execution
category: pydantic_ai
topic: code_execution
rules:
  - id: PYD-004
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: Pydantic AI Code-Execution Safety

**Policy ID:** `pydantic_ai_code_execution`  
**File:** `pydantic_ai/code_execution.yaml`  
**Rules:** PYD-004  
**Severities:** high  
**Fix types:** code  
**References:** LLM06 (Excessive Agency)

---

## What this policy covers

Pydantic AI tools whose body evaluates code at runtime. **PYD-004** fires when a
tool function (defined via `@agent.tool` / `@agent.tool_plain` or the `Tool(...)`
factory) calls the bare `eval`, `exec`, or `compile` builtin (predicate
`has_code_exec_call`, a bare-builtin AST match — `re.compile` and other attribute
calls do not fire).

---

## Why dynamic code execution is a distinct concern in Pydantic AI tools

A Pydantic AI tool is exposed to the model, so the model writes or steers any
string the tool evaluates. With any model-influenced input, `eval`/`exec`/`compile`
is arbitrary code execution inside the agent process — no OS sandbox stands between
the call and the runtime's imports, file handles, and in-memory credentials. The
blast radius is the whole process: one evaluated string can read `os.environ`,
touch any file the process can reach, or spawn a subprocess.

The Pydantic-AI-specific sharpening: this is the same arbitrary-execution
capability as the framework's built-in `CodeExecutionTool` (PYD-102), hand-rolled
inside a tool body — and it bypasses whatever sandboxing the native tool would have
applied. The native tool runs code in a provider-managed environment; an
in-process `eval` runs it directly in the agent's own Python, with full access to
the host application's process. So reaching for `eval` for convenience inside a
`@agent.tool` is strictly more exposed than using the native tool it imitates.

---

## Rule-by-rule defense

### PYD-004 — Tool body evaluates dynamic code (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:** a Pydantic AI tool whose body calls the bare `eval`, `exec`,
or `compile` builtin (predicate `has_code_exec_call`, an AST callee match, not a
substring scan).

**Why it is flaggable:** dynamic evaluation in a model-callable tool is an
arbitrary-code-execution surface whenever any part of the evaluated string
originates with the model. The presence of the primitive is the signal.

**Real-world consequence:** a `calculate(expr)` tool implemented as
`return eval(expr)` is driven by an injected instruction into
`__import__('os').environ` to read secrets, or into reading/writing files the
process can touch.

**Why severity is high and not critical:** no in-band sandbox stands between the
call and the full runtime, so the only reliable fix is removing dynamic
evaluation; it is not raised to critical because the engine reserves that tier and
the exposure depends on whether the evaluated string is actually model-influenced.
**Fix type — code:** removing `eval`/`exec`/`compile` is a tool-source edit.
**Confidence 0.85:** the bare-callee match avoids the `re.compile` false positive,
but a dynamic-eval helper in another module, or evaluation via
`types.FunctionType` / `marshal` / `pickle.loads`, escapes the body-only walk.

---

## What this policy does not cover

- The native `CodeExecutionTool` wired on the agent — that is the agent-scope
  concern of **PYD-102** (agent_safety.md), not a tool rule.
- Dynamic evaluation reached through a helper in another module — the walk sees
  only the tool body.
- Alternative dynamic-code primitives: `types.FunctionType`, `marshal.loads`,
  `pickle.loads`, `importlib`-driven loading.
- Evaluations whose argument is provably a constant literal still fire — the
  predicate flags the presence of the primitive, not proof of model-control.

---

## Recommendations beyond the fix

```python
import ast
from pydantic_ai import Agent, RunContext

agent = Agent("openai:gpt-4o")

@agent.tool_plain
def calculate(expr: str) -> str:
    """Evaluate a constant arithmetic expression; runs no arbitrary code."""
    node = ast.parse(expr, mode="eval")
    allowed = (ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant,
               ast.operator, ast.unaryop)
    if not all(isinstance(n, allowed) for n in ast.walk(node)):
        return "error: disallowed syntax"
    return str(eval(compile(node, "<expr>", "eval")))  # literals only
```

1. Remove `eval`/`exec`/`compile` from agent-callable tool bodies. For data math
   prefer `ast.literal_eval`; reserve a constrained AST walk for arithmetic.
2. If running code is genuinely the product, isolate it in a locked-down sandbox
   (no filesystem or network, hard timeout) — or use the native `CodeExecutionTool`
   under explicit human approval — rather than in-process evaluation.
3. Parse structured input with a typed Pydantic schema rather than evaluating it.
4. Keep application secrets out of the process that hosts any evaluation-capable
   tool, and log every evaluation with the session ID.
