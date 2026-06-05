---
policy_id: autogen_code_execution
category: autogen
topic: code_execution
rules:
  - id: AG2-010
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
references: [LLM05]
---

# Policy Rationale: AutoGen Code-Execution Safety

**Policy ID:** `autogen_code_execution`  
**File:** `autogen/code_execution.yaml`  
**Rules:** AG2-010  
**Severities:** high  
**Fix types:** code  
**References:** LLM05 (Improper Output Handling)

---

## What this policy covers

AutoGen tool functions whose body evaluates code at runtime. **AG2-010** fires
when a tool registered with an agent (via `register_function` or the
`register_for_llm` / `register_for_execution` decorators) calls the bare `eval`,
`exec`, or `compile` builtin (predicate `has_code_exec_call`, a bare-builtin AST
match — `re.compile` and other attribute calls do not fire).

---

## Why dynamic code execution is a distinct concern in AutoGen tools

A registered AutoGen tool is exposed to the model, so the model writes or steers
any string the tool evaluates. With any model-influenced input,
`eval`/`exec`/`compile` is arbitrary code execution inside the agent process —
no OS sandbox stands between the call and the runtime's imports, file handles,
and in-memory credentials. The blast radius is the whole process: one evaluated
string can read `os.environ`, touch any file the process can reach, or spawn a
subprocess.

The AutoGen-specific sharpening: this is the same arbitrary-execution risk
AutoGen's code *executor* carries, but reached inside an ordinary tool rather
than through the executor. AutoGen's documentation strongly recommends running
generated code inside Docker; a hand-rolled `eval`/`exec` in a tool body bypasses
that entirely — it runs in-process with none of the executor's container
isolation, and it hides inside a function that looks like any other tool. So the
mitigation AutoGen built (the Docker executor) is sidestepped exactly when a
developer reaches for `eval` for convenience.

---

## Rule-by-rule defense

### AG2-010 — Tool body evaluates dynamic code (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:** an AutoGen-registered tool whose body calls the bare `eval`,
`exec`, or `compile` builtin (predicate `has_code_exec_call`, an AST callee
match, not a substring scan).

**Why it is flaggable:** dynamic evaluation in a model-callable tool is an
arbitrary-code-execution surface whenever any part of the evaluated string
originates with the model. The presence of the primitive is the signal.

**Real-world consequence:** a `calc(expr)` tool implemented as `return eval(expr)`
is driven by an injected instruction into `__import__('os').environ` to read
secrets, or into reading/writing files the process can touch.

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

- AutoGen's code *executor* configuration (Docker, human review) — that is the
  agent-scope concern of **AG2-001 / AG2-002** (agent_safety.md), not a tool
  rule.
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
from autogen import register_function

def safe_calc(expr: str) -> str:
    """Evaluate a constant arithmetic expression; runs no arbitrary code."""
    node = ast.parse(expr, mode="eval")
    allowed = (ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant,
               ast.operator, ast.unaryop)
    if not all(isinstance(n, allowed) for n in ast.walk(node)):
        return "error: disallowed syntax"
    return str(eval(compile(node, "<expr>", "eval")))  # literals only

register_function(safe_calc, caller=assistant, executor=executor,
                  description="Evaluate a constant arithmetic expression.")
```

1. Remove `eval`/`exec`/`compile` from agent-callable tool bodies. For data math
   prefer `ast.literal_eval`; reserve a constrained AST walk for arithmetic.
2. If running code is genuinely the product, route it through AutoGen's Docker
   code executor or a locked-down external sandbox (no filesystem, no network,
   hard timeout) rather than in-process evaluation.
3. Keep application secrets out of the process that hosts any evaluation-capable
   tool — assume an evaluated string can read the whole environment.
4. Log every evaluation with the session ID and the model that requested it.
