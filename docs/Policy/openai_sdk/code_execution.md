---
policy_id: openai_sdk_code_execution
category: openai_sdk
topic: code_execution
rules:
  - id: OAI-013
    severity: high
    confidence: 0.9
    scope: tool
    fix_type: code
  - id: OAI-017
    severity: high
    confidence: 0.9
    scope: tool
    fix_type: code
references: [LLM05, LLM06]
---

# Policy Rationale: Code Execution

**Policy ID:** `openai_sdk_code_execution`  
**File:** `openai_sdk/code_execution.yaml`  
**Rules:** OAI-013, OAI-017  
**Severities:** high, high  
**Fix types:** code, code  
**References:** LLM05, LLM06

---

## What this policy covers

This policy targets OpenAI Agents SDK `@function_tool` bodies that invoke Python's dynamic-code primitives: `eval(...)`, `exec(...)`, and `compile(...)`. The detection is the structured `has_code_exec_call` predicate: it walks the function's AST and fires on any call whose callee is the bare builtin `eval`, `exec`, or `compile`. Because it matches the callee symbol rather than a substring, an attribute call such as `re.compile(...)` does not fire.

---

## Why dynamic code execution is a distinct concern in agent tools

Subprocess gives the model the OS shell. `exec`/`eval` gives the model the agent's *Python runtime itself* — same memory, same imports, same in-process credentials, same module-level singletons. There is no process boundary, no PID to kill, no `os.kill` from outside that helps if the model writes a `while True` loop. The agent host has to die.

The standard "I'll restrict globals" pattern is well-known to be insufficient. `exec(code, {"__builtins__": {}})` looks safe but the `()` operator on any reachable type quickly reconstructs `__builtins__` via `().__class__.__base__.__subclasses__()` chains. Even careful sandboxes leak through `__import__` substitutes, frame walking, or `gc.get_objects()`. The CPython runtime was not designed as a sandbox, and decades of CTF writeups establish that in-process Python sandboxes are best-effort at most.

The threat model in an agentic context is worse than in a Jupyter notebook. A notebook user typically wrote the code they paste; an agent tool typically receives code authored by the model — which itself may have been steered by an untrusted upstream prompt or document. The chain "untrusted document → prompt injection → model emits `tool_code` → tool runs `exec(tool_code)`" is a single hop from a malicious blog post to arbitrary code in the agent's process. We see exactly this pattern in the wild: a tool synthesis system whose `create_evolved_tool_version` receives `evolved_code: str` from the model and calls `exec(evolved_code, env)` in the next block.

The blast radius extends past one tool call because the agent process holds state across turns. A model that gains code execution in turn 1 can rewrite tool registries, swap out function pointers, or stash a long-lived callback that exfiltrates later prompts. There is no per-turn reset unless the host explicitly fork()s a fresh worker — and most agent runtimes do not.

---

## Rule-by-rule defense

### OAI-013 — Tool body calls eval/exec/compile on dynamic input (Severity: high, Confidence: 0.9, Fix type: code)

**What we detect:**
A `@function_tool`-decorated function whose body calls the bare builtin `eval`, `exec`, or `compile` (predicate `has_code_exec_call`, an AST call-node walk on the callee symbol). The match is unconditional on the argument — we do not attempt to determine whether the input string is model-supplied, since in an agent tool the conservative assumption is that any string parameter eventually is. Attribute calls that merely share a name, such as `re.compile`, are not matched.

**Why it is flaggable:**
Dynamic-code primitives inside a tool body are a near-universal foot-gun. Even when the immediate argument is a constant, the presence of `exec`/`eval` in the surface signals a design choice to interpret strings as code — a pattern the model can usually exploit later via a related parameter, a config file the model writes, or a follow-up turn.

**Real-world consequence:**
- `create_evolved_tool_version(..., evolved_code: str, ...)` at https://github.com/AI45Lab/MAGIC/blob/main/eval/OpenRT/MAGIC/eval/OpenRT/OpenRT/attacks/blackbox/implementations/evosynth/data_structures/ai_tool_system.py#L463 accepts model-generated Python source and calls `exec(evolved_code, env)` a few lines later. The `env` dict initializes `__builtins__` from the real module's builtins, which is *not* a restricted dict — the executed code has full Python power.
- The same file at https://github.com/AI45Lab/MAGIC/blob/main/eval/OpenRT/OpenRT/attacks/blackbox/implementations/evosynth/data_structures/ai_tool_system.py#L540 shows the exec call site. A model that wants to dump the agent's env, open outbound sockets, or modify other registered tools can do so by returning the right `evolved_code` string.

**Why severity is high and not medium:**
The rule sits one tier below "critical" only because the engine's severity scale tops out at `high`. The failure mode is in-process arbitrary code execution with no partial mitigation: there is no "small" version of this bug. Medium is reserved for issues that degrade output or impose recoverable risk; this one ends the process boundary entirely.

**Fix type — code:**
Removing `eval`/`exec`/`compile` requires editing the tool source. No hook, sandbox kwarg, or guardrail prevents an in-process call from executing once dispatched.

**Confidence 0.9:**
False positives: the common lookalike `re.compile(...)` does **not** fire, because the predicate matches the bare builtin callee `compile`, not any callee whose text contains `compile`. (This *was* a false positive under the earlier substring-based detection; moving to `has_code_exec_call` eliminated it.) A tool that genuinely calls the `eval`/`exec`/`compile` builtins fires regardless of whether the argument is a constant — intentional, per the conservative model-reachability assumption above. False negatives: indirect execution through `__import__("builtins").exec(...)`, `getattr(builtins, "ex" + "ec")(s)`, or `types.FunctionType(compile(...), ...)` uses callees the predicate does not resolve. The 0.9 number reflects that on the patterns the rule does detect, the security verdict is rarely wrong.

---

### OAI-017 — TypeScript tool body calls eval / new Function on dynamic input (Severity: high, Confidence: 0.9, Fix type: code)

**What we detect:** a TypeScript tool body that calls `eval(`, `new Function(`, or
`Function(` (`has_body_text`).

**Why it is flaggable:** when any part of the evaluated string flows from the
model, this is arbitrary code execution inside the Node / Worker / browser runtime
— file I/O, env vars, fetch credentials, and the agent's keys in memory are all
reachable, and `with({})`-style sandboxes are escapable via `globalThis` and
prototype chains.

**Real-world consequence:** a TS `calculate` tool that feeds a tool argument into
`eval` as a math evaluator is the canonical RCE shape.

**Why severity is high and not medium:** no in-band sandbox; the only reliable fix
is removing dynamic evaluation.

**Fix type — code:** remove `eval` / `new Function`; parse arithmetic with a real
expression parser, or run untrusted code in an isolate with no ambient
capabilities.

**Confidence 0.9:** `has_body_text` for `eval(` / `Function(` is high-precision for
this class, though it can fire on a comment.

**Provisional (TypeScript):** load-validated today; will not fire until the
engine's TypeScript tool parser ships.

---

## What this policy does not cover

- Indirect code execution: `getattr(builtins, "ex" + "ec")(s)` and similar string-construction tricks.
- Plugin loaders that import a module by name (`importlib.import_module(model_supplied_name)`) — equally dangerous but uses different primitives.
- `pickle.loads(...)` on model-supplied bytes — a separate deserialization concern.
- Whether the code being exec'd is *actually* model-supplied. The rule fires even on a constant exec; review judges intent.
- Sandboxed `exec` (e.g. RestrictedPython, asteval). These reduce risk but the rule does not detect them; that is intentional — sandboxed in-process exec is still a strong-warning pattern.
- AST-allow-listed evaluation. The safe pattern in *Recommendations* below still calls the `compile` and `eval` builtins, so it **fires the rule** — the rule flags the primitive, and a reviewer confirms the AST gate makes the specific use safe. This is an accepted fire-on-safe-code case, not a bug.

---

## Recommendations beyond the fix

```python
from agents import function_tool
import ast

@function_tool
def evaluate_arithmetic(expression: str) -> dict:
    """Evaluate a Python arithmetic expression. Only numeric literals and the
    operators + - * / // % ** are supported. Returns {result: number} or
    {error: str, retryable: False}."""
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as e:
        return {"error": f"syntax: {e}", "retryable": False}

    allowed_nodes = (
        ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant,
        ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow,
        ast.USub, ast.UAdd,
    )
    for node in ast.walk(tree):
        if not isinstance(node, allowed_nodes):
            return {"error": f"disallowed node: {type(node).__name__}", "retryable": False}
        if isinstance(node, ast.Constant) and not isinstance(node.value, (int, float)):
            return {"error": "only numeric constants allowed", "retryable": False}

    return {"result": eval(compile(tree, "<expr>", "eval"))}
```

1. If the tool genuinely needs to evaluate user expressions, walk the AST against an allow-list of node types before calling `compile`/`eval`. Never call `eval` on a string that has not been AST-validated.
2. For "run model-generated code" use cases (notebook agents, code-interpreter style), spawn a separate process with `subprocess.Popen([...])`, drop network, read-only `/`, write-only `/workspace` via bind mount, and a hard CPU and wall-clock cap. Treat the worker as single-use.
3. Never re-use the agent's `globals()` or live module objects as the `globals` argument to `exec`. The chain to `__builtins__` is one attribute away.
4. Log every dynamic evaluation with the input source and the session ID. An attacker who finds the exec primitive will try variants; logs are how you discover them.
