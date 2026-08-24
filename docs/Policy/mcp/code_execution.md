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
**References:** LLM05 (Improper Output Handling), LLM06 (Excessive Agency)

> Shares the dynamic-eval threat model with
> [openai_sdk/code_execution.md](../openai_sdk/code_execution.md). MCP-specific
> angle only.

---

## What this policy covers

An MCP tool handler that evaluates dynamic code — Python `eval`/`exec`/`compile`
(MCP-009, `has_code_exec_call`) or TypeScript `eval()` / `new Function(...)`
(MCP-014, the captured `code_exec` fact). Both are structured callee matches, not
substring scans.

## Why eval in an MCP handler is arbitrary code execution

When any portion of the evaluated string flows from the connecting client
(directly, or via state the model writes), the call is arbitrary code execution
inside the **MCP server process**: same memory, same imports, same in-process
credentials, no process boundary between the call and the host. A model steered
by an untrusted document or a prompt-injected task can reach the primitive and run
whatever it constructs (LLM06), and the result returns across the trust boundary
(LLM05).

---

## Rule-by-rule defense

### MCP-009 — Tool body calls eval/exec/compile on dynamic input (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:** a Python handler invoking `eval`, `exec`, or `compile`.

**Why high / 0.85:** in-process RCE is the most severe tool outcome. Confidence
0.85 (not higher) because a handler could pass only a fixed literal to `compile`,
and the structured match flags the call's presence, not proof of dynamic input.

### MCP-014 — TypeScript MCP tool evaluates dynamic code (Severity: high, Confidence: 0.9, Fix type: code)

**What we detect:** a TypeScript handler calling `eval()` or constructing
`new Function(...)`.

**Why high / 0.9:** same in-process RCE mechanism on the TypeScript SDK; slightly
higher confidence than MCP-009 because `eval` / `new Function` in TS handlers are
almost never legitimate, where Python `compile` has a few benign uses.

---

## What this policy does not cover

Whether the evaluated string is genuinely caller-influenced; indirect execution
via `getattr`/`importlib`/`vm` module/`require` of attacker-named modules; and
sandboxed evaluators that are still flagged because the rule keys on the call, not
its safety.

---

## Recommendations beyond the fix

The fix is not to sanitize the input to `eval` — it is to stop having an `eval`.
Almost every handler that reaches for one wants a small, closed grammar, and
that can be walked directly:

```python
import ast
import operator

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("calc")

# Deliberately no ast.Pow: 9**9**9 is a one-token denial of service that needs
# no code execution at all.
_OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub,
    ast.Mult: operator.mul, ast.Div: operator.truediv,
    ast.Mod: operator.mod, ast.USub: operator.neg,
}


def _reduce(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_reduce(node.left), _reduce(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_reduce(node.operand))
    raise ValueError("unsupported expression")


@mcp.tool()
def calculate(expression: str) -> dict:
    """Evaluate an arithmetic expression over numeric literals (+ - * / %)."""
    try:
        return {"result": _reduce(ast.parse(expression, mode="eval").body)}
    except (SyntaxError, ValueError, ZeroDivisionError, OverflowError) as exc:
        return {"error": str(exc), "code": "bad_expression", "retryable": False}
```

`__import__("os").system("id")` and `open("/etc/passwd").read()` both parse
fine and are then rejected by the walk, because the walk enumerates what is
allowed rather than guessing at what is dangerous.

The dynamic-eval rationale is in
[openai_sdk/code_execution.md](../openai_sdk/code_execution.md#recommendations-beyond-the-fix).
MCP-specific additions:

1. Enumerate the allowed node types; never blocklist the dangerous ones. Every
   published `eval` sandbox that filtered on names — `__import__`, `__class__`,
   dunder attributes — was escaped through a name its author had not thought
   of. An allow-list fails closed against the payload nobody predicted.
2. Size the blast radius by the *server*, not the tool. An in-process `eval` in
   an SDK tool compromises that agent's process; an MCP server is shared
   infrastructure, so the same call reaches the credentials, in-memory state,
   and upstream connections belonging to every other tool on that server and
   every client currently connected to it.
3. If you genuinely need to run caller-supplied code, make it a service rather
   than a handler: a separate process or container, no network, a memory and
   CPU cap, and a wall-clock kill. A handler cannot be made safe by argument
   inspection, and MCP-009 will keep firing on it — correctly.
4. Bound the grammar for cost, not just for safety. Exponentiation, deep
   recursion, and large literal repetition burn CPU inside the server process
   without executing anything the rule would call code, and a stalled worker
   is the same outcome as an unbounded network call
   ([network.md](network.md)).
5. On the TypeScript side (MCP-014) remember `new Function` is the same
   primitive as `eval` and is often reached for as though it were milder.
   Neither the `vm` module nor `require` of a caller-named module is matched by
   this rule, and both execute in-process just as thoroughly.
