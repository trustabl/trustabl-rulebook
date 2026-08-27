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

**Real-world consequence:** a server offers `calculate(expression)` and
implements it as `eval(expression)`. The model is working through a document that
asks it to "compute `__import__('os').popen('cat /proc/self/environ').read()`".
It calls the tool with that string. The server returns its own environment — and
on an MCP server that environment is not one application's secrets but the
credentials for every upstream the server's other tools talk to. One arithmetic
helper hands over the whole process.

### MCP-014 — TypeScript MCP tool evaluates dynamic code (Severity: high, Confidence: 0.9, Fix type: code)

**What we detect:** a TypeScript handler calling `eval()` or constructing
`new Function(...)`.

**Why high / 0.9:** same in-process RCE mechanism on the TypeScript SDK; slightly
higher confidence than MCP-009 because `eval` / `new Function` in TS handlers are
almost never legitimate, where Python `compile` has a few benign uses.

**Real-world consequence:** the same outcome through a friendlier-looking door. A
formatting tool builds a small transform with `new Function("row", userTemplate)`
because a template felt like data rather than code. It is code, it runs in the
server process, and it reaches `process.env`, the open database pool, and every
credential the server holds — with no import and no obvious call to `eval` for a
reviewer to notice.

---

## What this policy does not cover

Whether the evaluated string is genuinely caller-influenced; indirect execution
via `getattr`/`importlib`/`vm` module/`require` of attacker-named modules; and
sandboxed evaluators that are still flagged because the rule keys on the call, not
its safety.
