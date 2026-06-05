---
policy_id: vercel_ai_shell_safety
category: vercel_ai
topic: shell_safety
rules:
  - id: VAI-001
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: Vercel AI SDK Shell-Execution Safety

**Policy ID:** `vercel_ai_shell_safety`  
**File:** `vercel_ai/shell_safety.yaml`  
**Rules:** VAI-001  
**Severities:** high  
**Fix types:** code  
**References:** LLM06 (Excessive Agency)

---

## What this policy covers

Vercel AI SDK tools whose `execute()` body spawns an OS process. **VAI-001** fires
on the `has_shell_call` fact, which discovery sets when a tool handler calls a Node
`child_process` primitive — `exec`, `execSync`, `spawn`, `spawnSync`, `execFile`,
or `fork`. The fact is set on both the bare and `child_process.`-qualified callee
forms.

---

## Why shell execution is a distinct concern in Vercel AI tools

A Vercel AI tool is exposed to the model via the agent's `tools` record, so the
model writes or selects the command string the handler runs. Shell execution
selected by model output is the most direct path from prompt injection to remote
code execution: the spawned process inherits the agent process's working
directory, environment variables (including API keys), filesystem credentials, and
outbound network. A single injected instruction that reaches `exec`/`execSync` runs
with the agent's full privileges.

The Vercel-specific sharpening is that the `ai` core package ships *no* built-in
shell-tool primitive. Unlike frameworks with a first-class shell tool, a Vercel AI
project's only shell surface is a hand-rolled `execute()` that spawns a subprocess
— and it hides inside an ordinary-looking tool definition. That makes the
hand-rolled `child_process.exec(cmd)` the exact shape a reviewer must hunt for,
because nothing else in the SDK will surface it.

---

## Rule-by-rule defense

### VAI-001 — Tool execute() spawns a subprocess (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:** a Vercel AI tool whose `execute()` handler invokes a
`child_process` primitive (`exec`, `execSync`, `spawn`, `spawnSync`, `execFile`,
`fork`) — the `has_shell_call` fact, set on the bare and qualified callee forms.

**Why it is flaggable:** process spawn from a model-callable handler puts the OS
shell on the model's tool surface. The presence of the spawn is the signal; every
safeguard is bolted onto an inherently broad primitive.

**Real-world consequence:** a `run(cmd)` tool forwarding a model string into
`exec(cmd)` is one prompt injection from arbitrary command execution — an injected
`cmd="cat ~/.ssh/id_rsa"` leaks the private key into the model context.

**Why severity is high and not critical:** the fix usually means removing the
spawn or rearchitecting behind a typed API; it is not raised above high because
the exposure depends on what the handler does with the spawn, and the engine
reserves critical for unconditional RCE. **Fix type — code:** replacing the spawn
(or fronting it with an allow-list) is a tool-source edit. **Confidence 0.85:**
the fact is set on the recognized `child_process` callees, so a spawn hidden
behind a helper in another module escapes it, and a spawn through a less common
primitive outside the recognized set is a false negative.

---

## What this policy does not cover

- A spawn wrapped behind a helper defined in another module — discovery sees the
  tool handler, so a wrapper elsewhere escapes the fact.
- Spawn primitives outside the recognized `child_process` set, or reached through
  an aliased import (`import { exec as run } from "child_process"` used through a
  further indirection).
- Whether the spawned command is safe. A literal `execFile("ls", ["/tmp"])` fires
  even though it is comparatively benign — the fact flags the presence of the
  primitive, not proof of model-control.
- TypeScript only: a tool defined in plain `.js` may not be analyzed with the same
  fidelity as a typed `.ts` handler, so a `.js` `execute()` spawn can be a
  coverage gap.
- File-system writes and network exfiltration through non-subprocess primitives
  belong to other policies.

---

## Recommendations beyond the fix

```typescript
import { tool } from "ai";
import { z } from "zod";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);

export const gitLog = tool({
  description: "Return the last N git commits for the repo.",
  inputSchema: z.object({ count: z.number().int().min(1).max(50) }),
  execute: async ({ count }) => {
    // Fixed binary + argv array; no shell string, no model-supplied command.
    const { stdout } = await run("git", ["log", "-n", String(count), "--oneline"], {
      timeout: 10_000,
    });
    return { log: stdout };
  },
});
```

1. Replace shell-outs with a typed library call where one exists. If a subprocess
   is unavoidable, use `execFile`/`spawn` with a fixed binary and an argument
   array — never a shell string and never `exec(model_string)`.
2. Allow-list the exact commands permitted, and always pass `timeout=` — a model
   can request an infinitely-running command.
3. Run the agent in a sandbox with dropped capabilities and a network egress
   allow-list; pass a minimal `env` to the child rather than inheriting the
   process environment.
4. Keep shell logic out of any model-callable tool, and log every spawned command
   with the session ID for audit.
