---
policy_id: mcp_shell_safety
category: mcp
topic: shell_safety
rules:
  - id: MCP-010
    severity: high
    confidence: 0.7
    scope: tool
    fix_type: code
  - id: MCP-012
    severity: high
    confidence: 0.7
    scope: tool
    fix_type: code
references: [LLM06, LLM05]
---

# Policy Rationale: MCP Shell Invocation Safety

**Policy ID:** `mcp_shell_safety`  
**File:** `mcp/shell_safety.yaml`  
**Rules:** MCP-010, MCP-012  
**References:** LLM06 (Excessive Agency), LLM05 (Improper Output Handling)

> Shares the process-spawn threat model with
> [openai_sdk/shell_safety.md](../openai_sdk/shell_safety.md). MCP-specific angle
> only.

---

## What this policy covers

An MCP tool handler that spawns an OS process — Python `subprocess.*` /
`os.system` / `os.popen` / `os.spawn*` (MCP-010) or a TypeScript child-process
API `exec`/`execSync`/`execFile`/`spawn`/`fork`, bare or `child_process.*`
(MCP-012). Both read the structured `has_shell_call` predicate (Python walks the
AST; TypeScript reads the `shells_out` fact stamped by `tsHandlerFacts`), so a
match in a comment or string literal does not fire.

## Why process spawn in an MCP handler is excessive agency

Process spawn from a model-callable MCP tool puts the server host's shell on the
model's surface with no runtime sandbox. Because a connecting model chooses the
arguments passed to the tool, a prompt-injected conversation can steer those
values into a command (LLM06); the subprocess inherits the server host's
filesystem, environment, and network credentials, and its output returns across
the trust boundary (LLM05).

---

## Rule-by-rule defense

### MCP-010 — Tool body spawns a subprocess (Severity: high, Confidence: 0.7, Fix type: code)

**What we detect:** a Python handler calling `subprocess.*`, `os.system`,
`os.popen`, or `os.spawn*`.

**Why high / 0.7:** the fix usually means removing process spawn or rearchitecting
behind a typed API; partial mitigations narrow injection classes but not the
excessive-agency core. Confidence 0.7 because some handlers legitimately wrap a
single fixed command, and the `subprocess.` prefix also catches the non-spawning
`subprocess.list2cmdline` helper.

### MCP-012 — TypeScript MCP tool spawns a subprocess (Severity: high, Confidence: 0.7, Fix type: code)

**What we detect:** a TypeScript handler invoking a `child_process` API (bare from
a destructured `const { execSync } = ...` or via `child_process.*`).

**Why high / 0.7:** identical mechanism on the TypeScript SDK. The residual gaps
are a spawn reached through a renamed alias whose callee text matches no
recognized name, a helper in another module, or non-`child_process` spawners
(`Bun.spawn`, `Deno.Command`).

---

## What this policy does not cover

Whether a given literal command is actually safe; spawns hidden behind a
cross-module helper or a renamed alias; async spawners
(`asyncio.create_subprocess_*`) and non-`child_process` TypeScript spawners; and
the HTTP-exfiltration path, which SSRF ([ssrf.md](ssrf.md)) covers.

---

## Recommendations beyond the fix

The safe pattern — typed library API first, and if a spawn is genuinely
unavoidable then an argv list with `shell=False`, a timeout, and a stripped
environment — is in
[openai_sdk/shell_safety.md](../openai_sdk/shell_safety.md#recommendations-beyond-the-fix)
and applies unchanged to MCP-010. MCP-012 is the TypeScript half, where the
distinction lives in which child-process function you reach for:

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { z } from "zod";

const run = promisify(execFile);
const server = new McpServer({ name: "vcs", version: "1.0.0" });

server.tool(
  "git_log",
  {
    // The schema is the allow-list, and it is published to the client.
    revision: z.string().regex(/^[0-9a-f]{7,40}$/),
    limit: z.number().int().min(1).max(100),
  },
  async ({ revision, limit }) => {
    // execFile, not exec: an argv array, so there is no shell to inject into.
    const { stdout } = await run(
      "git",
      ["log", "-n", String(limit), "--format=%H %s", revision],
      {
        cwd: "/srv/repo",
        timeout: 10_000,
        maxBuffer: 1_000_000,
        env: { PATH: "/usr/bin:/bin", HOME: "/srv/repo" },  // NOT process.env
      },
    );
    return { content: [{ type: "text", text: stdout }] };
  },
);
```

MCP-specific additions:

1. **Expect the rule to keep firing.** MCP-010 and MCP-012 match the spawn
   itself, not the quality of its arguments, and that is deliberate: an argv
   array closes command injection but leaves the tool a
   run-a-program-on-the-server primitive. Only removing the spawn clears the
   finding. Suppress it against a specific reviewed handler if you must, but do
   not read a passing scan as "the shell is now safe".
2. Pass `env` explicitly instead of inheriting. This matters more on an MCP
   server than anywhere else the rule fires: the server process holds the
   credentials for *every* upstream its other tools talk to, and a spawned
   child inherits all of them by default. One shell-capable tool becomes a
   credential dump for the whole server.
3. Reach for `execFile`/`spawn` with an argv array, never `exec`/`execSync`,
   which take a command string and hand it to `/bin/sh`. This is the single
   highest-value TypeScript-side change, and the two names are close enough to
   be picked by autocomplete.
4. Put the constraint in the input schema. A `z.string().regex(...)` on a
   revision is reviewable, is published to the connecting client, and rejects
   the bad value before any process starts — where a check inside the handler
   body is invisible to everyone reading the tool's contract.
5. Bound both time and output: `timeout` so a wedged child does not hold the
   session worker the way a missing network timeout would
   ([network.md](network.md)), and `maxBuffer` so a chatty command cannot
   exhaust server memory through a tool that looked read-only.
6. Pin `cwd`. A relative path in a spawned command resolves against whatever
   directory the server happened to start in, which is a property of the
   deployment rather than of the tool.
