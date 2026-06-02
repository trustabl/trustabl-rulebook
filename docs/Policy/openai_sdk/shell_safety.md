---
policy_id: openai_sdk_shell_safety
category: openai_sdk
topic: shell_safety
rules:
  - id: OAI-012
    severity: high
    confidence: 0.9
    scope: tool
    fix_type: code
references: [LLM06, LLM05]
---

# Policy Rationale: Shell Safety

**Policy ID:** `openai_sdk_shell_safety`  
**File:** `openai_sdk/shell_safety.yaml`  
**Rules:** OAI-012  
**Severities:** high  
**Fix types:** code  
**References:** LLM06, LLM05

---

## What this policy covers

This policy targets OpenAI Agents SDK `@function_tool` bodies that spawn OS processes. The detection is the structured `has_shell_call` predicate: it walks the function's AST and fires on any call whose resolved callee is `os.system`, `os.popen`, a `subprocess.*` member (`subprocess.run`, `.Popen`, `.call`, `.check_output`, `.check_call`, …), or an `os.spawn*` member. Because it matches the resolved callee rather than raw text, a `subprocess.run(` mentioned in a comment or docstring does not fire.

---

## Why shell execution is a distinct concern in agent tools

In a conventional application, a subprocess call has a fixed callsite — the developer wrote the command string, and the only variability is parameter substitution they explicitly approved. In an agent tool the model writes (or selects) the command. Even when the tool author intends "the model only supplies an argument," the SDK has no enforcement: the model can return strings that bend the surrounding command structure, and the tool will faithfully run whatever it builds.

The blast radius is the entire process. The subprocess inherits the agent's working directory, environment variables (including API keys), filesystem credentials, and outbound network access. If the agent runs as a service account with database creds in env, a model-driven `subprocess.run("env", shell=True)` exfiltrates them in one call. If the agent has write access to `~/.ssh`, a single `subprocess.run("cat ~/.ssh/id_rsa", shell=True)` leaks the private key into the model context — and from there into provider logs, training data, or the next conversation turn.

Manual deny-list filtering (regex against `rm -rf`, `wget`, etc.) is not a defense. The space of dangerous commands is unbounded, encodings (base64, hex, unicode tricks) bypass naïve regex, and any new binary on the PATH introduces a new attack class. The shipped real-world tool we cite at https://github.com/taco-devs/termo-agent/blob/main/termo_agent/adapters/platform_adapter.py#L289 demonstrates the pattern: dozens of lines of deny-pattern regex preceding `subprocess.run(command, shell=True, ...)`. That hardening is admirable, but it is a perimeter that an adversarial model will eventually walk around.

This is why OWASP LLM Top 10:2025 places "Excessive Agency" (LLM06) at the center of agent security: the moment an agent can spawn a process, it can effectively do anything its user account can do. The right answer is almost always to remove process spawn from the tool surface, not to filter it.

---

## Rule-by-rule defense

### OAI-012 — Tool body spawns a subprocess (Severity: high, Confidence: 0.9, Fix type: code)

**What we detect:**
A `@function_tool`-decorated function whose body calls `os.system`, `os.popen`, any `subprocess.*` function (e.g. `subprocess.run`, `subprocess.Popen`, `subprocess.call`, `subprocess.check_output`, `subprocess.check_call`), or any `os.spawn*` function. The match is an AST call-node walk (predicate `has_shell_call`) that resolves the callee — not a substring scan — so a string literal or comment containing `subprocess.run(` does not trigger it.

**Why it is flaggable:**
Process spawn from inside an agent-callable tool puts the OS shell on the model's tool surface. Every safeguard (sandbox, deny-list, working-directory pin) is bolted on top of an inherently broad primitive; the rule fires unconditionally because the *presence* of process spawn is the signal.

**Real-world consequence:**
- `execute_command(command: str)` at https://github.com/taco-devs/termo-agent/blob/main/termo_agent/adapters/platform_adapter.py#L289 takes a model-supplied shell string and runs it via `subprocess.run(command, shell=True, ...)`. The tool wraps the call in deny-pattern regex, but `shell=True` combined with a free-form `command: str` parameter is the maximal-agency form of process spawn.
- `run_app(name, command, port)` at https://github.com/taco-devs/termo-agent/blob/main/termo_agent/adapters/platform_adapter.py#L938 forwards the model-supplied `command` into a `sprite-env services create ... --args '-c,{escaped}'` call via `subprocess.run(cmd, shell=True, ...)`. Even with the single-quote escaping, model-supplied content reaches a shell.

**Why severity is high and not medium:**
The fix usually requires removing process spawn from the tool altogether or wholesale rearchitecting it behind a typed API. Partial mitigations (argv lists, `shell=False`, working-directory pinning) reduce specific injection classes but do not eliminate the underlying excessive-agency problem. Severity is not bumped above `high` because the engine reserves the highest tier for unconditional remote-code-execution exposures; here the exposure depends on what the tool's caller does with the spawn.

**Fix type — code:**
Replacing `subprocess.run(...)` with a library call (or fronting it with an allow-list) is a tool-source edit. A sandbox at the agent level (seccomp, container) is complementary but is not what the rule asks for.

**Confidence 0.9:**
False positives: the predicate matches any `subprocess.*` callee by prefix, so a tool that imports `subprocess` only to call the non-spawning helper `subprocess.list2cmdline(...)` will fire even though it never spawns — a small over-match we accept because that helper rarely appears without a real spawn nearby. Whether a genuine `subprocess.run(["echo", "hi"])` is *safe* in context is a human judgment the rule does not make. The AST match removes a class of false positive that substring scanning had: a `subprocess.run(` inside a comment or docstring no longer fires. False negatives: tools that spawn via `multiprocessing.Process`, `asyncio.create_subprocess_exec`, the `os.exec*` family, or `pty.spawn` are not in the callee set, and a spawn wrapped behind a helper (`_run_safely(...)`) defined in another module escapes the body-only walk.

---

## What this policy does not cover

- `asyncio.create_subprocess_exec` / `asyncio.create_subprocess_shell` — async spawn equivalents are not in the literal list.
- `pty.spawn`, `pexpect.spawn`, `multiprocessing.Process` — alternative spawn primitives.
- `os.execvp` / `os.execlp` family — replaces the current process; rare in tools but equally dangerous.
- Spawn that is wrapped behind a helper in another module. The rule scans the tool body only.
- Whether the spawned command is safe. A literal `subprocess.run(["ls", "/tmp"], shell=False)` fires the rule even though it is comparatively benign.
- File-system writes outside the working directory, env-var exfiltration, and network exfiltration through *non-subprocess* primitives (sockets, HTTP). Those belong to other policies.

---

## Recommendations beyond the fix

```python
from agents import function_tool
import shutil
from pathlib import Path

# Replace `subprocess.run(["du", "-sh", path])` style tools with typed APIs.
@function_tool
def get_directory_size(path: str) -> dict:
    """Return the total size of files under `path` in bytes. Path must
    resolve inside the workspace allow-list."""
    workspace = Path("/home/agent/workspace").resolve()
    p = Path(path).resolve()
    if not p.is_relative_to(workspace):
        return {"error": "path escapes workspace", "retryable": False}
    total = sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
    return {"path": str(p), "bytes": total}
```

1. If the tool must shell out, build the argv list explicitly and pass `shell=False`. Never interpolate model strings into a `shell=True` command.
2. Always pass `timeout=`. A model can request an infinitely-running command.
3. Run the agent in a sandbox container with a read-only root filesystem, dropped capabilities, and a network egress allow-list. Treat the in-tool deny-list as belt-and-braces only.
4. Drop sensitive env vars from the subprocess: pass `env={...}` with only what the command needs. Default `env=None` inherits everything.
5. Log every spawned command with the session ID and the model that requested it, so any incident can be reconstructed.
