---
policy_id: pydantic_ai_shell_safety
category: pydantic_ai
topic: shell_safety
rules:
  - id: PYD-003
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
references: [LLM06]
---

# Policy Rationale: Pydantic AI Shell-Execution Safety

**Policy ID:** `pydantic_ai_shell_safety`  
**File:** `pydantic_ai/shell_safety.yaml`  
**Rules:** PYD-003  
**Severities:** high  
**Fix types:** code  
**References:** LLM06 (Excessive Agency)

---

## What this policy covers

Pydantic AI tool function bodies that spawn an OS process. **PYD-003** uses the
structured `has_shell_call` predicate: it walks the function's AST and fires on any
call whose resolved callee is `os.system`, `os.popen`, a `subprocess.*` member
(`subprocess.run`, `.Popen`, `.call`, `.check_output`, `.check_call`, …), or an
`os.spawn*` member. Because it matches the resolved callee, a `subprocess.run(` in
a comment or docstring does not fire.

---

## Why shell execution is a distinct concern in Pydantic AI tools

A Pydantic AI tool is registered with the agent and therefore model-callable, and
the model controls both whether the tool is called and the arguments it receives —
so any command string assembled from those arguments is attacker-influenced. Shell
execution selected by model output is the most direct path from prompt injection to
remote code execution: the subprocess inherits the agent process's working
directory, environment variables (including API keys), filesystem credentials, and
outbound network. A single injected instruction that reaches the shell runs with
the agent's full privileges.

Pydantic AI offers no in-band shell sandbox, so a hand-rolled
`subprocess.run(cmd, shell=True)` inside a `@agent.tool` is the framework's entire
shell surface — and it hides inside an ordinary-looking tool. The retrying agent
loop sharpens the hazard: a tool whose arguments fail validation is re-invoked, so
a model can refine an injected command across turns until the subprocess does what
the attacker wants.

---

## Rule-by-rule defense

### PYD-003 — Tool body spawns a subprocess (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:** a Pydantic AI tool whose body invokes `os.system`, `os.popen`,
a `subprocess.*` function, or an `os.spawn*` function (predicate `has_shell_call`,
an AST callee walk, not a substring scan).

**Why it is flaggable:** process spawn from a model-callable tool puts the OS shell
on the model's tool surface. The presence of the spawn is the signal; every
safeguard is bolted onto an inherently broad primitive.

**Real-world consequence:** a `run(cmd)` tool forwarding a model string into
`subprocess.run(cmd, shell=True)` is one prompt injection from arbitrary command
execution — an injected `cmd="cat ~/.ssh/id_rsa"` leaks the private key into the
model context.

**Why severity is high and not critical:** the fix usually means removing the spawn
or rearchitecting behind a typed API; it is not raised above high because the
exposure depends on what the caller does with the spawn, and the engine reserves
critical for unconditional RCE. **Fix type — code:** replacing the spawn (or
fronting it with an allow-list) is a tool-source edit. **Confidence 0.85:** the
`subprocess.*` prefix over-fires on the rare non-spawning helper
(`subprocess.list2cmdline`), and async/`pty` spawn primitives escape the body walk.

---

## What this policy does not cover

- `asyncio.create_subprocess_exec` / `asyncio.create_subprocess_shell`,
  `pty.spawn`, `pexpect.spawn`, `multiprocessing.Process`, and the `os.exec*`
  family — none are in the matched callee set.
- A spawn wrapped behind a helper defined in another module — the rule scans the
  tool body only.
- Whether the spawned command is safe. A literal `subprocess.run(["ls", "/tmp"],
  shell=False)` fires even though it is comparatively benign.
- File-system writes, env-var exfiltration, and network exfiltration through
  *non-subprocess* primitives belong to other policies.

---

## Recommendations beyond the fix

```python
import shutil
from pydantic_ai import Agent

agent = Agent("openai:gpt-4o")

@agent.tool_plain
def disk_usage(path: str) -> str:
    """Return free/used disk space for the volume containing `path`."""
    u = shutil.disk_usage(path)
    return f"total={u.total} used={u.used} free={u.free}"
```

1. Replace shell-outs with a typed library call wherever one exists
   (`shutil`, `pathlib`, an SDK client).
2. If a subprocess is genuinely unavoidable, build the argv list explicitly and
   pass `shell=False`; never interpolate model strings into a `shell=True` command.
   Allow-list the exact commands permitted.
3. Always pass `timeout=` — a model can request an infinitely-running command.
4. Run the agent in a sandbox with dropped capabilities and a network egress
   allow-list; pass a minimal `env` to the subprocess. Keep shell logic out of any
   agent-callable tool and log every spawned command for audit.
