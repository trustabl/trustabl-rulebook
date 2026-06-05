---
policy_id: autogen_shell_safety
category: autogen
topic: shell_safety
rules:
  - id: AG2-009
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
references: [LLM05]
---

# Policy Rationale: AutoGen Shell-Execution Safety

**Policy ID:** `autogen_shell_safety`  
**File:** `autogen/shell_safety.yaml`  
**Rules:** AG2-009  
**Severities:** high  
**Fix types:** code  
**References:** LLM05 (Improper Output Handling)

---

## What this policy covers

AutoGen tool function bodies that spawn an OS process. **AG2-009** uses the
structured `has_shell_call` predicate: it walks the function's AST and fires on
any call whose resolved callee is `os.system`, `os.popen`, a `subprocess.*`
member (`subprocess.run`, `.Popen`, `.call`, `.check_output`, `.check_call`, …),
or an `os.spawn*` member. Because it matches the resolved callee, a
`subprocess.run(` in a comment or docstring does not fire.

---

## Why shell execution is a distinct concern in AutoGen tools

A registered AutoGen tool is exposed to the model, and the model writes or selects
the command the tool runs. Shell execution selected by model output is the most
direct path from prompt injection to remote code execution: the subprocess
inherits the agent process's working directory, environment variables (including
API keys), filesystem credentials, and outbound network. A single injected
instruction that reaches the shell runs with the agent's full privileges.

The AutoGen-specific angle is that AutoGen already provides a *bounded* way to run
commands — the code executor, which AutoGen's docs insist should run in Docker. A
hand-rolled `subprocess.run(cmd, shell=True)` inside a tool sidesteps that
boundary completely: it runs in-process with no container, and it hides inside an
ordinary-looking tool the executor's safety settings never touch. So the tool body
is the shell surface a reviewer must inspect, because none of AutoGen's
executor-level controls apply to it.

---

## Rule-by-rule defense

### AG2-009 — Tool body spawns a subprocess (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:** an AutoGen-registered tool whose body invokes `os.system`,
`os.popen`, a `subprocess.*` function, or an `os.spawn*` function (predicate
`has_shell_call`, an AST callee walk, not a substring scan).

**Why it is flaggable:** process spawn from a model-callable tool puts the OS
shell on the model's tool surface. The presence of the spawn is the signal; every
safeguard is bolted onto an inherently broad primitive.

**Real-world consequence:** a `run(cmd)` tool forwarding a model string into
`subprocess.run(cmd, shell=True)` is one prompt injection from arbitrary command
execution — an injected `cmd="env"` exfiltrates the process environment, API keys
included.

**Why severity is high and not critical:** the fix usually means removing the
spawn or rearchitecting behind a typed API; it is not raised above high because
the exposure depends on what the caller does with the spawn, and the engine
reserves critical for unconditional RCE. **Fix type — code:** replacing the spawn
(or fronting it with an allow-list) is a tool-source edit. **Confidence 0.85:**
the `subprocess.*` prefix over-fires on the rare non-spawning helper
(`subprocess.list2cmdline`), and async/`pty` spawn primitives escape the body
walk.

---

## What this policy does not cover

- `asyncio.create_subprocess_exec` / `asyncio.create_subprocess_shell`,
  `pty.spawn`, `pexpect.spawn`, `multiprocessing.Process`, and the `os.exec*`
  family — none are in the matched callee set.
- A spawn wrapped behind a helper defined in another module — the rule scans the
  tool body only.
- Whether the spawned command is safe. A literal `subprocess.run(["ls", "/tmp"],
  shell=False)` fires even though it is comparatively benign.
- AutoGen's own code executor and its Docker configuration — that is an
  agent-scope concern (AG2-001), not a tool rule.

---

## Recommendations beyond the fix

```python
import shutil
from autogen import register_function

def disk_usage(path: str) -> str:
    """Return free/used disk space for the volume containing `path`."""
    u = shutil.disk_usage(path)
    return f"total={u.total} used={u.used} free={u.free}"

register_function(disk_usage, caller=assistant, executor=executor,
                  description="Report disk usage for a path.")
```

1. Replace shell-outs with a typed library call wherever one exists
   (`shutil`, `pathlib`, an SDK client).
2. If a subprocess is genuinely unavoidable, build the argv list explicitly and
   pass `shell=False`; never interpolate model strings into a `shell=True`
   command. Allow-list the exact commands permitted.
3. Always pass `timeout=` — a model can request an infinitely-running command.
4. Run the agent in a sandbox with dropped capabilities and a network egress
   allow-list; drop sensitive env vars from the subprocess. Keep shell logic out
   of any agent-callable tool and log every spawned command for audit.
