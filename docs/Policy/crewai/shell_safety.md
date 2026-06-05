---
policy_id: crewai_shell_safety
category: crewai
topic: shell_safety
rules:
  - id: CREW-004
    severity: high
    confidence: 0.85
    scope: tool
    fix_type: code
references: [LLM05]
---

# Policy Rationale: CrewAI Shell-Execution Safety

**Policy ID:** `crewai_shell_safety`  
**File:** `crewai/shell_safety.yaml`  
**Rules:** CREW-004  
**Severities:** high  
**Fix types:** code  
**References:** LLM05 (Improper Output Handling)

---

## What this policy covers

CrewAI `@tool`-decorated function bodies that spawn an OS process. The detection
is the structured `has_shell_call` predicate: it walks the function's AST and
fires on any call whose resolved callee is `os.system`, `os.popen`, a
`subprocess.*` member (`subprocess.run`, `.Popen`, `.call`, `.check_output`,
`.check_call`, …), or an `os.spawn*` member. Because it matches the resolved
callee rather than raw text, a `subprocess.run(` mentioned in a comment or
docstring does not fire.

---

## Why shell execution is a distinct concern in CrewAI tools

In a conventional program a subprocess call has a fixed callsite the developer
wrote; the only variability is parameter substitution they approved. In a
model-callable CrewAI tool the model writes or selects the command, and the SDK
imposes no enforcement — the model can return strings that bend the surrounding
command structure, and the tool faithfully runs whatever it builds. Shell
execution selected by model output is the most direct path from prompt injection
to remote code execution.

The blast radius is the entire process: the subprocess inherits the agent's
working directory, environment variables (including API keys), filesystem
credentials, and outbound network access. The CrewAI-specific sharpening is that
CrewAI ships **no** built-in shell-tool class, so unlike frameworks with a
first-class `ShellTool`, a tool that shells out by hand is the *only* shell
surface in a CrewAI project — and it hides inside an ordinary-looking `@tool`.
That makes the hand-rolled `subprocess.run(cmd, shell=True)` the exact shape a
reviewer must hunt for, because nothing else in the framework will flag it.

---

## Rule-by-rule defense

### CREW-004 — Tool body spawns a subprocess (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:** a CrewAI `@tool`-decorated function whose body invokes
`os.system`, `os.popen`, a `subprocess.*` function, or an `os.spawn*` function
(predicate `has_shell_call`, an AST callee walk, not a substring scan).

**Why it is flaggable:** process spawn from a model-callable tool puts the OS
shell on the model's tool surface. The presence of the spawn is the signal;
every safeguard is bolted onto an inherently broad primitive.

**Real-world consequence:** a `run(cmd)` tool forwarding a model string into
`subprocess.run(cmd, shell=True)` is one prompt injection from arbitrary command
execution with the agent's privileges — e.g. an injected
`cmd="cat ~/.ssh/id_rsa"` leaks the private key into the model context.

**Why severity is high and not critical:** the fix usually means removing the
spawn or rearchitecting behind a typed API; it is not raised above high because
the exposure depends on what the caller does with the spawn, and the engine
reserves critical for unconditional RCE. **Fix type — code:** replacing the
spawn (or fronting it with an allow-list) is a tool-source edit. **Confidence
0.85:** the `subprocess.*` prefix over-fires on the rare non-spawning helper
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
  shell=False)` fires even though it is comparatively benign — the predicate
  flags the presence of the primitive, not proof of model-control.
- File-system writes, env-var exfiltration, and network exfiltration through
  *non-subprocess* primitives belong to other policies.

---

## Recommendations beyond the fix

```python
from crewai.tools import tool
import shutil

# Replace `subprocess.run("du -sh " + path, shell=True)` with a typed API.
@tool("disk_usage")
def disk_usage(path: str) -> str:
    """Return free/used disk space for the volume containing `path`."""
    usage = shutil.disk_usage(path)
    return f"total={usage.total} used={usage.used} free={usage.free}"
```

1. Replace shell-outs with a typed library call wherever one exists
   (`shutil`, `pathlib`, an SDK client) rather than shelling to a CLI.
2. If a subprocess is genuinely unavoidable, build the argv list explicitly and
   pass `shell=False`; never interpolate model strings into a `shell=True`
   command. Allow-list the exact commands permitted.
3. Always pass `timeout=` — a model can request an infinitely-running command.
4. Run the agent in a sandbox container with a read-only root filesystem,
   dropped capabilities, and a network egress allow-list; drop sensitive env
   vars from the subprocess (`env={...}` with only what the command needs).
5. Keep shell logic out of any agent-callable tool, and log every spawned
   command with the session ID for audit.
