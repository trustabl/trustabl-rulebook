---
policy_id: google_adk_shell_safety
category: google_adk
topic: shell_safety
rules:
  - id: ADK-010
    severity: high
    confidence: 0.9
    scope: tool
    fix_type: code
references: [LLM06, LLM05]
---

# Policy Rationale: Shell Safety

**Policy ID:** `google_adk_shell_safety`  
**File:** `google_adk/shell_safety.yaml`  
**Rules:** ADK-010  
**Severities:** high  
**Fix types:** code  
**References:** LLM06, LLM05

> **Read [openai_sdk/shell_safety.md](../openai_sdk/shell_safety.md) for the full threat model.**
> This document covers Google ADK–specific differences only.

---

## What this policy covers

Google ADK `FunctionTool`-wrapped functions whose body spawns an OS process.
Detection is the same `has_shell_call` AST predicate described in the OpenAI doc:
it fires on a resolved callee of `os.system`, `os.popen`, any `subprocess.*`
member, or any `os.spawn*` member — a structured call-node match, so the string
`subprocess.run(` in a comment or docstring does not trigger it.

---

## Why shell execution is a distinct concern in agent tools

The mechanism is identical to the OpenAI case (the model selects the command; the
subprocess inherits the runtime's full filesystem, environment, and credentials);
see [openai_sdk/shell_safety.md](../openai_sdk/shell_safety.md#why-shell-execution-is-a-distinct-concern-in-agent-tools).

The ADK-specific sharpening is the **deployment target**. ADK agents commonly run
on Cloud Run, Vertex AI Agent Engine, or GKE with an attached service account
whose token is available from the local metadata server. A model-driven
`subprocess.run("curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/...", shell=True)`
combines process spawn and metadata access into one step — the subprocess does
not even need an outbound library, just `curl`. ADK provides no sandbox around
tool execution, so the spawned process has whatever the container grants.

---

## Rule-by-rule defense

### ADK-010 — Tool body spawns a subprocess (Severity: high, Confidence: 0.9, Fix type: code)

**What we detect:**
A `FunctionTool`-wrapped function whose body calls `os.system`, `os.popen`, any
`subprocess.*` function, or any `os.spawn*` function (predicate `has_shell_call`,
an AST callee walk — not a substring scan).

**Why it is flaggable:**
Process spawn from an agent-callable tool puts the OS shell on the model's tool
surface. The presence of the spawn is the signal; every safeguard is bolted on
top of an inherently broad primitive.

**Real-world consequence:**
- An ADK `run_cmd(command: str)` tool forwards a model-supplied string into
  `subprocess.run(command, shell=True)`; on Cloud Run this is one step from
  reading the service-account token and the mounted secrets.
- A `convert_file(path)` tool that shells out to a CLI converter is driven into
  `; cat /var/run/secrets/...` via argument injection.

**Why severity is high and not medium:**
Same reasoning as OAI-012 — the fix usually means removing process spawn or
rearchitecting behind a typed API; partial mitigations narrow specific injection
classes but not the excessive-agency core. Not bumped above high because the
exposure depends on what the caller does with the spawn.

**Fix type — code:**
Replacing the spawn with a library call or fronting it with an allow-list is a
tool-source edit; an agent-level sandbox is complementary.

**Confidence 0.9:**
Same profile as OAI-012 — the `subprocess.*` prefix match over-fires on the rare
non-spawning helper (`subprocess.list2cmdline`), and async/`pty`/`multiprocessing`
spawn primitives or a spawn hidden in another module escape the body-only walk.

---

## What this policy does not cover

Identical to [openai_sdk/shell_safety.md](../openai_sdk/shell_safety.md#what-this-policy-does-not-cover):
`asyncio.create_subprocess_*`, `pty.spawn` / `pexpect`, `multiprocessing.Process`,
the `os.exec*` family, spawn wrapped behind a helper in another module, and the
question of whether a given literal command is safe. Non-subprocess exfiltration
paths (sockets, HTTP) belong to other policies — ADK SSRF (ADK-009) covers the
HTTP path.

---

## Recommendations beyond the fix

The safe pattern — typed library API, argv list with `shell=False`, `timeout=`,
sandboxing, and dropped env vars — is in
[openai_sdk/shell_safety.md](../openai_sdk/shell_safety.md#recommendations-beyond-the-fix).
ADK/GCP-specific additions:

1. Run the agent container with a read-only root filesystem and a minimal service
   account, so a spawned process inherits little worth stealing.
2. Block the metadata CIDR at the VPC egress level so a `curl`-style spawn cannot
   reach `169.254.169.254`.
3. Drop sensitive env vars and mounted secrets from any subprocess that genuinely
   must run.
