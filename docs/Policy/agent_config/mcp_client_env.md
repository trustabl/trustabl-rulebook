---
policy_id: agent_config_mcp_client_env
category: agent_config
topic: mcp_client_env
rules:
  - id: AGCFG-019
    severity: medium
    confidence: 0.4
    scope: repo
    fix_type: code
references: [LLM02, LLM06]
---

# Policy Rationale: MCP Stdio Server Started With the Whole Parent Environment

**Policy ID:** `agent_config_mcp_client_env`  
**File:** `agent_config/mcp_client_env.yaml`  
**Rules:** AGCFG-019  
**Severities:** medium  
**Fix types:** code  
**References:** LLM02 (Sensitive Information Disclosure), LLM06 (Excessive Agency)

> **Verification status.** The SDK behavior below was read on 2026-11-26 as raw source text:
> the Python SDK's `src/mcp/client/stdio/__init__.py` at tag `v1.27.0` and the TypeScript
> SDK's `src/client/stdio.ts` at tag `v1.29.0`, both from the `modelcontextprotocol`
> GitHub organisation. **Not verified, and therefore not assumed:** how earlier or later
> SDK versions treat `env`; the Gemini CLI vulnerability write-up and the coding-agent CI
> prompt-injection research note that the source sheet names for this rule were not read, so
> nothing below depends on them; and how common it is for real projects to pass the whole environment
> beyond the public sample in the Trustabl report for this batch.

---

## What this policy covers

An application that uses an MCP SDK as a client starts a stdio server as a child process,
and its launch parameters carry an optional `env`. This policy has one rule. **AGCFG-019**
flags a launch whose `env` is the whole parent environment and whose command is not a literal, the case of a host that starts whichever server a variable, a configuration entry or input names. It is repo scope and reports
one finding per matching call. The pack loads for each scan, because the file has no SDK
import; the rule's own predicate does the gating.

---

## Rule-by-rule defense

### AGCFG-019 — MCP stdio server with a non-literal command is started with the whole parent environment (Severity: medium, Confidence: 0.4, Fix type: code)

**What we detect:** a `StdioServerParameters(...)` call in Python, in a file that imports
from the `mcp` package, or a `new StdioClientTransport({...})` call in TypeScript or
JavaScript, with `StdioClientTransport` imported from
`@modelcontextprotocol/sdk/client/stdio.js`, whose `env` is `os.environ`, a name imported
from `os` as `environ`, `os.environ.copy()`, `dict(os.environ)`, a dict display with a
`**os.environ` entry, `process.env`, or an object display with a `...process.env` entry. A
type cast on the TypeScript value does not hide it. The command must not be a literal: the `command` keyword (or the first positional argument in Python) is a variable, a configuration lookup, an f-string with a substitution or another expression, and a TypeScript `command` property is not a string or a template with no substitution. Gated by `repo_call_kwarg_matches`.

What is not flagged: a launch whose command is a string literal, an f-string with no substitution, `sys.executable`, or (TypeScript) a string or a template with no substitution, which names the project's own server; a launch with no command argument; a dict of named variables; an `env` held in a variable or built in a
helper; a `**kwargs` splat; a launch written in a JSON config file (other rules read
those); `subprocess` and `child_process` calls; and any file under a test path.

**Why it is flaggable.**

- Both SDKs define a default for a child process that is not given `env`. The Python
  module's `get_default_environment()` is documented as returning a default environment object
  with the environment variables "deemed safe to inherit", taken from
  `DEFAULT_INHERITED_ENV_VARS`: `HOME`, `LOGNAME`, `PATH`, `SHELL`, `TERM` and `USER` on
  POSIX, and a Windows list. The TypeScript module defines the same list and notes that it
  is "inspired by the default env inheritance of sudo".
- When `env` is given, both SDKs merge it over that default: Python builds
  `{**get_default_environment(), **server.env}` and TypeScript spreads
  `getDefaultEnvironment()` and then the server's `env`. A whole-environment `env` therefore
  replaces the narrow default with all variables of the parent, including credentials the
  server has no use for.

**Real-world consequence:** a server chosen at run time is code the host did not write and
the model's tool calls drive. A variable in its environment can be read by that code and sent wherever the
server can reach.

**Why severity is medium:** The pack sets medium and states no reasoning for it. The
explanation names the credentials that a whole-environment `env` hands to the server.

**Fix type — code:** the fix edits the launch call. The pack's fix is to pass a dict of the
variables the server reads, for example `env={"GITHUB_TOKEN": os.environ["GITHUB_TOKEN"]}`;
the SDK adds its default list, so the server still starts.

**Confidence 0.4:** the pack's explanation states these limits of the check:

- It reads the keyword or property written at the launch call; an `env` in a variable, a
  helper or a `**kwargs` splat is not judged, and JSON launch configs have their own rules.
- A Python call is judged when the file imports from `mcp` and the callee is
  `StdioServerParameters`; a TypeScript call is judged when `StdioClientTransport` is
  imported from the SDK's `client/stdio` module.
- Files under a test path are not read.
- A command that is a literal is not flagged, and a command that is not a literal does not
  prove that the server is third-party code: a path built from the project's own directory in
  an f-string or a variable is flagged.
- `subprocess` calls and other SDKs' options objects are not judged, because a child
  process inherits the full parent environment when `env` is omitted.

The pack states no other limits for this rule.

---

## What this policy does not cover

- An `env` that reaches the launch through a variable, a helper or a splat.
- MCP launches in `.mcp.json` and other config files.
- `ClaudeAgentOptions(env=...)`, `subprocess.run(env=...)` and other process APIs.
- Whether the variables passed are secrets; the check does not read their names.

---

## Recommendations beyond the fix

```python
params = StdioServerParameters(
    command="npx",
    args=["-y", "example-server"],
    env={"EXAMPLE_TOKEN": os.environ["EXAMPLE_TOKEN"]},
)
```

1. List the variables each server needs and pass those.
2. Keep production credentials out of the process that hosts MCP clients when the servers
   are not your own.

---

## Sources

Retrieved 2026-11-26.

- Model Context Protocol Python SDK, `src/mcp/client/stdio/__init__.py` at tag `v1.27.0`,
  `github.com/modelcontextprotocol/python-sdk`. The source of the Python default and merge
  behavior above.
- Model Context Protocol TypeScript SDK, `src/client/stdio.ts` at tag `v1.29.0`,
  `github.com/modelcontextprotocol/typescript-sdk`. The source of the TypeScript default and
  merge behavior above.
