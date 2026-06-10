---
policy_id: claude_sdk_repo
category: claude_sdk
topic: repo
rules:
  - id: CSDK-201
    severity: critical
    confidence: 0.9
    scope: repo
    fix_type: config
  - id: CSDK-202
    severity: critical
    confidence: 0.9
    scope: repo
    fix_type: config
references: [LLM06]
---

# Policy Rationale: Repository Permission Posture

**Policy ID:** `claude_sdk_repo`  
**File:** `claude_sdk/repo.yaml`  
**Rules:** CSDK-201, CSDK-202  
**Severities:** critical, critical  
**Fix types:** config, config  
**References:** LLM06

---

## What this policy covers

Repo-scope rules for project-wide Claude Agent SDK permission configuration:
the posture declared in `.claude/settings.json` / `settings.local.json`
(predicate `repo_claude_default_mode_is`) and the posture set in code on a
`ClaudeAgentOptions(...)` session object (predicate
`repo_claude_options_permission_mode_is`). Both fire once per scan, not per tool
or per agent. Each rule fires when the respective `bypassPermissions` value is
present.

---

## Why permission posture is a distinct concern in agent tools

Claude Code's permission prompts are the in-band human-in-the-loop control: by
default, a tool call that writes a file, runs a shell command, or fetches the
network pauses for approval. That prompt is the last line of defense between a
prompt-injected or mistaken model action and a real effect on the host. Turning
it off does not weaken one tool — it removes the approval step for *every* tool
the agent can reach, repo-wide.

The danger is amplified by where the setting lives. A `defaultMode:
bypassPermissions` in `.claude/settings.json` is checked into the repository, so
it applies to everyone who clones it, not just the author who set it — a
permission decision made once silently governs every future contributor's
sessions. The `ClaudeAgentOptions(permission_mode="bypassPermissions")` form is
worse in practice because it is where applications actually enable the bypass,
and it executes wherever the application runs (a server, a user's machine, CI)
with no checked-in file to audit.

This is OWASP LLM Top 10:2025 **LLM06 (Excessive Agency)** at the configuration
layer: the agent is granted the standing authority to act without confirmation,
so a single injection or model error becomes an unguarded write, command, or
fetch. The fix is configuration, not code — which is why these are the
highest-leverage findings to act on.

---

## Rule-by-rule defense

### CSDK-201 — Project default permission mode bypasses approvals (Severity: critical, Confidence: 0.9, Fix type: config)

**What we detect:**
A `.claude/settings.json` (or `settings.local.json`) anywhere in the repo whose
`defaultMode` is `bypassPermissions` (predicate `repo_claude_default_mode_is:
[bypassPermissions]`).

**Why it is flaggable:**
`defaultMode: bypassPermissions` disables Claude Code's approval prompts for the
whole repo. Every tool the agent can reach then runs unprompted — file writes,
shell commands, and network fetches all execute with no human step.

**Real-world consequence:**
A checked-in `.claude/settings.json` with `bypassPermissions` means a single
prompt-injected instruction in any document the agent reads can drive an
unguarded `rm`, an exfiltrating network call, or a credential-file read — on the
machine of *anyone* who cloned the repo, not just the author.

**Why severity is critical and not high:**
It removes the only in-band approval control, repo-wide and for every
contributor — a single switch that disables the gate between model output and
every tool's side effects. The earlier framing rated it high on the grounds that
the setting is the enabling condition rather than the exploit itself; the
deployment-readiness gate makes that distinction the wrong cut. A mean-based
readiness score dilutes one fatal setting across many clean surfaces, so a
repo-wide approval bypass must be rated critical to trip the gate's
critical-override and block deployment outright — which is the verdict a human
reviewer gives it.

**Fix type — config:**
Remove the entry or change it to `default` (prompt on every tool call) or
`acceptEdits` (auto-approve only file edits, still gate shell/network). No tool
source changes — it is a settings-file edit. Reserve `bypassPermissions` for
disposable sandboxes, never a shared repo.

**Confidence 0.9:**
The match is an exact value read from a parsed settings file, so false positives
are rare — limited to a settings file that is present but unused (e.g. an example
config not loaded by the running agent). False negatives: a bypass set only at
runtime via the SDK rather than in settings is CSDK-202's job, not this rule's.

### CSDK-202 — Session permission mode bypasses approvals (Severity: critical, Confidence: 0.9, Fix type: config)

**What we detect:**
A `ClaudeAgentOptions(...)` construction in code that sets
`permission_mode="bypassPermissions"` (predicate
`repo_claude_options_permission_mode_is: [bypassPermissions]`).

**Why it is flaggable:**
This is the in-code, session-level form of the `settings.json` `defaultMode`
bypass, and it is where most applications actually enable it. The session turns
off Claude Code's approval prompts, so every tool the agent can call runs with
no human in the loop.

**Real-world consequence:**
An application that constructs
`ClaudeAgentOptions(permission_mode="bypassPermissions")` ships an agent that
acts without confirmation wherever it runs — a server handling untrusted user
input, or a desktop app on an end-user's machine. One injected instruction
becomes an unguarded action with the process's full privileges.

**Why severity is critical and not high:**
Identical blast radius to CSDK-201 — the approval control is gone for every tool
— and it executes in production paths, not just developer clones, which if
anything makes it worse. Rated critical for the same reason its sibling is: a
single fatal approval-bypass switch must reach the deployment gate's
critical-override rather than being averaged away by a mean-based readiness
score.

**Fix type — config:**
Drop the kwarg or set it to `default` / `acceptEdits`. It is a constructor
argument change, not a tool-logic change. Reserve `bypassPermissions` for
disposable sandboxes, never code that runs on a developer's or user's machine.

**Confidence 0.9:**
The match reads the literal `permission_mode` value off the parsed
`ClaudeAgentOptions` call. False positives are limited to dead code (an options
object built but never used) or a value overridden elsewhere at runtime; false
negatives include a mode passed via a variable the scanner cannot resolve to a
literal.

---

## What this policy does not cover

- `permission_mode` / `defaultMode` values supplied dynamically from a variable,
  environment lookup, or config file the scanner cannot resolve to a literal.
- `acceptEdits` mode — auto-approving file edits is a narrower risk these rules
  deliberately do not flag, since shell and network actions still prompt.
- Per-tool allow/deny lists in `settings.json` (`permissions.allow` /
  `deny` / `ask`) that grant broad authority without flipping `defaultMode` —
  a separate settings-permission policy would cover that surface.
- Whether the agent's tools are themselves dangerous; this policy is about the
  approval gate, not what is behind it.

---

## Recommendations beyond the fix

```jsonc
// .claude/settings.json — gate everything by default; auto-approve only edits.
{
  "permissions": {
    "defaultMode": "acceptEdits",
    "deny": ["Bash(rm *)", "Bash(curl *)", "WebFetch"]
  }
}
```

```python
# In code: prompt on tool calls; never bypass on a shared/prod path.
options = ClaudeAgentOptions(permission_mode="default")
```

1. Default to `default` (prompt) for anything running on a real machine; use
   `acceptEdits` only when file-edit churn is the bottleneck and shell/network
   remain gated.
2. If a workflow genuinely needs unattended execution, run it in a disposable
   sandbox (container, ephemeral VM) and scope the agent's tools tightly, rather
   than reaching for `bypassPermissions` on a developer or production host.
3. Keep `settings.local.json` (developer-local, gitignored) for any personal
   loosening, so a bypass never lands in the shared, checked-in config.
