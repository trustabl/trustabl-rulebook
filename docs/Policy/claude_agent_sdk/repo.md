# Repository configuration

Repo-scope rules for project-wide Claude Agent SDK configuration: the
permission posture declared in `.claude/settings.json` and in `ClaudeAgentOptions`
session objects. These fire once per scan, not per tool or agent.

## CSDK-201 — Project default permission mode bypasses approvals

**Severity:** high — **Confidence:** 0.9

**Scope:** repo

### What it flags

A `.claude/settings.json` (or `settings.local.json`) that sets
`"defaultMode": "bypassPermissions"`.

### Why it matters

`defaultMode: bypassPermissions` disables Claude Code's permission prompts for
the whole repo. Every tool the agent can reach then runs with no human approval
step — file writes, shell commands, and network fetches all execute unprompted.
A single prompt-injection or a model mistake becomes an unguarded action on the
developer's machine, and because the setting lives in a checked-in file it
applies to everyone who clones the repo, not just the author.

### How to fix

Remove the `"defaultMode": "bypassPermissions"` entry, or change it to
`"default"` so tool calls prompt, or `"acceptEdits"` if you only want to
auto-approve file edits while still gating shell and network actions. Reserve
`bypassPermissions` for disposable sandboxes, never a shared repo.

## CSDK-202 — Session permission mode bypasses approvals

**Severity:** high — **Confidence:** 0.9

**Scope:** repo

### What it flags

A `ClaudeAgentOptions(...)` construction in code that sets
`permission_mode="bypassPermissions"`.

### Why it matters

This is the in-code, session-level form of the `settings.json` `defaultMode`
bypass (CSDK-201), and it is where most applications actually enable it. The
session turns off Claude Code's approval prompts, so every tool the agent can
call — file writes, shell commands, network fetches — runs with no human in the
loop. A single prompt-injection or model error becomes an unguarded action.

### How to fix

Drop `permission_mode="bypassPermissions"` from the `ClaudeAgentOptions(...)`
call, or set it to `"default"` so tool calls prompt (or `"acceptEdits"` to
auto-approve only file edits while still gating shell and network access).
Reserve `bypassPermissions` for disposable sandboxes, never code that runs on a
developer's or user's machine.
