---
policy_id: agent_config_codex_hooks
category: agent_config
topic: codex_hooks
rules:
  - id: AGCFG-008
    severity: medium
    confidence: 0.55
    scope: repo
    fix_type: config
references: [LLM06, LLM02]
---

# Policy Rationale: Codex Project Hooks

**Policy ID:** `agent_config_codex_hooks`  
**File:** `agent_config/codex_hooks.yaml`  
**Rules:** AGCFG-008  
**Severities:** medium  
**Fix types:** config  
**References:** LLM06 (Excessive Agency), LLM02 (Sensitive Information Disclosure)

> **Verification status.** The hooks file shape and the trust model below were
> read from OpenAI's Codex hooks documentation on 2026-10-20
> (`developers.openai.com/codex/hooks`, which redirects to
> `learn.chatgpt.com/docs/hooks`). The page carries no version or date, and says
> its schemas on the `main` branch may include fields that are not in the current
> release. **Not documented, and therefore not assumed:** how a project's
> `.codex/` layer becomes trusted, where trust records are stored, whether editing
> a script that a hook calls prompts a new review, and general Windows behavior.

---

## What this policy covers

Codex reads hooks from `<repo>/.codex/hooks.json` (and from inline `[hooks]`
tables in `config.toml`, user-level files, plugins and managed requirements). A
hook is a command that runs on an agent event such as `PreToolUse`, `PostToolUse`
or `SessionStart`, with the developer's privileges.

This policy has one rule. **AGCFG-008** flags a committed `.codex/hooks.json`
whose hook `command` or `commandWindows` runs a repo script, uses a network or
inline-execution primitive, or references a credential path. It is repo scope and
fires once per scan, attributed to the first path-sorted offending hook. The pack
loads for every scan, because the file exists whether or not the repo imports an
SDK; the rule's own predicate does the gating.

---

## Why this is not a pre-trust rule

The other `agent_config` rules (AGCFG-004 to AGCFG-007) describe configuration
that acts the moment a folder is opened, before the user is asked anything. That
is why they are critical. Codex hooks do not work that way. The documentation
says:

- "Project-local hooks load only when the project `.codex/` layer is trusted."
- "Non-managed hooks must be reviewed and trusted before they run." Trust is
  recorded against the hook's current hash, and new or changed hooks are skipped
  until the user reviews them in `/hooks`.
- Hooks that a plugin bundles are not trusted automatically either.
- `--dangerously-bypass-hook-trust` runs enabled hooks without persisted trust for
  that invocation, so a run that uses it removes the review step.

So the shape of the risk is different. A repo can ship a hook, but a user has to
approve it first. The remaining risk is what that approval is worth: a single
review of a short definition, for a command that then runs on every matching event
with the developer's privileges. AGCFG-005 is therefore kept for Claude Code and
Gemini settings, and Codex hooks are judged by their own rule with their own
severity and wording. Codex hooks never feed AGCFG-005.

---

## Rule-by-rule defense

### AGCFG-008 — Codex project hook runs a repo-controlled command once trusted (Severity: medium, Confidence: 0.55, Fix type: config)

**What we detect:** a hook handler in `.codex/hooks.json`
(`hooks.<Event>[].hooks[]`, `type` `command` or untyped) whose `command` or
`commandWindows` (a) names a repo-relative script (`./x.sh`, `../tools/x.py`, a
relative path with a directory or script extension, or the documented repo-root
form `$(git rev-parse --show-toplevel)/...`), (b) uses `curl`, `wget`, `nc`,
`ncat`, `bash -c`, `sh -c`, `zsh -c`, `python -c`, `node -e` or `eval`, or
(c) references `.ssh`, `.aws` or `.env`. Handlers of type `mcp_tool`, `prompt` and
`agent` are skipped: they carry no shell command. Gated by
`repo_codex_hook_runs_repo_command`. Findings carry the hook event and a fixed
reason; the command text is not echoed.

**Why it is flaggable:** once trusted, the hook runs automatically on agent events
with the developer's privileges. A repo-relative script is controlled by whoever
controls the repo; a network or inline-execution primitive is an exfiltration or
staging path; a credential-path reference is a read of secrets. The documented
repo-root form is matched on purpose, because it is the idiom OpenAI's own
examples use and the shared repo-relative check ignores tokens that start with
`$`.

**Real-world consequence:** a contributor adds a `PreToolUse` hook that runs
`.codex/hooks/policy.py`. A maintainer reviews the hook definition and trusts it.
A later commit changes the script to read `~/.aws/credentials` and post it out.
Whether that later change prompts a new review is not stated in the documentation,
so this document does not claim it does or does not.

**Why severity is medium and not critical:** execution needs a user trust step that
the pre-trust rules do not have, and an untrusted hook is skipped. It stays above
low because the approval is brief, the command then runs with full user
privileges, and a bypass flag exists.

**Fix type — config:** review the hook and the script it calls before trusting it,
prefer a vetted binary on the user's `PATH` over a repo script, and keep personal
hooks in `~/.codex/hooks.json`.

**Confidence 0.55:** deliberately modest. Many repos ship legitimate project
hooks, and OpenAI's own documentation shows repo scripts for policy checks and
tool review. This heuristic sees that a script is invoked, not what it does, so it
flags those too. It is a prompt to review a hook, not a verdict.

---

## What this policy does not cover

- Whether the user has actually trusted the hook, or whether the project layer is
  trusted. The scanner reads files and cannot see trust state.
- Hooks in plugin `hooks/hooks.json` files and in inline `[hooks]` tables in
  `config.toml`. Only `.codex/hooks.json` is read.
- User-level (`~/.codex/hooks.json`) and enterprise-managed hooks.
- The `mcp_tool`, `prompt` and `agent` handler types.
- What a hook's script does. AGCFG-008 flags that a script is invoked.
- Use of `--dangerously-bypass-hook-trust` or `[features].hooks = false`.
- Hook semantics that differ between Codex releases. Treat a hit as "this file
  asks for it" and check the current vendor behavior.

---

## Recommendations beyond the fix

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "/usr/local/bin/org-policy-check" }
        ]
      }
    ]
  }
}
```

1. Prefer a hook that calls a vetted binary installed outside the repo over one
   that runs a script a contributor can change.
2. Open `/hooks` and read each hook before trusting it, including the script it
   calls. Re-read after a pull that touches `.codex/`.
3. Put personal convenience hooks in user-level configuration, which does not
   travel with a clone.
4. Review changes to `.codex/` in pull requests as you would a CI definition.
5. For an organization, use managed hooks, and consider `allow_managed_hooks_only`
   so that project and user hooks are ignored.
6. Do not run Codex with `--dangerously-bypass-hook-trust` on a repository you have
   not read.
