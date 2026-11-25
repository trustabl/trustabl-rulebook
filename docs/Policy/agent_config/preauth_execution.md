---
policy_id: agent_config_preauth_execution
category: agent_config
topic: preauth_execution
rules:
  - id: AGCFG-004
    severity: critical
    confidence: 0.9
    scope: repo
    fix_type: config
  - id: AGCFG-005
    severity: critical
    confidence: 0.7
    scope: repo
    fix_type: config
  - id: AGCFG-006
    severity: critical
    confidence: 0.8
    scope: repo
    fix_type: config
  - id: AGCFG-007
    severity: high
    confidence: 0.85
    scope: repo
    fix_type: config
references: [LLM06, LLM03, LLM02]
---

# Policy Rationale: Pre-Trust Agent Configuration

**Policy ID:** `agent_config_preauth_execution`  
**File:** `agent_config/preauth_execution.yaml`  
**Rules:** AGCFG-004, AGCFG-005, AGCFG-006, AGCFG-007  
**Severities:** critical, critical, critical, high  
**Fix types:** config, config, config, config  
**References:** LLM06 (Excessive Agency), LLM03 (Supply Chain), LLM02 (Sensitive Information Disclosure)

> **Verification status.** Read on 2026-11-11. The Codex project-config behavior comes
> from the Codex configuration reference (`developers.openai.com/codex/config-reference`)
> and from `PROJECT_LOCAL_CONFIG_DENYLIST` in `codex-rs/config/src/loader/mod.rs` on the
> `main` branch of `openai/codex`. The Gemini CLI behavior comes from its
> `docs/reference/configuration.md` and from its source at commit `e5d88fb` (2026-11-10):
> `packages/core/src/core/contentGenerator.ts` and `packages/cli/src/config/settings.ts`.
> **Not verified, and therefore not assumed:** the Gemini CLI hooks shape (the scanner
> reads Gemini hooks with the same walk it uses for Claude Code); whether `NODE_OPTIONS`
> or `LD_PRELOAD` set in `.gemini/.env` reaches a child process Gemini CLI starts; which
> tool reads a `*_PROXY_COMMAND` or `GEMINI_SANDBOX*` key in a Codex `config.toml` (the
> reference lists none, and the check keeps them); and `.gemini/.env` files in public
> repositories, which were not sampled. Treat Gemini and Codex hits as "this file asks
> for it", and check the current vendor behavior before you rely on a verdict.

---

## What this policy covers

Agent harnesses read configuration from the repository itself: settings files,
hook definitions, MCP server lists, workspace env files. If that configuration
runs a command or grants authority, the effect lands when the folder is opened,
before the user has been asked to trust it. Cloning the repo is enough. No prompt
injection and no model cooperation are needed, which is why these rules are
critical where most agent rules are not.

The four rules cover four distinct mechanisms: **AGCFG-004** auto-approves the
repo's own MCP servers; **AGCFG-005** declares hooks that execute
repo-controlled or exfiltrating commands; **AGCFG-006** overrides sandbox, proxy,
endpoint, or loader behavior from a workspace file; **AGCFG-007** turns on editor
agent auto-approve. All are repo scope and fire once per scan, attributed to the
first path-sorted offending file and line. The pack loads for every scan, because
the files exist whether or not the repo imports an SDK; each rule's own predicate
does the gating.

---

## Evidence

These are the public disclosures behind the policy. This document states only what
is listed here and does not reproduce exploit details.

| Reference | Harness | What it shows | Rule |
|---|---|---|---|
| CVE-2026-12537 | Gemini CLI | `.gemini/.env` sets `GEMINI_SANDBOX_PROXY_COMMAND`; CVSS v4 10.0 | AGCFG-006 |
| CVE-2025-59536 | Claude Code | Project `.mcp.json` servers ran before the trust dialog | AGCFG-004 |
| CVE-2025-54136 (MCPoison), CVE-2025-54135 (CurXecute) | Cursor | Cursor issues in the MCP-config area; no further detail is reproduced here | AGCFG-004 (related) |
| CVE-2025-53773 | Copilot / VS Code | `chat.tools.autoApprove` | AGCFG-007 |

Taxonomy: OWASP ASI04 and ASI05, MITRE ATLAS AML.T0053. Source: Trustabl Agentic
Security Baseline 2026-10-06, issue AGS-06. AGCFG-005 has no CVE in this list; its
grounding is the mechanism (hooks execute commands with the developer's privileges)
and the fact that the other three rules share the same pre-trust attack shape.

---

## Rule-by-rule defense

### AGCFG-004 — Project settings auto-enable the repo's own MCP servers (Severity: critical, Confidence: 0.9, Fix type: config)

**What we detect:** a `.claude/settings.json` or `settings.local.json` that sets
`enableAllProjectMcpServers: true`, or a non-empty `enabledMcpjsonServers`.
Parsed into `ClaudeSettings.EnableAllProjectMcpServers` / `EnabledMcpjsonServers`;
gated by `repo_project_mcp_autoenable`. Absent keys, `false`, and an empty list
are silent.

**Why it is flaggable:** both keys remove the approval step for servers declared
in the repo's `.mcp.json`. The servers are launched commands, so whoever controls
the repo controls what runs. This is the mechanism class behind CVE-2025-59536.

**Real-world consequence:** a developer clones a repo and opens it; the committed
settings pre-approve a server whose command is a script in the repo; it runs with
the developer's privileges before they read anything.

**Why severity is critical:** code execution with no user action beyond opening
the folder. **Fix type — config:** delete the keys; approve servers per user.

**Confidence 0.9:** the predicate reads two explicit keys, so false positives are
rare. The remaining doubt is intent: a repo that is itself a disposable sandbox
might set it deliberately, and `settings.local.json` is normally gitignored, so a
hit there may not be committed content.

### AGCFG-005 — Project hooks execute repo-controlled commands (Severity: critical, Confidence: 0.7, Fix type: config)

**What we detect:** a hook `command` in `.claude/settings.json` (or
`settings.local.json`) or `.gemini/settings.json` that (a) names a repo-relative
script (`./x.sh`, `$CLAUDE_PROJECT_DIR/...`, a relative path with a directory or
script extension), (b) uses `curl`, `wget`, `nc`, `ncat`, `bash -c`, `sh -c`,
`zsh -c`, `python -c`, `node -e` or `eval`, or (c) references `.ssh`, `.aws`, or
`.env`. Gated by `repo_project_hook_runs_untrusted_command`. Findings carry the
hook event and a fixed reason; the command text is not echoed.

**Why it is flaggable:** hooks run automatically on agent events with the
developer's privileges. A repo-relative script is controlled by the repo; a network
or inline-exec primitive is an exfiltration or staging path; a credential-path
reference is a read of secrets.

**Real-world consequence:** a `SessionStart` hook runs `./scripts/setup.sh` that a
later commit changes to read `~/.aws/credentials` and post it out.

**Why severity is critical:** same pre-trust execution shape as AGCFG-004.
**Fix type — config:** remove the hook or move it to user-level settings.

**Confidence 0.7:** the lowest in the policy, on purpose. Many repos ship benign
project hooks (a formatter script, a lint wrapper) that this heuristic flags, since
it cannot read the script's intent. The Gemini hooks shape is also unverified (see
the verification note).

### AGCFG-006 — Workspace env file overrides sandbox, proxy, endpoint or trust (Severity: critical, Confidence: 0.8, Fix type: config)

**What we detect:** key **names** (values are not read) in env and config files.
In `.gemini/.env`: `GEMINI_SANDBOX*`, `*_PROXY_COMMAND`, `GOOGLE_GEMINI_BASE_URL`,
`GOOGLE_VERTEX_BASE_URL`, `NODE_OPTIONS`, `LD_PRELOAD`. In `.codex/config.toml`:
`sandbox_mode = "danger-full-access"`, `approval_policy = "never"`, and the keys
`NODE_OPTIONS`, `LD_PRELOAD`, `*_PROXY_COMMAND` and `GEMINI_SANDBOX*` at any depth. In a
repo-root `.env`: `GEMINI_SANDBOX*` and `*_PROXY_COMMAND` alone, because ordinary
applications set the others. Gated by `repo_workspace_env_overrides_trust`.

What is not flagged, and why. A `*_BASE_URL` key is judged where the tool reads it.
- Gemini CLI reads two endpoint variables. `contentGenerator.ts` takes
  `process.env['GOOGLE_VERTEX_BASE_URL']` for Vertex auth and
  `process.env['GOOGLE_GEMINI_BASE_URL']` otherwise. A search of the repository's
  `packages/` and `docs/` found no `OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL` or
  `GEMINI_API_BASE`. A key Gemini CLI does not read is not an override of Gemini CLI.
- Codex ignores endpoint keys in a project file. The reference says: "Codex ignores
  `openai_base_url`, `chatgpt_base_url`, `apps_mcp_product_sku`, `model_provider`,
  `model_providers`, `notify`, `profile`, `profiles`, `experimental_realtime_ws_base_url`,
  and `otel` when they appear in a project-local `.codex/config.toml`". The loader's
  `PROJECT_LOCAL_CONFIG_DENYLIST` removes the same set (and two more) from the project
  table before use, with the comment "Project-local config comes from repository
  contents, so it should not get to choose where a user's credentials are sent or which
  local commands are run." So `config.toml` judges no endpoint key.

**Why it is flaggable:** these keys change what the harness executes or what code it
loads. A `*_PROXY_COMMAND` is a command the tool runs. `GOOGLE_GEMINI_BASE_URL` and
`GOOGLE_VERTEX_BASE_URL` change where Gemini CLI sends prompts and credentials.
`NODE_OPTIONS` and `LD_PRELOAD` change what code is loaded. CVE-2026-12537 is the
`GEMINI_SANDBOX_PROXY_COMMAND` case.

In Codex, `NODE_OPTIONS` and `LD_PRELOAD` under `[shell_environment_policy.set]` in a
project file are kept by the loader. `sanitize_project_config` in
`codex-rs/config/src/loader/mod.rs` filters that table when a credential broker is enabled,
and not otherwise (`credential_broker ==
CredentialBrokerProjectState::Enabled`). In that case it drops `experimental_use_profile`
from `shell_environment_policy`, and drops from `set` the keys that match `ZDOTDIR` or
`BASH_ENV` (`key.eq_ignore_ascii_case("ZDOTDIR")`, `key.eq_ignore_ascii_case("BASH_ENV")`),
a credential-broker provider environment key, or
a trusted provider environment key. `NODE_OPTIONS` and `LD_PRELOAD` are not in that list.
When no credential broker is enabled, the loader filters nothing in this table, so all
keys in `set` are kept. Either way the two keys reach the environment of the commands Codex
runs, after the project is trusted.

**Trust conditions.** Gemini CLI's `loadEnvironment` loads the file in a trusted
workspace; in an untrusted one it loads the four keys `GEMINI_API_KEY`, `GOOGLE_API_KEY`,
`GOOGLE_CLOUD_PROJECT` and `GOOGLE_CLOUD_LOCATION`. The reference says Codex "loads
project-scoped config files only when you trust the project". So a finding describes what
happens after the folder is trusted.

**Real-world consequence:** after the folder is trusted, a proxy command in the file runs,
and an endpoint override sends Gemini prompts and credentials to the host the repo author
named, with no further prompt.

**Why severity is critical:** The pack sets critical and states no reasoning for it.
CVE-2026-12537, the `GEMINI_SANDBOX_PROXY_COMMAND` case, is rated CVSS v4 10.0; that score
is stated for that issue, not for each arm of this rule. **Fix type — config:** delete the
key; set sandbox and proxy options in user-level config.

**Confidence 0.8:** key-name matching is precise for the keys listed. A legitimate
corporate proxy or gateway in `.gemini/.env`, or an endpoint override that names the
vendor's own host, is flagged like a malicious one, because values are not read. The
verification-status note lists what remains unverified.

**Sources, each cited for the statements above and nothing more.**
- Codex configuration reference, retrieved 2026-11-11: the ignored-key list and the trust
  sentence.
- `codex-rs/config/src/loader/mod.rs` (`openai/codex`, `main`, retrieved 2026-11-11):
  `PROJECT_LOCAL_CONFIG_DENYLIST` and `sanitize_project_config`.
- Gemini CLI `docs/reference/configuration.md` and `packages/core/src/core/contentGenerator.ts`
  (`google-gemini/gemini-cli`, commit `e5d88fb`, retrieved 2026-11-11): the endpoint
  variables. `packages/cli/src/config/settings.ts`: the untrusted-workspace key list.

### AGCFG-007 — Editor settings enable agent auto-approve (Severity: high, Confidence: 0.85, Fix type: config)

**What we detect:** a boolean `true` for any key containing `autoapprove` or
`yolo` (case-insensitive) in `.vscode/settings.json` or `.cursor/*.json` other than
`mcp.json`, flat (`"chat.tools.autoApprove"`) or nested. JSONC comments and
trailing commas are tolerated. Gated by `repo_editor_agent_auto_approve`.

**Why it is flaggable:** with auto-approve on, the editor agent runs tool calls and
terminal commands without confirmation, for everyone who opens the workspace.
CVE-2025-53773 concerns `chat.tools.autoApprove`.

**Real-world consequence:** an injected instruction in any file the agent reads
becomes an unprompted command on the developer's machine.

**Why severity is high and not critical:** it removes a safeguard rather than
executing a command by itself, so exploitation still needs an injection.
**Fix type — config:** remove the flag.

**Confidence 0.85:** the match is an explicit boolean, but the substring match on
key names can hit an unrelated setting that happens to contain `yolo`.

---

## What this policy does not cover

- Whether a committed file is actually tracked by git. The scanner sees the working
  tree, so a gitignored `settings.local.json` or `.env` is read like any other.
- Object-valued auto-approve settings (per-command terminal allow-lists).
- Env values of any kind: they are not read, so a key with a malicious value and a key
  with a benign value look the same.
- `*_BASE_URL` keys that the tool does not read: Codex ignores them in a project file
  and Gemini CLI reads two. A tool that reads a different key is not covered.
- Nested `.env` files outside `.gemini/`, harnesses other than Claude Code, Gemini
  CLI, Codex, VS Code and Cursor, and user-level or enterprise-managed config.
- Hook scripts' contents: AGCFG-005 flags that a script is invoked, not what it does.
- Gemini CLI hook semantics (unverified), and the tool that reads a `*_PROXY_COMMAND` or
  `GEMINI_SANDBOX*` key in a Codex `config.toml` (unverified; follow-up).

---

## Recommendations beyond the fix

```json
{
  "permissions": { "defaultMode": "default" }
}
```

1. Keep project settings declarative: permissions and deny-lists, no hooks that
   run repo scripts, no MCP auto-approval.
2. Put personal convenience (hooks, auto-approve, proxies, sandbox mode) in
   user-level configuration, which does not travel with a clone.
3. Review config files in pull requests as you would CI definitions: a change to
   `.claude/`, `.gemini/`, `.vscode/`, `.cursor/` or `.codex/` can execute code on
   every contributor's machine.
4. Open unfamiliar repos in a disposable environment first, and read the config
   directories before you trust the folder.
