---
policy_id: agent_config_script_agent_bypass
category: agent_config
topic: script_agent_bypass
rules:
  - id: AGCFG-015
    severity: high
    confidence: 0.6
    scope: repo
    fix_type: config
references: []
---

# Policy Rationale: Agent CLI Started with Approvals or Sandbox Disabled by a Committed Script

**Policy ID:** `agent_config_script_agent_bypass`  
**File:** `agent_config/script_agent_bypass.yaml`  
**Rules:** AGCFG-015  
**Severities:** high  
**Fix types:** config  
**References:** none

> **Verification status.** The Snyk post was read in full on 2026-11-04 from its web page
> (raw HTML). The GitHub advisory GHSA-cxm3-wv7p-598c was read on 2026-11-04 from its
> advisory page; the page text read does not show an agent CLI flag. The vendor flags
> below were read on 2026-11-04 from Anthropic's Claude Code CLI reference
> (`code.claude.com/docs/en/cli-reference`) and permissions page
> (`code.claude.com/docs/en/permissions`), the Gemini CLI reference
> (`docs/cli/cli-reference.md` in `google-gemini/gemini-cli`), the Codex CLI command
> reference (`learn.chatgpt.com/docs/developer-commands`, the target of the redirect from
> `developers.openai.com/codex/cli/reference`) and the aider options page
> (`aider.chat/docs/config/options.html`). The npm lifecycle behavior was read on
> 2026-11-04 from the npm CLI v10 scripts page (`docs.npmjs.com/cli/v10/using-npm/scripts`),
> and the husky behavior from the husky "Get started" and "How To" pages
> (`typicode.github.io/husky/get-started.html`, `.../how-to.html`). **Not verified, and
> therefore not assumed:** a vendor page for the `q chat --trust-all-tools` form (the Amazon
> Q pages read on 2026-11-04 returned a page title and no other text, so that form rests on
> the Snyk post alone); how husky connects a hook file to git (the husky pages read state
> the file and the commit example, not the mechanism); the behavior of npm and husky
> versions other than the pages' current text; the behavior of vendor CLI versions other
> than the pages' current text; and whether any other tool takes the flags listed below.

---

## What this policy covers

A repository can commit scripts that run when its package is installed or when a git hook
fires. If one of those scripts starts a coding-agent CLI with a flag that turns off its
approval prompts or its sandbox, the agent runs with the developer's own logged-in session
and no prompt. The pack loads for each scan, because the files it reads have no SDK import;
the rule's own predicate does the gating.

This policy has one rule. **AGCFG-015** flags a committed script that starts `claude`,
`gemini`, `codex` or `aider`, or the form `q chat`, together with a documented bypass flag.
It is repo scope and fires once per scan, attributed to the first path-sorted offending
file and line.

---

## Rule-by-rule defense

### AGCFG-015 — Committed script runs an agent CLI with approvals or sandbox disabled (Severity: high, Confidence: 0.6, Fix type: config)

**What we detect:** one of three surfaces, gated by
`repo_script_runs_agent_cli_with_bypass_flag`.

1. In each `package.json` at any depth, the `preinstall`, `install`, `postinstall` and
   `prepare` entries of `scripts` when the value is a string.
2. In each file directly inside a `.husky/` directory at any depth (the generated
   `.husky/_` directory is not read), each line that does not begin with `#`.
3. In each JavaScript or TypeScript file outside test paths (the engine's `pathclass`
   test-path rule), a call to `spawn`, `spawnSync`, `exec`, `execSync`, `execFile`,
   `execFileSync`, `Bun.spawn` or `Bun.spawnSync`.

For the shell surfaces the string is split on `&&`, `||`, `;`, `|`, `$(` and the backtick,
and each part is split into words with quote handling. The command word must be the first
word of a part, after environment assignments, `env`, `exec`, `time`, `sudo`, or `npx`,
`bunx`, `pnpm`, `yarn` or `npm` with a leading flag, `dlx` or `exec` and a known package
(`@anthropic-ai/claude-code`, `@google/gemini-cli`, `@openai/codex`). The binary is the base
name of the command word. For a spawn call the binary must be a string literal that is the
first argument (or the first element of the `Bun.spawn` command array) and the flag must be
a string literal in the same call, as a command string or as an element of an args array.

The binary and flag pairs are fixed in `agentBypassFlag` and are matched as whole words:

- `claude` with `--dangerously-skip-permissions`, or `--permission-mode` followed by
  `bypassPermissions` (as two words or as `--permission-mode=bypassPermissions`).
- `gemini` with `--yolo`, or `--approval-mode` followed by `yolo` (two words or `=`).
- `codex` with `--dangerously-bypass-approvals-and-sandbox` or `--yolo`.
- `aider` with `--yes-always`.
- `q` as the first argument `chat` together with `--trust-all-tools`. The binary `q` alone does
  not match.

What is not flagged:

- Any script name other than the four lifecycle names, Makefiles, shell scripts, README and
  documentation text, and workflow `run:` steps (the CI rules read workflow files).
- `--allow-dangerously-skip-permissions` (a different word from the claude flag).
- A binary or flag held in a variable, a command built at run time, a call through another
  helper, and a spawn call whose binary is the result of another call.
- A spawn call that takes the binary or the flags from an object or array defined elsewhere,
  as in the configuration entries the Snyk post shows.
- A string that merely mentions a command, such as `echo claude --yolo`.
- Any other binary, including `cline`, `agent` and `cursor-agent`, and the flags `-y`,
  `--force`, `--auto-approve`, `--full-auto` and an `approval_policy` override.
- A `package.json` that is not valid JSON, a `scripts` value that is not an object, and a
  script value that is not a string.
- A JavaScript or TypeScript file under a test path.

A hit records the file, the line, and a fixed reason that names the surface, the binary and
the flag. No other text from the script, including the prompt, is stored in a struct, a
reason, a log or a finding.

**Why it is flaggable.**

- The source. Liran Tal, "Weaponizing AI Coding Agents for Malware in the Nx Malicious
  Package Security Incident" (Snyk, 27 August 2025), says: "the postinstall malware tried
  multiple AI CLI tools locally, including Claude's Claude Code, Google's Gemini CLI, and
  Amazon's new q command-line coding agent, and invoked them with unsafe flags to bypass
  guardrails and scan the filesystem". It names the flags: `--dangerously-skip-permissions`
  (Claude Code), `--yolo` (Gemini CLI) and `--trust-all-tools` (Amazon q). It says "The
  postinstall script telemetry.js imports child processing capabilities" and shows
  `const { spawnSync } = require('child_process');` and configuration entries of the form
  `{ cmd: 'claude', args: ['--dangerously-skip-permissions', '-p', PROMPT] }`,
  `{ cmd: 'gemini', args: ['--yolo', '-p', PROMPT] }` and
  `{ cmd: 'q', args: ['chat', '--trust-all-tools', '--no-interactive', PROMPT] }`. The flags
  therefore appear in that post as arguments passed from JavaScript, which is why the rule
  reads spawn calls as well as `package.json` and hook files. The post does not show the line
  that runs each entry, and this policy does not claim it does.
- When the scripts run. The npm CLI v10 scripts page, read 2026-11-04, lists `preinstall`,
  `install`, `postinstall`, `prepublish`, `preprepare`, `prepare` and `postprepare` under
  "npm install" and says "These also run when you run `npm install -g <pkg-name>`"; it lists
  the same hooks under "npm ci" and says "These all run after the actual installation of
  modules into `node_modules`, in order". For `prepare` it says "Runs on local `npm install`
  without any arguments" and "Runs BEFORE the package is packed, i.e. during `npm publish`
  and `npm pack`". For a package installed from git it says "the prepare script will be run,
  before the package is packaged and installed." The page does not define `preinstall`,
  `install` and `postinstall` apart from listing them under the commands that run them.
- When a husky hook file runs. The husky "How To" page, read 2026-11-04, says "Adding a hook
  is as simple as creating a file" and shows `echo "npm test" > .husky/pre-commit`. The "Get
  started" page says `husky init` "creates a pre-commit script in .husky/ and updates the
  prepare script in package.json", and its example runs a `git commit` and says the test
  script runs on the commit. Neither page explains how a file in `.husky/` is connected to
  git.
- What the Claude flag does. The Claude Code CLI reference says: "`--dangerously-skip-permissions`
  Skip permission prompts. Equivalent to `--permission-mode bypassPermissions`." The
  permissions page says `bypassPermissions` "Skips permission prompts, except for the
  actions no mode auto-approves". The same reference lists `--allow-dangerously-skip-permissions`
  as adding `bypassPermissions` to the mode cycle "without starting in it", which is why the
  rule does not match it.
- What the Gemini flags do. The Gemini CLI reference lists `--approval-mode` with
  "Choices: `default`, `auto_edit`, `yolo`, `plan`" and `--yolo` as "Deprecated.
  Auto-approve all actions. Use `--approval-mode=yolo` instead."
- What the Codex flag does. The Codex CLI command reference lists
  `--dangerously-bypass-approvals-and-sandbox, --yolo` as a flag that runs commands without
  approvals or sandboxing, and tells the reader to use it inside an externally hardened
  environment.
- What the aider flag does. The aider options page lists `--yes-always` as a flag that
  answers yes to confirmations.
- The nx incident. The advisory GHSA-cxm3-wv7p-598c, "Malicious versions of Nx and some
  supporting plugins were published" (published 27 August 2025; reporters credited on the
  page: jahredhope, hckhanh, TimShilov; tadhglewis as "Other"), says the affected package
  "contained a `postinstall` script that scanned user's file system". The advisory is cited
  for the postinstall script and the incident and nothing more; the page text read shows no
  agent CLI flag.

A committed script that starts one of these CLIs with its bypass flag therefore runs the
agent with the developer's session and no prompt, the way the post describes the nx
postinstall script doing.

**Real-world consequence:** the agent acts on the files and credentials the developer's
session can reach without asking, and the script's author chooses the prompt. The pack's
explanation states this and does not state a figure for how many repositories do it.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Fix type — config:** the fix is an edit to the committed script. The pack's fix removes the
flag, grants the agent the specific tools the task needs (for example
`claude -p "summarize" --allowedTools Read`), and for a script that must run unattended runs
it in a container or CI job that holds no credentials.

**Confidence 0.6:** the pack's explanation states these limits of the check:

- In a spawn call the binary and the flag must both be string literals in the same call; a
  value in a variable, a command built at run time and a call through another helper are not
  seen.
- Named `package.json` scripts, Makefiles, shell scripts, workflow `run:` steps, README text
  and a command split over several lines are not judged.
- A binary other than the ones listed is not judged.
- The check cannot tell a script written by the project's own developers for their use from
  one added to attack them.
- JavaScript and TypeScript files under test paths are not read.

On 2026-11-04 the detector's logic was run as a prototype over shallow clones of 134
public repositories (72 `package.json` files, 15 Makefiles, 33 `.husky` hook files and all
their JavaScript and TypeScript files outside `node_modules`); it found no hit on the three
surfaces above. The same pass over shell scripts, which this rule does not read, found
developer-run wrappers that launch `claude` with `--dangerously-skip-permissions`, which is
why the rule does not read them. The sample was drawn from GitHub topic and star searches,
so the zero count says nothing about recall in other repositories. The pack states no
measurement of the rule's precision or recall.

---

## What this policy does not cover

- Workflow `run:` steps. CI-004 reads agent steps in workflows with an untrusted trigger.
  A step on a trigger that is not untrusted is not read by any rule.
- Named `package.json` scripts, Makefiles and shell scripts.
- Git hooks other than `.husky/` files, and hook managers other than husky.
- `cline`, `cursor-agent` or `agent`, and `q` outside the form `q chat --trust-all-tools`.
- A bypass set through configuration instead of a flag. AGCFG-005 reads project hooks, and
  CSDK-201 reads a bypass default mode in Claude settings.
- A spawn call whose binary or flag is not a literal.

---

## Recommendations beyond the fix

A script that needs an agent can name the tools it grants:

```json
{
  "scripts": {
    "summarize": "claude -p \"summarize\" --allowedTools Read"
  }
}
```

1. Do not start an agent CLI from an install lifecycle script or a git hook.
2. If a script must start one, grant it named tools instead of a bypass flag.
3. Run unattended agent jobs in a container or CI job with no access to the developer's
   credentials.
4. Review changes to `package.json` scripts, `.husky/` files and spawn calls in pull
   requests.

---

## Sources

- Liran Tal, "Weaponizing AI Coding Agents for Malware in the Nx Malicious Package Security
  Incident", Snyk, 27 August 2025.
  https://snyk.io/blog/weaponizing-ai-coding-agents-for-malware-in-the-nx-malicious-package/
  Retrieved 2026-11-04. Cited for the flags the post shows, the postinstall `telemetry.js`
  script and its use of `child_process`, and nothing more. It does not describe this rule,
  and the post gives no count of repositories.
- GHSA-cxm3-wv7p-598c, GitHub Security Advisory, nrwl/nx.
  https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c Retrieved 2026-11-04.
  Cited for the postinstall script and the incident and nothing more.
- npm CLI v10 scripts: https://docs.npmjs.com/cli/v10/using-npm/scripts Retrieved
  2026-11-04. Cited for when the lifecycle scripts run and nothing more.
- husky, Get started and How To: https://typicode.github.io/husky/get-started.html and
  https://typicode.github.io/husky/how-to.html Retrieved 2026-11-04. Cited for where a hook
  file lives and that a commit runs the example hook, and nothing more.
- Claude Code CLI reference: https://code.claude.com/docs/en/cli-reference Retrieved
  2026-11-04.
- Claude Code permissions: https://code.claude.com/docs/en/permissions Retrieved
  2026-11-04.
- Gemini CLI reference:
  https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/cli-reference.md
  Retrieved 2026-11-04.
- Codex CLI command reference:
  https://learn.chatgpt.com/docs/developer-commands?surface=cli Retrieved 2026-11-04.
- aider options: https://aider.chat/docs/config/options.html Retrieved 2026-11-04.

---
