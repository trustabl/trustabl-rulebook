---
policy_id: ci_agent_hardening
category: ci
topic: agent_hardening
rules:
  - id: CI-003
    severity: high
    confidence: 0.7
    scope: repo
    fix_type: config
  - id: CI-004
    severity: high
    confidence: 0.8
    scope: repo
    fix_type: config
  - id: CI-005
    severity: medium
    confidence: 0.5
    scope: repo
    fix_type: config
references: []
---

# Policy Rationale: Hardening of Coding-Agent Jobs on Untrusted GitHub Actions Triggers

**Policy ID:** `ci_agent_hardening`  
**File:** `ci/agent_hardening.yaml`  
**Rules:** CI-003, CI-004, CI-005  
**Severities:** high, high, medium  
**Fix types:** config, config, config  
**References:** none

---

## What this policy covers

Coding-agent jobs in GitHub Actions workflows (`applies_to: github_actions`,
`scope: repo`) that run on an event any GitHub user can cause, with or without
an actor gate. The triggers and the agents are the ones listed in
[untrusted_triggers](untrusted_triggers.md). The pack's policy description says
the pack loads on each scan and each rule's predicate gates it. It also says
one finding is reported for each step that runs an offending agent, and for
CI-003 for each `actions/checkout` step in an offending agent job.

- **CI-003** matches an agent job whose `actions/checkout` step does not set
  `persist-credentials: false`. Predicate:
  `repo_ci_agent_checkout_persists_credentials`.
- **CI-004** matches an agent step whose tool allow-list or flags grant
  unrestricted shell. Predicate: `repo_ci_agent_unrestricted_shell`.
- **CI-005** matches an agent step with shell or web access and no earlier
  egress block in the job. Predicate: `repo_ci_agent_no_egress_restriction`.

---

## Why job hardening is a distinct concern for coding agents in CI

The pack's policy description says the content of the event is untrusted input
whether or not the job has an actor gate. The rules in
[untrusted_triggers](untrusted_triggers.md) ask who can trigger the agent;
these rules ask what an agent steered by the event's content can reach on the
runner.

The explanations name three things it can reach. CI-003: a checkout that
configured a credential in the local git config. CI-004: a shell, where text
from the triggering event can make the agent run arbitrary commands with the
job's token and secrets. CI-005: the network, where the pack's explanation says
nothing in the workflow stops the agent sending a token or secret it has read
to an outside host.

---

## Rule-by-rule defense

### CI-003 — Checkout persists credentials in an agent job (Severity: high, Confidence: 0.7, Fix type: config)

**What we detect:**  
A job that runs a coding agent on an untrusted trigger and checks out the
repository with `actions/checkout` without setting
`persist-credentials: false`. Predicate:
`repo_ci_agent_checkout_persists_credentials`.

**Why it is flaggable:**  
The `actions/checkout` `action.yml` describes `persist-credentials` as
"Whether to configure the token or SSH key with the local git config", with a
default of `true`. The pack's explanation says commands run by an agent
steered by the event's content run on a runner where that configuration was
applied.

**Real-world consequence:**  
If the agent can run shell commands, an instruction in an issue body can get it
to run git commands that use the configured token, or to read the local git
config where the checkout stored it.

**Why severity is high:**  
The pack sets high and states no reasoning for it. The costs the explanation
names are that commands run by an agent steered by the event's content run on a
runner where the checkout's credential configuration was applied.

**Fix type — config:**  
The pack's fix is an edit to the workflow file. Set
`persist-credentials: false` on each `actions/checkout` step in the agent job.
If the agent must push, give it a narrowly scoped token through the action's own
input instead of the checkout's stored credential.

**Confidence 0.7:**  
The pack sets 0.7 for this rule and states these limits: "it reads
persist-credentials on actions/checkout steps in the same job as the agent
step. A false value (boolean or the string) is the sole value treated as safe,
so an expression counts as persisting. Credentials set up another way, such as
git config in a run step or a token passed to an action, are not seen."

### CI-004 — Agent step grants unrestricted shell (Severity: high, Confidence: 0.8, Fix type: config)

**What we detect:**  
A coding agent on an untrusted trigger whose tool allow-list grants `Bash` with
no pattern, `Bash(*)`, or a pattern that starts with a shell, interpreter or
download tool (`bash`, `sh`, `zsh`, `cmd`, `powershell`, `pwsh`, `python`,
`python3`, `node`, `curl`, `wget`, `nc`, `ncat`); or a step that skips
approvals or the sandbox (`--dangerously-skip-permissions`,
`--permission-mode bypassPermissions`, Gemini `--yolo` or a bare
`run_shell_command`, Codex `--dangerously-bypass-approvals-and-sandbox`,
`sandbox: danger-full-access` or `safety-strategy: unsafe`). Predicate:
`repo_ci_agent_unrestricted_shell`.

**Why it is flaggable:**  
The pack's explanation says text from the triggering event can then make the
agent run arbitrary commands on the runner with the job's token and secrets.
The codex-action `action.yml` describes `safety-strategy: unsafe` as not
trying to restrict Codex's privileges at all.

**Real-world consequence:**  
If the allow-list grants `Bash` with no pattern and an issue body asks the
agent to download and run a script, the agent can run it on the runner, where
the job's token and any secrets in its environment are within reach.

**Why severity is high:**  
The pack sets high and states no reasoning for it. The costs the explanation
names are arbitrary commands run on the runner with the job's token and
secrets.

**Fix type — config:**  
The pack's fix is an edit to the workflow file. Allow the exact commands the
task needs, for example `Bash(npm test)` or `run_shell_command(git diff)`, and
remove any flag that skips approvals or the sandbox. Keep Codex on its default
safety strategy with a `workspace-write` sandbox.

**Confidence 0.8:**  
The pack sets 0.8 for this rule and names no false-positive or false-negative
scenarios for it.

### CI-005 — Agent job with shell or web access has no egress restriction (Severity: medium, Confidence: 0.5, Fix type: config)

**What we detect:**  
A coding agent on an untrusted trigger that can run shell commands or fetch
URLs (a `Bash`, `WebFetch` or `WebSearch` grant, a Gemini shell or web tool, or
a Codex full-access sandbox), with no `step-security/harden-runner` step with
`egress-policy: block` before it in the job. Predicate:
`repo_ci_agent_no_egress_restriction`.

**Why it is flaggable:**  
The pack's explanation says that if the event's content gets the agent to read
a token or secret, nothing in the workflow stops it sending the value to an
outside host. It calls this an inference from the workflow file alone. The
harden-runner `action.yml` describes `egress-policy` as the policy for
outbound traffic, `audit` or `block`, and `allowed-endpoints` as the endpoints
allowed when the policy is `block`.

**Real-world consequence:**  
If an issue body gets an agent with a `WebFetch` grant and a shell grant to
read a secret from its environment, the agent can send the value to a host the
issue body names, and no step in the job blocks the connection.

**Why severity is medium:**  
The pack sets medium and states no reasoning for it. The costs the explanation
names are a token or secret the agent has read being sent to an outside host.

**Fix type — config:**  
The pack's fix is an edit to the workflow file. Add
`step-security/harden-runner` as the first step of the agent job with
`egress-policy: block` and `allowed-endpoints` limited to the model API and
GitHub, or run the agent on a runner whose network is restricted.

**Confidence 0.5:**  
The pack sets 0.5 for this rule and states these limits: "network controls
outside the workflow file, such as a self-hosted runner's network policy or
organization settings, are not visible. The harden-runner step is recognised by
its action name and egress-policy: block, and must come before the agent step
in the same job. An agent step with no tool configuration is counted as having
neither shell nor fetch access."

---

## What this policy does not cover

- **Other triggers and agents.** The triggers and agents are the sets listed in
  [untrusted_triggers](untrusted_triggers.md#what-this-policy-does-not-cover).
- **Checkout steps in other jobs.** CI-003 reads the checkout steps in the agent
  step's job only (CI-003 limits).
- **Credentials set up another way.** Git config in a run step or a token
  passed to an action is not seen by CI-003 (CI-003 limits).
- **Where grants are read.** For `claude-code-action` and the base action:
  `--allowedTools` or `--allowed-tools`, `--dangerously-skip-permissions` and
  `--permission-mode` in `claude_args`, and `permissions.allow` and
  `permissions.defaultMode` in `settings`. For `run-gemini-cli`: `tools.core`
  and `tools.allowed` in `settings`. For `codex-action`: `sandbox`,
  `safety-strategy` and `codex-args`. For the `claude`, `gemini` and `codex`
  CLIs: flags on the command. Grants for the `cline` and `aider` CLIs are not
  read.
- **Settings from a file.** `settings` is read when its value is a JSON object.
  The claude-code-action `action.yml` says `settings` takes a JSON string or a
  path to a settings file; a path is not followed.
- **Bash patterns with another first word.** CI-004 checks the first word of a
  `Bash(...)` or `run_shell_command(...)` pattern against the list above. A
  pattern that starts with another command is not flagged by CI-004, whatever
  that command can do.
- **Restricted grants and CI-005.** CI-005 counts any `Bash` grant as shell
  access, restricted or not, so an exact grant such as `Bash(npm test)` still
  needs the egress block to clear CI-005.
- **harden-runner without the input.** CI-005 reads the step's
  `egress-policy` input and compares it with `block`. A `harden-runner` step
  that leaves the input unset is not recognised.
- **Network controls outside the workflow file** (CI-005 limits).
- The pack states no other limits for these rules.

---

## Recommendations beyond the fix

```yaml
name: codex-on-comment
on:
  issue_comment:
    types: [created]
permissions:
  contents: read
jobs:
  answer:
    runs-on: ubuntu-latest
    steps:
      - uses: step-security/harden-runner@v2
        with:
          egress-policy: block
          allowed-endpoints: >
            api.openai.com:443
            api.github.com:443
            github.com:443
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
      - uses: openai/codex-action@v1
        with:
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
          sandbox: workspace-write
          prompt: |
            Answer this comment about the repository:
            ${{ github.event.comment.body }}
```

1. Leave `allow-users` unset so `codex-action` keeps its write-access check;
   this example relies on that check as its actor gate. The `claude-code-action`
   example in [untrusted_triggers](untrusted_triggers.md#recommendations-beyond-the-fix)
   uses an `if:` gate and the same three hardening steps.
2. Leave `safety-strategy` unset. CI-004 flags `safety-strategy: unsafe`.
3. Run `harden-runner` with `egress-policy: audit` first and review the
   endpoints the job contacts before switching to `block`; the endpoint list
   above follows the pack's fix (the model API and GitHub) and the action may
   need others.
4. Set `persist-credentials: false` on each checkout in the agent job, not
   the first one alone; CI-003 reads each of them.
5. Grant exact commands. An exact `Bash(...)` grant clears CI-004, and CI-005
   still asks for the egress block because the grant is shell access.
