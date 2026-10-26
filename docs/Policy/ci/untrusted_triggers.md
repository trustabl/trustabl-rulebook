---
policy_id: ci_untrusted_triggers
category: ci
topic: untrusted_triggers
rules:
  - id: CI-001
    severity: critical
    confidence: 0.7
    scope: repo
    fix_type: config
  - id: CI-002
    severity: critical
    confidence: 0.75
    scope: repo
    fix_type: config
references: []
---

# Policy Rationale: Coding Agents on Untrusted GitHub Actions Triggers

**Policy ID:** `ci_untrusted_triggers`  
**File:** `ci/untrusted_triggers.yaml`  
**Rules:** CI-001, CI-002  
**Severities:** critical, critical  
**Fix types:** config, config  
**References:** none

---

## What this policy covers

GitHub Actions workflows in the repo-root `.github/workflows` directory
(`applies_to: github_actions`, `scope: repo`) that run a coding agent on an
event any GitHub user can cause. The pack's policy description names the
events: issues, issue comments, pull request review comments, discussions,
discussion comments and `pull_request_target`. It says the pack loads on each
scan and each rule's predicate gates it, and that one finding is reported for
each step that runs an offending agent.

The coding agents are the ones the CI-001 explanation names:
`claude-code-action`, `claude-code-base-action`, `run-gemini-cli`,
`codex-action`, and the `claude`, `gemini`, `codex`, `cline` and `aider` CLIs.

- **CI-001** matches an agent job on one of those events with no actor gate.
  Predicate: `repo_ci_agent_untrusted_trigger_ungated`.
- **CI-002** matches the same ungated job when it also holds a write token or
  secrets beyond the model key. Predicate:
  `repo_ci_agent_untrusted_trigger_privileged`.

---

## Why untrusted triggers are a distinct concern for coding agents in CI

The CI-001 explanation says the event's title, body and comments reach the
agent as input, so any user who can cause the event can give the agent
instructions. The events in this policy are ones the policy description says
any GitHub user can cause, such as opening an issue or posting a comment.

The explanation names the controls that limit who that user is: an `if:` on
the job, the step or a job it needs that restricts `author_association` to
`OWNER`, `MEMBER` or `COLLABORATOR` or names the allowed actors, and the
write-access check that `claude-code-action` and `codex-action` make
themselves. The claude-code-action security documentation (`docs/security.md`
in anthropics/claude-code-action) says the action checks that the triggering
user has write access to the repository for issue, pull request, comment and
review events, and that `allowed_non_write_users` bypasses that requirement.
The codex-action `action.yml` describes `allow-users` as a list of GitHub
usernames who can run the action, or `'*'` to allow all users.

The CI-002 explanation covers what an instruction from the event can reach. If
the job's `GITHUB_TOKEN` can write to the repository, or the job references a
secret beyond the model key, the explanation says instructions from the
triggering event can then act with that token or read that secret.

---

## Rule-by-rule defense

### CI-001 — Agent step runs on an untrusted trigger without an actor gate (Severity: critical, Confidence: 0.7, Fix type: config)

**What we detect:**  
A job that runs one of the coding agents above, in a workflow triggered by one
of the events above, where no `if:` on the job, the step or a job it needs
restricts `author_association` to `OWNER`, `MEMBER` or `COLLABORATOR` or names
the allowed actors, and the action's own write-access check is absent or
switched off. The pack treats that check as switched off when
`allowed_non_write_users` or `allowed_bots` is set to `'*'`, or when
`allow-users` is set to `'*'`. Predicate:
`repo_ci_agent_untrusted_trigger_ungated`.

**Why it is flaggable:**  
The pack's explanation says the event's title, body and comments reach the
agent as input, so any user who can cause the event can give the agent
instructions. With no actor gate, nothing in the workflow limits who that user
is.

**Real-world consequence:**  
If a workflow runs `claude-code-action` on `issues: opened` with
`allowed_non_write_users: "*"`, a user without write access can open an issue
whose body asks the agent for something other than the task the workflow set,
and the agent receives that body as input. What the agent can then do depends
on the token, secrets and tools the job gives it, which CI-002 and the
[agent_hardening](agent_hardening.md) rules cover.

**Why severity is critical:**  
The pack sets critical and states no reasoning for it. The costs the
explanation names are that any user who can cause the event can give the agent
instructions.

**Fix type — config:**  
The pack's fix is an edit to the workflow file, not to agent or tool source
code. Add a job-level `if:` that admits trusted actors, for example
`contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)`.
For `claude-code-action` and `codex-action`, keep the built-in write-access
check by removing `'*'` from `allowed_non_write_users`, `allowed_bots` and
`allow-users`.

**Confidence 0.7:**  
The pack sets 0.7 for this rule and states these limits: "an if: expression is
matched as text and is not evaluated, so a condition that joins an allow-list
with another branch (A || allow-list) counts as gated. An actor check made in
an earlier step, an environment with required reviewers, and a label gate are
not recognised. A reusable workflow is followed one hop when it is a local
file; remote reusable workflows and composite actions are not followed."

### CI-002 — Ungated agent job holds a write token or extra secrets (Severity: critical, Confidence: 0.75, Fix type: config)

**What we detect:**  
An agent job that meets the CI-001 condition and also holds authority beyond
the model key: its `GITHUB_TOKEN` has `write-all` or write access to
`contents`, `pull-requests`, `actions` or `packages`; it references a secret
outside the agent's model-key input; or it passes `secrets: inherit` to a
reusable workflow. Predicate: `repo_ci_agent_untrusted_trigger_privileged`.

**Why it is flaggable:**  
The pack's explanation says instructions from the triggering event can then
act with that token or read that secret. CI-001 is about who can instruct the
agent; CI-002 is about what that instruction can reach beyond the model key.

**Real-world consequence:**  
If the CI-001 workflow above also declares `permissions: contents: write` and
sets `NPM_TOKEN` from a secret in the agent step's environment, an issue body
can ask an agent that has shell access to push a commit with the job's token,
or to print the publishing token from its environment.

**Why severity is critical:**  
The pack sets critical and states no reasoning for it. The costs the
explanation names are that instructions from the triggering event can act with
the job's write token or read the extra secret.

**Fix type — config:**  
The pack's fix is an edit to the workflow file. Give the agent job a read token
(`permissions: contents: read`) and pass it the model key alone. Move any step
that needs write access or another secret into a separate job that runs after a
trusted-actor check.

**Confidence 0.75:**  
The pack sets 0.75 for this rule and states these limits: "permissions are
read from the job, then the workflow, then the calling job; when none of them
declares a permissions block nothing is flagged, because the repository default
is not visible. A secret counts as the model key by where it is referenced (the
agent step's model-key input, or a model-key environment variable such as
ANTHROPIC_API_KEY), not by its name. Secrets passed to a remote reusable
workflow are not seen. The write scopes counted are contents, pull-requests,
actions and packages; other scopes such as id-token are not counted."

---

## What this policy does not cover

- **Other triggers.** The untrusted events are the six the policy description
  names. A job in a workflow with none of them among its triggers, such as a
  workflow on `workflow_run`, is not evaluated by either rule.
- **Other agents.** An agent step is a `uses:` of
  `anthropics/claude-code-action` (with its base-action forms),
  `google-github-actions/run-gemini-cli` or `openai/codex-action`, or a `run:`
  command whose command word is `claude`, `gemini`, `codex`, `cline` or
  `aider`, directly or through `npx`, `bunx`, `pnpm`, `yarn` or `npm`. Another
  action that runs a model is not recognised.
- **Gates the rules do not recognise.** An actor check in an earlier step, an
  environment with required reviewers and a label gate (CI-001 limits).
- **Gates counted without being evaluated.** An `if:` that joins an allow-list
  with another branch counts as gated (CI-001 limits). In a workflow whose sole
  untrusted trigger is `pull_request_target`, a check that the pull request's
  head repository is the base repository, or that it is not a fork, also counts
  as a gate.
- **Expressions in bypass inputs.** A `${{ }}` expression in
  `allowed_non_write_users`, `allowed_bots` or `allow-users` is treated like
  `'*'`, so the action's own check counts as switched off.
- **Built-in checks of other agents.** `run-gemini-cli`, the base action and
  the CLIs are not credited with a built-in check, so only an `if:` gate counts
  for them.
- **Gates through status functions.** A job whose `if:` calls a status-check
  function such as `failure()` or `cancelled()` does not inherit a gate from the
  jobs it needs.
- **Repository-default permissions.** When no `permissions` block is declared,
  CI-002 flags nothing for the token (CI-002 limits).
- **`GITHUB_TOKEN` references.** A reference to `secrets.GITHUB_TOKEN` is not
  counted as an extra secret; the token's authority is read from the
  `permissions` block.
- **Matrix values and unparsed files.** `strategy.matrix` is not evaluated, and
  a workflow file that fails to parse produces no finding.
- The pack states no other limits for either rule.

---

## Recommendations beyond the fix

The example is a skeleton, not a complete setup. It shows the controls the
rules in this policy and in [agent_hardening](agent_hardening.md) ask for. The
claude-code-action setup documentation says the default GitHub App
authentication path requires `id-token: write`, so the job declares it, with
`contents: read` as in the action's FAQ. The action's own examples for
responding to issues and pull requests declare more: its setup guide shows
`contents`, `pull-requests` and `issues` at `write`. Add what the workflow
needs after checking the action's current setup guide. On a job with no actor
gate, CI-002 counts `contents` and `pull-requests` at `write` as a write token;
it does not count `issues` or `id-token`.

```yaml
name: claude-on-comment
on:
  issue_comment:
    types: [created]
permissions:
  contents: read
jobs:
  answer:
    if: contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: step-security/harden-runner@v2
        with:
          egress-policy: block
          allowed-endpoints: >
            api.anthropic.com:443
            api.github.com:443
            github.com:443
      - uses: actions/checkout@v6
        with:
          persist-credentials: false
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          claude_args: --allowedTools "Read,Bash(npm test)"
```

1. Keep the built-in write-access check of `claude-code-action` and
   `codex-action` and add the job-level `if:` as well. The pack recognises
   either one as a gate, and the `if:` also covers agents with no built-in
   check.
2. Leave `github_token` out unless a custom GitHub App needs it. The
   claude-code-action usage documentation describes the input as for
   connecting a custom GitHub App. Where `allowed_non_write_users` or a custom
   app is used, the security documentation says to pass
   `github_token: ${{ secrets.GITHUB_TOKEN }}`, which is scoped to the job's
   declared permissions and expires when the job completes, and advises against
   a personal access token.
3. Declare a `permissions` block on each agent job. CI-002 cannot see the
   repository default, so a job with no block is not checked for a write token.
4. Put steps that need write access or other secrets in a separate job that
   runs after a trusted-actor check, as the CI-002 fix says.
5. The example also applies the fixes from
   [agent_hardening](agent_hardening.md): `harden-runner` with
   `egress-policy: block` as the first step, `persist-credentials: false` on the
   checkout, and an allow-list of exact commands. That doc covers the endpoint
   list.
