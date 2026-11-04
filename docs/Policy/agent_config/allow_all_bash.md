---
policy_id: agent_config_allow_all_bash
category: agent_config
topic: allow_all_bash
rules:
  - id: AGCFG-016
    severity: high
    confidence: 0.7
    scope: repo
    fix_type: config
references: []
---

# Policy Rationale: Committed Allow Rule That Approves All Bash Commands

**Policy ID:** `agent_config_allow_all_bash`  
**File:** `agent_config/allow_all_bash.yaml`  
**Rules:** AGCFG-016  
**Severities:** high  
**Fix types:** config  
**References:** none

> **Verification status.** The Claude Code behavior below was read on 2026-11-04 from
> Anthropic's permissions page (`code.claude.com/docs/en/permissions`). No advisory, paper
> or vendor statement about allow-all Bash rules was found, so this policy cites the vendor
> page alone. **Not verified, and therefore not assumed:** how Claude Code reads `Bash()`
> (empty parentheses), `Bash(:*)` and `Bash( *)`, which the page does not document; how
> Claude Code versions older than the page read on that day treat these rules; and whether a
> permission mode other than the Manual mode the page describes changes the result.

---

## What this policy covers

Claude Code reads permission rules from a project's `.claude/settings.json` and
`.claude/settings.local.json`. A Bash rule in `permissions.allow` lets Claude run a matching
command without a prompt. The pack loads for each scan, because the files it reads have no
SDK import; the rule's own predicate does the gating.

This policy has one rule. **AGCFG-016** flags a committed allow entry that matches all Bash
commands. It is repo scope and fires once per scan, attributed to the first path-sorted
offending file and line. AGCFG-012 flags `git`, `xargs` and `npx` prefix entries and does not
judge a bare `Bash` or `Bash(*)` entry, so no entry fires both rules.

---

## Rule-by-rule defense

### AGCFG-016 — Project settings auto-approve all Bash commands (Severity: high, Confidence: 0.7, Fix type: config)

**What we detect:** in each `.claude/settings.json` or `.claude/settings.local.json`, at any
depth in the repo, a `permissions.allow` entry whose text, trimmed of surrounding space, is
`Bash` or `Bash(*)`. Gated by `repo_settings_allow_all_bash`. Settings files in test-fixture
folders are judged like any other.

A bare `Bash` or `Bash(*)` entry in `permissions.deny` or `permissions.ask` of a settings
file in the same `.claude/` folder cancels the finding. The deny and ask rules of the
`settings.json` and `settings.local.json` in one folder are pooled.

What is not flagged:

- `Bash()`, `Bash(:*)` and `Bash( *)`, which the permissions page does not document.
- A prefix or exact entry such as `Bash(git *)` or `Bash(git status)`.
- An entry for another tool.
- An entry cancelled by a bare `Bash` or `Bash(*)` deny or ask rule in the same `.claude/`
  folder. A narrower deny or ask rule such as `Bash(rm *)` does not cancel it, and a deny or
  ask rule in another `.claude/` folder does not cancel it.
- A settings file that is not valid JSON.
- User settings, managed settings, hooks, sandbox auto-approval and prompt-time approvals.

**Why it is flaggable.** All behavior in this list is from the permissions page, read on
2026-11-04.

- What the entry matches. The page says "`Bash(*)` is equivalent to `Bash` and matches all
  Bash commands. As a deny rule, both forms remove the tool from Claude's context." Its table
  for matching all uses of a tool reads "`Bash` | Matches all Bash commands".
- How rules combine. "Rules are evaluated in order: deny, then ask, then allow. The first
  match in that order determines the outcome, and rule specificity doesn't change the
  order." It adds "An allow rule can't carve an exception out of a deny rule. The same
  precedence applies between ask and allow: a matching ask rule prompts even when a more
  specific allow rule also matches the same call." So a narrower deny or ask rule leaves the
  rest of the commands matched by the allow entry, and a bare deny or ask rule does not.
- That a repository can carry it. The page says permission settings can be checked into
  version control to share with developers in an organization.
- When it applies. The page says Claude Code shows the trust dialog in interactive
  sessions, and that a `claude -p` run or an SDK session does not show it. For
  `.claude/settings.local.json` it says "When the file is tracked in git, or `.claude` is a
  symlink, Claude Code treats it as repository-supplied instead and holds its rules until you
  trust the folder."

A committed `Bash` or `Bash(*)` allow entry therefore lets Claude run any shell command that
no deny or ask rule matches, without a prompt, for the people who clone the repository.

**Real-world consequence:** a shell command that the developer would have reviewed in a
prompt runs without one. The pack's explanation states this and does not state a figure for
how many repositories do it.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Fix type — config:** the fix is an edit to the committed settings file. The pack's fix
replaces the entry with exact commands such as `Bash(git status)`, and to make shell commands
prompt for the whole team adds `Bash` to `permissions.ask`. The pack's fix also states that
with sandboxing enabled and `autoAllowBashIfSandboxed` at its default of `true`, sandboxed
Bash commands still run without a prompt, per the permissions page.

**Confidence 0.7:** the pack's explanation states these limits of the check:

- It reads the permissions block of `.claude/` settings files in the repo, at any depth, and
  judges files in test-fixture folders like any other.
- A bare `Bash` or `Bash(*)` deny or ask rule in the same `.claude/` folder cancels the
  finding; a narrower rule does not.
- Deny and ask rules in user or managed settings, hooks, sandbox auto-approval and
  prompt-time approvals are not seen. The permissions page says that with sandboxing enabled
  and `autoAllowBashIfSandboxed` at its default of `true`, sandboxed Bash commands run
  without prompting "even if your permissions include a bare `Bash` ask rule".
- `Bash()`, `Bash(:*)` and `Bash( *)` are not judged.
- A settings file that is not committed is not told apart from one that is when the scan
  target is a local folder. The page says an untracked `.claude/settings.local.json` is
  "normally your own file".

On 2026-11-04 the detector's logic was run as a prototype over the `.claude/settings*.json`
files of 10 public repositories (11 files). It found one entry, in a settings file under an
evaluation-fixtures directory of one repository, which is why the pack states that files in
test-fixture folders are judged. The pack states no measurement of the rule's precision or
recall.

---

## What this policy does not cover

- Prefix entries for `git`, `xargs` and `npx` (AGCFG-012).
- A project default permission mode set to `bypassPermissions` (CSDK-201).
- A skill that grants unrestricted `Bash` in `allowed-tools` (CSKILL-001).
- User settings, managed settings, hooks and sandbox auto-approval.
- Whether a settings file is tracked in git.

---

## Recommendations beyond the fix

Exact commands in the committed settings, and a prompt for the rest:

```json
{
  "permissions": {
    "allow": ["Bash(git status)", "Bash(npm test)"],
    "ask": ["Bash"]
  }
}
```

1. Name exact commands in `permissions.allow` instead of all of Bash.
2. Add `Bash` to `permissions.ask` in the committed file so the rest prompts for the team.
   With sandboxing enabled and `autoAllowBashIfSandboxed` at its default of `true`, the
   permissions page says sandboxed Bash commands run without prompting even if your
   permissions include a bare `Bash` ask rule, so the ask entry does not prompt for them.
3. Check `.claude/settings.local.json` before you commit it.
4. Review changes to `.claude/settings.json` in pull requests.

---

## Sources

- Claude Code permissions: https://code.claude.com/docs/en/permissions Retrieved 2026-11-04.
  Cited for how the `Bash` and `Bash(*)` rules match, how deny, ask and allow rules combine,
  and when a project's allow rules apply, and nothing more. The page does not describe this
  rule.

---
