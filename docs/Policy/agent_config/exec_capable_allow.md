---
policy_id: agent_config_exec_capable_allow
category: agent_config
topic: exec_capable_allow
rules:
  - id: AGCFG-012
    severity: medium
    confidence: 0.6
    scope: repo
    fix_type: config
references: []
---

# Policy Rationale: Exec-capable Pre-approved Command Prefix

**Policy ID:** `agent_config_exec_capable_allow`  
**File:** `agent_config/exec_capable_allow.yaml`  
**Rules:** AGCFG-012  
**Severities:** medium  
**Fix types:** config  
**References:** none

> **Verification status.** The Claude Code behavior below was read on 2026-10-28 from
> Anthropic's permissions page (`code.claude.com/docs/en/permissions`). The description
> of `xargs` was read on the same day from its manual page (`man7.org`, `xargs(1)`).
> The paper cited below was read on 2026-10-28 in its arXiv HTML version. **Not
> verified, and therefore not assumed:** whether a narrower prefix such as
> `Bash(git status *)` lets a caller place options before the subcommand; how Claude
> Code versions older than the page read on that day treat these rules; whether
> permission modes other than the Manual mode the page describes change the result;
> and the behavior of programs other than `git`, `xargs` and `npx`.

---

## What this policy covers

Claude Code reads permission rules from a project's `.claude/settings.json` and
`.claude/settings.local.json`. A Bash rule in `permissions.allow` lets Claude run a
matching command without a prompt. The pack loads for each scan, because the files it
reads have no SDK import; the rule's own predicate does the gating.

This policy has one rule. **AGCFG-012** flags a committed settings file whose
`permissions.allow` list holds a Bash rule that is a bare `git`, `xargs` or `npx`
command followed by a trailing wildcard. It is repo scope and fires once per scan,
attributed to the first offending allow entry. Like AGCFG-011, it is not a pre-trust
rule: Claude Code applies a project's allow rules after the user accepts the folder.

---

## Rule-by-rule defense

### AGCFG-012 — Project settings pre-approve a command prefix that can run other programs (Severity: medium, Confidence: 0.6, Fix type: config)

**What we detect:** an entry in the `permissions.allow` list of a `.claude/settings.json`
or `.claude/settings.local.json`, at any depth in the repo, whose Bash pattern is one of
`git`, `xargs` or `npx` followed by `:*` or a space and `*`. For example `Bash(git:*)`,
`Bash(git *)`, `Bash(xargs *)` and `Bash(npx:*)` are flagged. Gated by
`repo_settings_allow_exec_capable_prefix`.

What is not flagged:

- An exact command such as `Bash(git status)` or `Bash(git diff --stat)`.
- A narrower prefix such as `Bash(git status *)` or `Bash(git diff:*)`.
- `find` and the exec wrappers `watch`, `setsid`, `ionice` and `flock`.
- A bare `Bash`, `Bash()` or `Bash(*)` allow entry. No rule in the pack flags one.
- Any other program.

How a finding is cancelled: the deny and ask lists of the settings files in the same
`.claude/` folder are pooled. A bare `Bash`, `Bash()`, `Bash(*)`, or a wildcard rule on
the same command cancels an allow entry for that command. A narrower deny such as
`Bash(git push *)` does not cancel it. A deny or ask rule in a different `.claude/`
folder of the repo does not. Each allow entry yields one internal hit that records the
file, the line and a reason naming the entry; the finding text is the rule's fixed
explanation.

**Why it is flaggable.** All behavior in this list is from Claude Code's permissions
page, read on 2026-10-28.

- Syntax: "The `:*` suffix is an equivalent way to write a trailing wildcard, so
  `Bash(ls:*)` matches the same commands as `Bash(ls *)`." The page also says "A `*` at
  the end, with a space before it, also matches the bare command."
- `git`: the page's wildcard examples show `Bash(git * main)` matching
  `git -c core.fsmonitor=<script> diff main`. It says that in a pattern like this the
  `*` stands in for the git subcommand and the options before it, that this includes
  `-c`, and that `-c` "makes git run a program you name".
- `xargs`: "Bare `xargs` is also stripped". For an invocation with flags, the page says
  "an invocation like `xargs -n1 grep pattern` is matched as an `xargs` command, so
  rules written for the inner command do not cover it." The `xargs(1)` manual page
  describes the program as "build and execute command lines from standard input".
- `npx`: "Development environment runners such as `direnv exec`, `devbox run`,
  `mise exec`, `npx`, and `docker exec` are not in the list" of stripped wrappers, and
  "Because these tools execute their arguments as a command, a rule like
  `Bash(devbox run *)` matches whatever comes after `run`".
- Where the rules live: the page says a project's permission settings can be checked
  into version control, and that a `.claude/settings.local.json` tracked in git is
  treated as repository-supplied.

A prefix rule on one of these three commands therefore approves the options or the
inner command a caller places after it, so it covers more than the command the author
had in mind. Claude Code applies a project's allow rules to a trusted folder, so the
call runs with no prompt.

**Why `find` and the exec wrappers are not flagged.** The same page says: "A prefix rule
like `Bash(watch *)` or `Bash(find *)` can't auto-approve the following commands, so in
Manual mode they prompt", and lists the exec wrappers `watch`, `setsid`, `ionice` and
`flock`, and `find` with an action such as `-exec`, `-delete`, `-rm` or `-fprint`. The
page documents a prompt for those forms, so the pack does not flag them.

**Real-world consequence:** if a committed `.claude/settings.json` allows `Bash(git:*)`,
a caller that chooses the arguments can run `git -c ...` with a program named in the
option, and the rule approves it with no prompt. An `npx` rule approves whichever package
command follows it. An `xargs` rule approves whichever command it is given.

**The problem class in the literature.** Yang, Zhang, Liu, Chen, Cao, Hooi and Zhang,
*From Approval to Abuse: Privilege Escalation Attacks on Harness-Protected Coding
Agents* (arXiv 2610.22987, submitted 16 October 2026), study allow rules that a harness
persists after a user approves them, in Claude Code and Codex CLI. They report that
untrusted repository context can steer an agent into requesting an overly broad allow
rule, and that Claude Code "abstracts over static command syntax": an unquoted
parameter such as `curl reports -v` induces the wildcard rule `curl reports *`. Their
conclusion says that approvals persisted as "context-free syntactic rules" create a
blind spot. The paper is cited for that problem class and nothing more. It studies rules
created at a prompt, not rules committed to a repository, and the paper's text does not
name `git`, `xargs` or `npx`. This policy does not attribute its prefix-matching or
command claims to the paper.

**Why severity is medium:** The pack sets medium and states no reasoning for it. The
costs the explanation names are that a prefix rule on one of these commands approves
more than the command the author had in mind, and that no prompt lets the developer
stop the call.

**Fix type — config:** the fix is an edit to the committed settings file. The pack's fix
is to replace the wildcard with exact commands that name the subcommand and arguments,
such as `Bash(git status)` and `Bash(git diff --stat)`; and to add the prefix to
`permissions.ask` or `permissions.deny` in the committed settings to make it prompt or be
refused for the whole team. The page says "Rules are evaluated in order: deny, then ask,
then allow." No tool source code changes.

**Confidence 0.6:** the pack's explanation states these limits of the check:

- It reads the permissions block of the `.claude/` settings files in the repo.
- A bare `Bash`, `Bash(*)` or same-prefix deny or ask rule in a settings file in the
  same `.claude/` folder cancels the finding; deny and ask rules in user or managed
  settings, hooks and prompt-time approvals are not seen.
- A narrower prefix such as `Bash(git status *)` and an exact command such as
  `Bash(git status)` are not flagged.
- A bare `Bash` or `Bash(*)` allow rule, and other programs that can run commands, are
  not judged.
- The command list is fixed.

The pack states no other limits for this rule.

---

## What this policy does not cover

- A committed bare `Bash`, `Bash()` or `Bash(*)` allow entry. No rule flags one.
- Deny and ask rules in user or managed settings, hooks and prompt-time approvals.
- Whether the folder has been trusted. The check reads the repo's settings files.
- Programs other than `git`, `xargs` and `npx`, including `find` and the exec wrappers.
- A narrower prefix, which is not flagged.
- A settings file that is not valid JSON. It is skipped.

---

## Recommendations beyond the fix

Committed rules that name exact commands:

```json
{
  "permissions": {
    "allow": [
      "Bash(git status)",
      "Bash(git diff --stat)"
    ]
  }
}
```

A committed rule that makes a prefix prompt for the whole team:

```json
{
  "permissions": {
    "ask": [
      "Bash(git:*)"
    ]
  }
}
```

1. Name the subcommand and its arguments in each committed Bash allow rule.
2. Use `permissions.ask` or `permissions.deny` in the committed settings for a prefix
   the team should be asked about or refused.
3. Check `.claude/settings.local.json` before you commit it, since a rule saved from a
   prompt lands there.
4. Review changes to `.claude/settings.json` in pull requests.

---

## Sources

- Claude Code documentation, "Configure permissions", `code.claude.com/docs/en/permissions`,
  retrieved 2026-10-28. The source of the Claude Code behavior above.
- `xargs(1)` manual page, `man7.org/linux/man-pages/man1/xargs.1.html`, retrieved
  2026-10-28.
- Xianglin Yang, Yechao Zhang, Jiahao Liu, Yulin Chen, Yuxin Cao, Bryan Hooi and Jiaheng
  Zhang, *From Approval to Abuse: Privilege Escalation Attacks on Harness-Protected Coding
  Agents*, arXiv 2610.22987 (v1, 16 October 2026). Cited for the problem class.
- Background, not a basis for the rule: GitHub security advisory GHSA-qgqw-h4xq-7w8w
  (CVE-2026-24887), "Command Injection in find Command Bypasses User Approval Prompt",
  published 2026-02-03 on `anthropics/claude-code`. It concerns how Claude Code parsed a
  `find` command, not committed allow rules.
