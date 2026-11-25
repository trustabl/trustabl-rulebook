---
policy_id: agent_config_settings_local_committed
category: agent_config
topic: settings_local_committed
rules:
  - id: AGCFG-018
    severity: low
    confidence: 0.5
    scope: repo
    fix_type: config
references: [LLM06]
---

# Policy Rationale: Per-user Settings File in the Repository

**Policy ID:** `agent_config_settings_local_committed`  
**File:** `agent_config/settings_local_committed.yaml`  
**Rules:** AGCFG-018  
**Severities:** low  
**Fix types:** config  
**References:** LLM06 (Excessive Agency)

> **Verification status.** The Claude Code behavior below was read on 2026-11-25 as raw
> text from Anthropic's settings page (`code.claude.com/docs/en/settings.md`) and
> permissions page (`code.claude.com/docs/en/permissions.md`). The paper was read the same
> day in its arXiv abstract. **Not verified, and therefore not assumed:** whether a given
> file is tracked in git (the scan reads a directory, not the git index); the contents of
> a global excludes file or `.git/info/exclude`; and how older Claude Code versions treat
> the file.

---

## What this policy covers

Claude Code keeps a per-user, per-project settings file at `.claude/settings.local.json`.
This policy has one rule. **AGCFG-018** flags a scanned tree that holds that file when no
`.gitignore` from the scan root down to its folder ignores it. It is repo scope and fires
once per scan, attributed to the first such file.

---

## Rule-by-rule defense

### AGCFG-018 — Per-user Claude Code settings file is not git-ignored (Severity: low, Confidence: 0.5, Fix type: config)

**What we detect:** a `.claude/settings.local.json`, at any depth, that is not matched by
a pattern in the `.gitignore` files from the scan root down to its folder. Patterns are
applied from the outermost file inward, the last match wins, a `!` pattern re-includes,
and a pattern that matches a parent folder (`.claude/`) matches the file. Gated by
`repo_claude_settings_local_committed`.

**Why it is flaggable.** From the settings page, read 2026-11-25: the file is for "Personal
overrides for one project", and "Claude Code keeps it out of git when it creates the file;
if you create it by hand, add it to `.gitignore` yourself". From the permissions page: when
you choose "Yes, and don't ask again" for a Bash command, "Claude Code saves that approval
as an `allow` rule in `.claude/settings.local.json`". A copy that reaches the repository
therefore publishes one person's standing approvals to all who clone it.

**Real-world consequence:** the approvals in the file apply to a later user of the clone
once they trust the folder. The file can also list commands and hosts that identify one
person's work.

**The problem class in the literature.** *When Consent Outlives Context* (arXiv 2609.33910)
studies approvals that persist beyond the task and context that justified them, and shows
that replaying that residual authority raises attack success. The paper is cited for that
problem class and nothing more. It does not mention `settings.local.json`.

**Why severity is low:** The pack sets low and states no reasoning for it.

**Fix type — config:** `git rm --cached` the file and add it to `.gitignore`; move any rule
the team needs into the committed `.claude/settings.json` after review.

**Confidence 0.5:** the pack's explanation states these limits of the check:

- It reads the `.gitignore` files inside the scanned tree.
- Whether the file is tracked is not known from a directory scan, so an untracked file in
  a working copy is flagged like a tracked one.
- A global excludes file and `.git/info/exclude` are outside the tree and not read.
- The file's content is not judged here.

---

## What this policy does not cover

- Whether the file is tracked in git.
- Global excludes, `.git/info/exclude` and the `core.excludesFile` setting.
- The content of the file (AGCFG-012, AGCFG-016 and AGCFG-017 read its allow rules).
- Other per-user files, such as `CLAUDE.local.md`.

---

## Recommendations beyond the fix

```gitignore
.claude/settings.local.json
```

1. Add the entry to `.gitignore` before the first Claude Code session in a new repository.
2. Check `git status` for `.claude/` before you commit.
3. Put rules the team shares in `.claude/settings.json`, with exact commands.

---

## Sources

Retrieved 2026-11-25.

- Claude Code documentation, "Settings", `code.claude.com/docs/en/settings.md`. Cited for
  the purpose of the file and the `.gitignore` statement.
- Claude Code documentation, "Configure permissions", `code.claude.com/docs/en/permissions.md`.
  Cited for where a "don't ask again" approval is saved.
- *When Consent Outlives Context: Residual Authority Replay in Long-Lived Agents*, arXiv
  2609.33910. Cited for the problem class and nothing more.
