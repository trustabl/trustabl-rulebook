---
policy_id: agent_config_unscoped_allow
category: agent_config
topic: unscoped_allow
rules:
  - id: AGCFG-017
    severity: high
    confidence: 0.6
    scope: repo
    fix_type: config
references: [LLM06]
---

# Policy Rationale: Pre-approved Interpreter Prefix or Unscoped Tool

**Policy ID:** `agent_config_unscoped_allow`  
**File:** `agent_config/unscoped_allow.yaml`  
**Rules:** AGCFG-017  
**Severities:** high  
**Fix types:** config  
**References:** LLM06 (Excessive Agency)

> **Verification status.** The Claude Code behavior below was read on 2026-11-25 as raw
> text from Anthropic's permissions page (`code.claude.com/docs/en/permissions.md`) and
> the permission-modes page (`code.claude.com/docs/en/permission-modes.md`). The
> HarnessSecurity paper was read the same day in its arXiv HTML version. **Not verified,
> and therefore not assumed:** how Claude Code versions older than those pages treat
> these rules; whether a prompt appears for some `python`, `node`, `bash` or `sh` forms
> in ways the pages do not describe; how permission modes other than the Manual mode
> change the result; and whether any of these entries occurs in real repositories beyond
> the public sample listed in the Trustabl report for this batch.

---

## What this policy covers

Claude Code reads permission rules from a project's `.claude/settings.json` and
`.claude/settings.local.json`. An entry in `permissions.allow` lets Claude make the
matching call without a prompt. The pack loads for each scan, because the files it reads
have no SDK import; the rule's own predicate does the gating.

This policy has one rule. **AGCFG-017** flags an allow entry that approves a whole class
of calls. It is repo scope and fires once per scan, attributed to the first offending
entry. Like AGCFG-011 and AGCFG-012, it is not a pre-trust rule: Claude Code applies a
project's allow rules after the user accepts the folder.

---

## Rule-by-rule defense

### AGCFG-017 — Project settings pre-approve an interpreter prefix or an unscoped tool (Severity: high, Confidence: 0.6, Fix type: config)

**What we detect:** an entry in `permissions.allow` of a `.claude/settings.json` or
`.claude/settings.local.json`, at any depth in the repo, that is one of:

- a Bash rule that is a bare `python`, `python3`, `node`, `bash`, `sh`, `curl` or `wget`
  command followed by `:*` or a space and `*` (`Bash(python:*)`, `Bash(curl *)`);
- `WebFetch` with no domain, or `WebFetch(*)`;
- `Edit` or `Write` with no path, or with `(*)`;
- an `mcp__` entry that names a server and no tool: `mcp__github` or `mcp__github__*`.

Gated by `repo_settings_allow_unscoped_grant`.

What is not flagged: an exact command such as `Bash(python scripts/lint.py)`; a narrower
prefix such as `Bash(python -m pytest *)`; `WebFetch(domain:docs.python.org)`;
`Edit(src/**)`; `mcp__github__get_issue`; a bare `Bash` or `Bash(*)` (AGCFG-016); the
`git`, `xargs`, `npx`, `env`, `sed` and `awk` prefixes (AGCFG-012); a WebFetch rule for a
named host (AGCFG-011); and any other interpreter, such as `ruby`, `perl` or `uvx`.

How a finding is cancelled: the deny and ask lists of the settings files in the same
`.claude/` folder are pooled. A deny or ask rule of the same shape cancels the matching
allow entry; a bare `Bash` deny or ask covers all the Bash prefixes above. A narrower deny
such as `Bash(curl http://example.com/*)` does not cancel the entry. A rule in a
different `.claude/` folder does not.

**Why it is flaggable.** All behavior in this list is from the Claude Code pages read on
2026-11-25.

- WebFetch: the permissions page's rule table has the row "`WebFetch` | Matches all web
  fetch requests".
- Edit and Write: the page says an `Edit(*)`, `Write(*)` or `NotebookEdit(*)` allow rule pre-approves the
  tool inside the working directories, and that the bare tool name, such as `Edit`, covers
  paths outside them too. The same
  page says some calls are still not pre-approved, such as writes to protected paths.
- MCP: "`mcp__puppeteer` matches any tool provided by the `puppeteer` server", and
  `mcp__puppeteer__*` "also matches all tools from the `puppeteer` server".
- Bash text matching: a Bash rule "match[es] the whole command text", and the page shows
  that a deny rule such as `Bash(curl *)` does not match `sh -c 'curl https://example.com'`
  or `/usr/bin/curl`, so a command can be run in a form that a rule for the inner command
  does not cover. It also says "If Bash is allowed, Claude can still use `curl`, `wget`,
  or other tools to reach any URL."
- Interpreters: the page says its file-path rules "don't apply to arbitrary subprocesses
  that read or write files indirectly, like a Python or Node script that opens files
  itself". A prefix rule on an interpreter names the program that runs and leaves the
  program text to the caller; the pages do not describe a prompt for that form.
- The HarnessSecurity paper (below) describes a trial in which an unauthorized checker
  that the harness gate had rejected was run "through an allowed Python interpreter".

**Protected paths.** The permission-modes page says that `permissions.allow` rules do not
pre-approve writes to the protected paths it lists (`.git`, `.claude`, `.mcp.json`, shell
rc files and others), and that those writes prompt in the default and `acceptEdits` modes.
An `Edit` or `Write` allow rule therefore does not reach them; it does reach `CLAUDE.md`,
`AGENTS.md`, source files and the files outside that list.

**Real-world consequence:** an `Edit` allow entry lets Claude change any file outside the
protected list without a prompt, a `WebFetch` entry lets it fetch any URL, an interpreter
prefix lets it run whatever program text it writes, and a whole-server `mcp__` entry
approves all tools that server offers, including ones added in a later version.

**The problem class in the literature.** *HarnessSecurity-Bench* (Zhu et al., arXiv
2610.07639) assesses security mechanisms of coding agent harnesses. Its abstract reports
that enabling auto-approve raised attack success from 29.2% to 95.6%, and that "allowed
tools or commands can leave unauthorized operations reachable through alternative
execution paths". The paper is cited for that problem class and nothing more. It does not
study committed settings files, and this policy does not attribute its matching claims to
the paper.

**Why severity is high:** The pack sets high and states no reasoning for it. The cost the
explanation names is that no prompt lets the developer stop a call that an entry covers.

**Fix type — config:** the fix is an edit to the committed settings file. The pack's fix
is to replace each entry with an exact command, domain or path, and to add the class to
`permissions.ask` or `permissions.deny` to make it prompt or be refused for the whole
team. The permissions page says "Rules are evaluated in order: deny, then ask, then
allow." No tool source code changes.

**Confidence 0.6:** the pack's explanation states these limits of the check:

- It reads the permissions block of the `.claude/` settings files in the repo.
- A deny or ask rule of the same shape in the same `.claude/` folder cancels the finding;
  deny and ask rules in user or managed settings, hooks, sandbox settings and prompt-time
  approvals are not seen.
- Writes to protected paths still prompt under an `Edit` or `Write` allow rule.
- A bare `Bash` or `Bash(*)` entry, the AGCFG-012 prefixes and a named-host WebFetch rule
  belong to other rules.
- Other interpreters are not judged and the program list is fixed.

The pack states no other limits for this rule.

---

## What this policy does not cover

- A bare `Bash` or `Bash(*)` allow entry (AGCFG-016).
- `git`, `xargs`, `npx`, `env`, `sed` and `awk` prefixes (AGCFG-012).
- A WebFetch rule for a named host (AGCFG-011).
- Interpreters other than the five listed, and `uvx`, `pipx` and `docker` prefixes.
- `NotebookEdit`, `Read` and other tools without a path.
- Deny and ask rules in user or managed settings, hooks and prompt-time approvals.
- A settings file that is not valid JSON. It is skipped.

---

## Recommendations beyond the fix

Committed rules that name exact commands, domains and paths:

```json
{
  "permissions": {
    "allow": [
      "Bash(python scripts/lint.py)",
      "WebFetch(domain:docs.python.org)",
      "Edit(src/**)",
      "mcp__github__get_issue"
    ]
  }
}
```

1. Name the program text, the domain, the path or the tool in each committed allow rule.
2. Use `permissions.ask` or `permissions.deny` for a class the team should be asked about
   or refused.
3. Review changes to `.claude/settings.json` in pull requests.

---

## Sources

Retrieved 2026-11-25.

- Claude Code documentation, "Configure permissions", `code.claude.com/docs/en/permissions.md`.
  The source of the Claude Code matching behavior above.
- Claude Code documentation, "Permission modes", `code.claude.com/docs/en/permission-modes.md`.
  Cited for the protected-path list and the statement that allow rules do not pre-approve
  those writes, and nothing more.
- Zhu et al., *HarnessSecurity-Bench: Do Security Mechanisms Really Protect Coding Agent
  Harnesses?*, arXiv 2610.07639. Cited for the problem class and nothing more.
