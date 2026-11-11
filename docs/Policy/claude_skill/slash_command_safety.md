---
policy_id: claude_slash_command_safety
category: claude_skill
topic: slash_command_safety
rules:
  - id: CCMD-001
    severity: high
    confidence: 0.9
    scope: slash_command
    fix_type: config
  - id: CCMD-002
    severity: high
    confidence: 0.8
    scope: slash_command
    fix_type: config
  - id: CCMD-003
    severity: medium
    confidence: 0.7
    scope: slash_command
    fix_type: config
references: [LLM01, LLM06]
---

# Policy Rationale: Claude Code Slash Command Safety

**Policy ID:** `claude_slash_command_safety`  
**File:** `claude_skill/slash_command_safety.yaml`  
**Rules:** CCMD-001, CCMD-002, CCMD-003  
**Severities:** high, high, medium  
**Fix types:** config, config, config  
**References:** LLM01 (Prompt Injection), LLM06 (Excessive Agency)

> **Verification status.** The Claude Code behavior below was read on 2026-11-11 from
> Anthropic's skills page (`code.claude.com/docs/en/skills`, which also serves
> `/slash-commands`), permissions page and tools reference. No paper or advisory about slash
> command files was found: four skill papers were searched in full and none mentions a command
> file, so the vendor pages are the basis. One paper (arXiv 2601.10338) is cited for the skill
> problem class and nothing more. **Not verified, and therefore not assumed:** commands in
> `~/.claude/commands`, the frontmatter contract of plugin commands, how Claude Code reads
> `disable-model-invocation` written as a string (neither its docs nor its source were found to
> say; the engine reads a string that spells true as true), and any run of Claude Code.

---

## What this policy covers

Claude Code reads Markdown files in `.claude/commands/`. The skills page says "Custom commands
have been merged into skills. A file at `.claude/commands/deploy.md` and a skill at
`.claude/skills/deploy/SKILL.md` both create `/deploy` and work the same way." A command file
"supports the same frontmatter except `name` and `paths`", so its `allowed-tools` line is the
same pre-approval list a `SKILL.md` carries.

The skill rules (CSKILL-001, CSKILL-050) read `SKILL.md` files. No rule read a command file
before this policy: the engine discovered commands and parsed their grants, and the same
`allowed-tools: Bash` was a finding on a skill and no finding on a command. These three rules
fire per command, at `slash_command` scope, over the parsed frontmatter. The surface is Markdown
and the rules carry no `language:` field. The pack loads for each scan.

- **CCMD-001** flags an unrestricted `Bash` grant.
- **CCMD-002** flags a model-invocable command that pre-approves a file-writing tool.
- **CCMD-003** flags a pre-approved `WebSearch` or an unrestricted `WebFetch`.

A command can fire all three; each is a separate finding on a separate tool. Command findings
are not a scored surface in this release, so they change no readiness score. A finding on a file
under a test path is tagged test-origin by the engine's path classifier like any finding.

---

## Rule-by-rule defense

### CCMD-001 — Slash command pre-approves unrestricted shell (Severity: high, Confidence: 0.9, Fix type: config)

**What we detect:** a parsed `allowed-tools` grant for `Bash` whose pattern, trimmed, is empty,
`*` or `:*`: a bare `Bash`, `Bash(*)` or `Bash(:*)` (predicate
`slash_command_allows_unrestricted_shell`, the same grant logic as `skill_allows_unrestricted_shell`).
A prefix grant such as `Bash(git status *)` is not flagged.

**Why it is flaggable.** All behavior in this list is from the skills page, read on 2026-11-11.

- What the field does. `allowed-tools` lists "Tools Claude can use without asking permission
  during the turn that invokes this skill. The grant clears when you send your next message."
  It "does not restrict which tools are available", and the permission settings "still govern
  tools that are not listed". "Deny and ask rules still override `allowed-tools`."
- That a repository can carry it. The page says workspace trust does not gate this field:
  Claude Code applies a project skill's `allowed-tools` even in a `-p` run in a folder that has
  not been trusted, and "A skill can grant itself broad tool access, so review the
  `allowed-tools` of skills checked into a repository before you run Claude Code there." The
  page states this for skills; commands are stated to work the same way.
- Who can start it. "By default, Claude can invoke any skill that doesn't have
  `disable-model-invocation: true` set." The tools reference says skills run "through the
  existing `Skill` tool rather than adding a new tool entry".

A bare `Bash` grant therefore lets the model run any shell command that no deny or ask rule
matches, with no prompt, during the turn that runs the command, and the model can start the
command itself unless the file opts out.

**Real-world consequence:** a shell command a person would have reviewed in a prompt runs
without one when text the model read steers it there: a fetched page, a file the command reads,
an issue body pasted into the prompt. The pack does not state a figure for how many repositories
carry such a grant.

**Why severity is high:** The pack sets high and states no reasoning for it. CSKILL-001, the same
grant on a `SKILL.md`, is rated high at 0.9.

**Fix type — config:** the fix is an edit to the command's frontmatter: narrow the grant with
prefix patterns such as `Bash(git status *) Bash(npm test *)`, or remove `Bash` and let the
normal prompt run, and set `disable-model-invocation: true` so the model cannot start it.

**Confidence 0.9:** the predicate reads a frontmatter field, so a finding means the grant is
in the file. The pack's explanation states these limits:

- It reads the command file's frontmatter. It does not judge a prefix pattern such as
  `Bash(git *)` for breadth, the command body, settings permission rules, or a bare `Bash` allow
  rule in settings (AGCFG-016).
- A managed policy can make Claude Code ignore the field: the page says that when
  `allowManagedPermissionRulesOnly` is set, "Claude Code ignores `allowed-tools` in project and
  personal skills", which needs "Claude Code v2.1.282 or later".
- A command whose frontmatter is not valid YAML is not parsed and is silent.
- `disable-model-invocation` is read leniently: `true`, `yes`, `on`, `y` and `1`, quoted or not,
  in any letter case, count as set. If Claude Code does not honor a string value, CCMD-002 is
  silent on a command the model can in fact start.

On 2026-11-11 the detector's logic was run as a prototype (a Python port of the shared grant
test, not the engine) over 29 public repositories that commit `.claude/commands/` files: 973
command files, 67 with `allowed-tools`. It matched 20 files, in 5 repositories. Each was a
bare `Bash` grant, which is what the rule is defined to flag. One match
sat under a `tests/fixtures/` path and is tagged test-origin. The sample was drawn from topic
searches, so it leans toward command-heavy repositories; one repository supplied 14 of the 20.
The pack states no measurement of precision or recall.

### CCMD-002 — Model-invocable slash command pre-approves file writes (Severity: high, Confidence: 0.8, Fix type: config)

**What we detect:** the command does not set `disable-model-invocation: true` (predicate
`slash_command_model_invocable`) and pre-approves `Write`, `Edit`, `MultiEdit` or `NotebookEdit`
with no restricting pattern (predicate `slash_command_allows_unrestricted_tool`). The pattern
test follows the permissions page: `Write` and `NotebookEdit` count whatever pattern follows them,
because "Use `Edit(docs/**)` in place of `Write(docs/**)`" for `Write`, `NotebookEdit` and legacy
`MultiEdit`; `Edit` counts with no pattern or a catch-all one (`*`, `**`, `/**`, `//**`); a path
pattern such as `Edit(docs/**)` is a restriction and is not flagged. `MultiEdit` is listed as a
legacy alias; the tools reference lists no such tool.

**Why it is flaggable.** From the skills page, 2026-11-11: "`disable-model-invocation: true`:
Claude can't invoke the skill on its own. Use this for workflows with side effects or that you
want to control timing". The inverse is the default, so a command without it can be started by
the model, and a command pre-approving writes then carries a grant that needs no prompt and is
reachable from any text that reaches the model. The pairing is the one CSKILL-050 flags on a
skill.

**Real-world consequence:** an edit to source, configuration or the project's own
`.claude/settings.json` that nobody approved. The pack does not state a figure.

**Why severity is high:** The pack sets high and states no reasoning for it. CSKILL-050, the same
pairing on a `SKILL.md`, is rated high at 0.8.

**Fix type — config:** set `disable-model-invocation: true`, or drop the write tools from
`allowed-tools`, or scope writes with an `Edit(<path>)` grant and a PreToolUse hook.

**Confidence 0.8:** the pack's explanation states its limits. It reads frontmatter and does not
judge what the body asks the model to write, a path-scoped `Edit` grant, settings deny rules, or
whether the description makes the model likely to pick the command. The page says an omitted
`description` falls back to the first non-empty line of the content, so a command without one is
still listed; no run of Claude Code confirmed this. The prototype matched 19 files in 8
repositories, all without `disable-model-invocation`, each a `Write`, `Edit` or `MultiEdit` grant.

### CCMD-003 — Slash command pre-approves model-driven web retrieval (Severity: medium, Confidence: 0.7, Fix type: config)

**What we detect:** a `WebSearch` grant, or a `WebFetch` grant with no pattern or `*` (predicate
`slash_command_allows_unrestricted_tool`). The tools reference states that `WebSearch` takes "No
specifier; allow or deny the tool as a whole", so a grant of it is unrestricted. A
`WebFetch(domain:example.com)` grant is a restriction and is not flagged. The rule does not
require model invocation: a person who types the command still gets retrieval the model chooses,
with no prompt.

**Why it is flaggable.** The pre-approval mechanics are those under CCMD-001. Retrieved pages and
results enter the conversation as text the model reads, so pre-approved retrieval is an inbound
channel for instructions; the URL or query is an outbound channel for in-context data. The pack's explanation says so and cross-references
CSDK-112 and CSDK-124, the same grant on a subagent.

**Real-world consequence:** the model follows an instruction placed on a page it fetched, or
sends context in a URL, with no prompt. The pack does not state a figure.

**Why severity is medium:** The pack sets medium and states no reasoning for it.

**Fix type — config:** remove the web tools, or pin `WebFetch` to a domain the command controls
with `WebFetch(domain:example.com)`, and treat retrieved text as untrusted input.

**Confidence 0.7:** the pack's explanation states its limits: it reads frontmatter, does not
judge MCP fetch tools, and does not judge what the body does with retrieved text. The prototype
matched 5 files in 3 repositories: bare `WebFetch` in 3 files in 2 repositories, and `WebSearch`
in the other 2 files, which are in the third repository.

---

## What this policy does not cover

- A command body that runs shell lines or fetches text. The skill rules read dynamic-context
  commands in `SKILL.md` bodies; no command rule reads a body.
- Commands in `~/.claude/commands` and settings-level permission rules (AGCFG-012, AGCFG-016).
- A prefix pattern that is broad in practice, such as `Bash(git *)`.
- MCP tools granted by name, and `PowerShell`.
- A `SKILL.md` (CSKILL-*) or a subagent (CSDK-110, CSDK-111, CSDK-112).
- Whether the model would choose to start a given command.

---

## Recommendations beyond the fix

```yaml
---
description: Run the unit tests
disable-model-invocation: true
allowed-tools: Bash(npm test *) Read
---
```

1. Name exact command prefixes in `allowed-tools` instead of all of `Bash`.
2. Set `disable-model-invocation: true` on any command that writes files or has side effects.
3. Pre-approve for the whole session in permission settings rather than a command when a grant
   should outlast one turn; the page says settings are the place for that.
4. Review changes under `.claude/commands/` in pull requests as permission changes.
5. In an organization, `allowManagedPermissionRulesOnly` makes Claude Code ignore
   `allowed-tools` in project and personal skills, per the skills page.

---

## Sources

- Claude Code skills (custom commands are covered on the same page): https://code.claude.com/docs/en/skills
  Retrieved 2026-11-11. Cited for the merge of commands into skills, the frontmatter fields, how
  `allowed-tools` grants apply, model invocation and `disable-model-invocation`.
- Claude Code permissions: https://code.claude.com/docs/en/permissions Retrieved 2026-11-11. Cited
  for `Write`, `NotebookEdit` and `MultiEdit` path rules and for `Edit` patterns.
- Claude Code tools reference: https://code.claude.com/docs/en/tools-reference Retrieved
  2026-11-11. Cited for the `Skill` tool and for `WebSearch` taking no specifier.
- Yi Liu, Weizhe Wang, Ruitao Feng, Yao Zhang, Guangquan Xu, Gelei Deng, Yuekang Li, Leo Zhang,
  "Agent Skills in the Wild: An Empirical Study of Security Vulnerabilities at Scale", arXiv
  2601.10338, 2026-01-15. Cited for the skill problem class and nothing more: it studies skills
  and does not mention command files. It lists "excessive permissions" among its privilege
  escalation patterns and describes a "consent gap" as "the mismatch between what users approve
  and what skills actually do". It does not describe `allowed-tools`, and no claim in this doc
  about commands rests on it.
