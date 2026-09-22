---
policy_id: claude_sdk_repo
category: claude_sdk
topic: repo
rules:
  - id: CSDK-201
    severity: high
    confidence: 0.9
    scope: repo
    fix_type: config
  - id: CSDK-202
    severity: high
    confidence: 0.9
    scope: repo
    fix_type: config
  - id: CSDK-204
    severity: low
    confidence: 0.6
    scope: repo
    fix_type: config
  - id: CSDK-205
    severity: medium
    confidence: 0.7
    scope: repo
    fix_type: config
  - id: CSDK-206
    severity: medium
    confidence: 0.6
    scope: repo
    fix_type: config
references: [LLM06, LLM10]
---

# Policy Rationale: Repository Session Configuration Posture

**Policy ID:** `claude_sdk_repo`  
**File:** `claude_sdk/repo.yaml`  
**Rules:** CSDK-201, CSDK-202, CSDK-204, CSDK-205, CSDK-206  
**Severities:** high, high, low, medium, medium  
**Fix types:** config, config, config, config, config  
**References:** LLM06 (Excessive Agency), LLM10 (Unbounded Consumption)

---

## What this policy covers

Repo-scope rules for project-wide Claude Agent SDK session configuration
posture: two flavors of approval gating, one flavor of execution bounding,
and two flavors of tool-surface bounding.

Approval gating: the posture declared in `.claude/settings.json` /
`settings.local.json` (predicate `repo_claude_default_mode_is`, CSDK-201) and
the posture set in code on a `ClaudeAgentOptions(...)` session object,
correlated with whether that same construction sets a `disallowed_tools`
deny-list (predicate `repo_claude_options_mode_without_kwarg`, CSDK-202/206 —
see below). Both fire once per scan, not per tool or per agent.

Execution bounding: whether any `ClaudeAgentOptions(...)` construction in the
project sets an explicit `max_turns` (predicate
`repo_claude_options_max_turns_missing`). Fires once per scan when the project
has at least one such construction and none of them cap turns.

Tool-surface bounding: whether a `ClaudeAgentOptions(...)` construction that
sets `permission_mode="acceptEdits"` is paired with an explicit
`disallowed_tools` deny-list (predicates
`repo_claude_options_permission_mode_is: [acceptEdits]` combined with
`repo_claude_options_disallowed_tools_missing`, CSDK-205), and — the same
mechanism, now correlated per construction site instead of repo-wide —
whether a `bypassPermissions` construction is paired with `disallowed_tools`
(predicate `repo_claude_options_mode_without_kwarg`, CSDK-202/206). Both are a
distinct mechanism from `max_turns`: Claude SDK's `allowed_tools` only
auto-approves listed tools, it does not restrict which tools can run, so
`disallowed_tools` is the only construct in this SDK that actually narrows
the tool surface — see "What this policy does not cover" for why an
allow-list-scope reading of CSDK-202 was considered and rejected.

---

## Why permission posture is a distinct concern in agent tools

Claude Code's permission prompts are the in-band human-in-the-loop control: by
default, a tool call that writes a file, runs a shell command, or fetches the
network pauses for approval. That prompt is the last line of defense between a
prompt-injected or mistaken model action and a real effect on the host. Turning
it off does not weaken one tool — it removes the approval step for *every* tool
the agent can reach, repo-wide.

The danger is amplified by where the setting lives. A `defaultMode:
bypassPermissions` in `.claude/settings.json` is checked into the repository, so
it applies to everyone who clones it, not just the author who set it — a
permission decision made once silently governs every future contributor's
sessions. The `ClaudeAgentOptions(permission_mode="bypassPermissions")` form is
worse in practice because it is where applications actually enable the bypass,
and it executes wherever the application runs (a server, a user's machine, CI)
with no checked-in file to audit.

This is OWASP LLM Top 10:2025 **LLM06 (Excessive Agency)** at the configuration
layer: the agent is granted the standing authority to act without confirmation,
so a single injection or model error becomes an unguarded write, command, or
fetch. The fix is configuration, not code — which is why these are the
highest-leverage findings to act on.

---

## Rule-by-rule defense

### CSDK-201 — Project default permission mode bypasses approvals (Severity: high, Confidence: 0.9, Fix type: config)

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

**Why severity is high and not medium:**
It removes the only in-band approval control, repo-wide and for every
contributor. It is not critical only because exploitation still requires the
agent to be driven to a harmful action (injection or error); the setting itself
is the enabling condition, not the exploit.

**Fix type — config:**
Remove the entry or change it to `default` (prompt on every tool call) or
`acceptEdits` (auto-approve only file edits, still gate shell/network). No tool
source changes — it is a settings-file edit. Reserve `bypassPermissions` for
disposable sandboxes, never a shared repo.

**Confidence 0.9:**
The match is an exact value read from a parsed settings file, so false positives
are rare — limited to a settings file that is present but unused (e.g. an example
config not loaded by the running agent). False negatives: a bypass set only at
runtime via the SDK rather than in settings is CSDK-202's job, not this rule's.

### CSDK-202 — Session permission mode bypasses approvals with no tool deny-list (Severity: high, Confidence: 0.9, Fix type: config)

**What we detect:**
A SINGLE `ClaudeAgentOptions(...)` construction in code that both sets
`permission_mode="bypassPermissions"` and does not set `disallowed_tools` at
that same site (predicate `repo_claude_options_mode_without_kwarg: {modes:
[bypassPermissions], kwarg: disallowed_tools}`). This correlates both facts
at the SAME construction site — unlike a repo-wide reading of the two facts
independently, which would silently go quiet on a project with two options
objects (one safe with a deny-list, one `bypassPermissions` without one). An
`Opaque` construction (built with `**` unpacking) that sets a matching
`permission_mode` still counts as missing `disallowed_tools`: a deny-list
hidden inside the unpacked dict is not one this engine can see, so it is not
credited as a mitigation for that specific site.

**Why it is flaggable:**
This is the in-code, session-level form of the `settings.json` `defaultMode`
bypass, and it is where most applications actually enable it. The session
turns off Claude Code's approval prompts, so every tool the agent can call
runs with no human in the loop — and with no `disallowed_tools` deny-list,
nothing else bounds which tools that includes. `allowed_tools` does not help
here: per the Agent SDK's own reference docs, it only auto-approves tools, it
does not restrict which ones can run, so an empty or narrowly-scoped
`allowed_tools` alongside `bypassPermissions` is not a mitigating factor — it
is the maximally dangerous shape, since every unlisted tool still runs, now
with no prompt either. (This distinction was investigated directly against
outreach feedback proposing the opposite reading — see "What this policy
does not cover.")

**Real-world consequence:**
An application that constructs
`ClaudeAgentOptions(permission_mode="bypassPermissions")` with no deny-list
ships an agent that acts without confirmation, on any tool it can reach,
wherever it runs — a server handling untrusted user input, or a desktop app
on an end-user's machine. One injected instruction becomes an unguarded
action with the process's full privileges, and a narrow `allowed_tools` list
someone added believing it was a safety net does nothing to stop it.

**Why severity is high and not medium:**
Identical blast radius to CSDK-201 — the approval control is gone for every
unlisted tool — and it executes in production paths, not just developer
clones. Not critical for the same reason: the bypass is the enabling
condition, not the exploit itself.

**Fix type — config:**
Drop the kwarg or set it to `default` / `acceptEdits`, or — if
`bypassPermissions` is genuinely required — pass `disallowed_tools=` naming
at minimum shell execution and anything that reaches the network or
credentials; `disallowed_tools` denies matching calls in every permission
mode, including `bypassPermissions`, so it is the one control that still
bounds the surface. It is a constructor argument change, not a tool-logic
change. Reserve `bypassPermissions` for disposable sandboxes, never code
that runs on a developer's or user's machine.

**Confidence 0.9:**
The match reads the literal `permission_mode` value and the `disallowed_tools`
presence off the parsed `ClaudeAgentOptions` call, at the same site. False
positives are limited to dead code (an options object built but never used)
or a value overridden elsewhere at runtime; false negatives include a mode
passed via a variable the scanner cannot resolve to a literal, and a
construction that sets `disallowed_tools=[]` or `disallowed_tools=None`,
which still reads as "set" and silences the rule (the same tri-state gap
CSDK-204/205 have for their own absence checks).

### CSDK-206 — Session bypasses approvals with a deny-list that still leaves a broad surface (Severity: medium, Confidence: 0.6, Fix type: config)

**What we detect:**
The complementary case to CSDK-202: a `ClaudeAgentOptions(...)` construction
that sets `permission_mode="bypassPermissions"` AND sets `disallowed_tools`
at that same site (predicate `repo_claude_options_permission_mode_is:
[bypassPermissions]` combined with `not: repo_claude_options_mode_without_kwarg`
on the same modes/kwarg). Exactly one of CSDK-202/CSDK-206 fires per
`bypassPermissions` site — they are mutually exclusive by construction.

**Why it is flaggable:**
`disallowed_tools` denies matching calls in every permission mode, including
`bypassPermissions`, so a deny-list present at this site is a real,
SDK-enforced bound — not just an auto-approve list a developer might mistake
for one. The residual risk is what the deny-list does not name: every tool
not on it still runs with no human approval step at all, because
`bypassPermissions` is otherwise unconditional. A deny-list is allow-by-
default; its safety is exactly as good as the completeness of what it
excludes, which this rule cannot evaluate.

**Real-world consequence:**
A `bypassPermissions` session with `disallowed_tools=["Bash"]` still lets a
prompt-injected task fetch arbitrary URLs, write arbitrary files, or call any
other tool the session can reach — the developer addressed the shell-execution
risk they thought of, not the full tool surface. This is a real but narrower
gap than CSDK-202's: the SDK is doing some of the work, just possibly not
enough.

**Why severity is medium and not high:**
Lower than CSDK-202 because a real, SDK-enforced restriction is present — the
developer took the one action that genuinely bounds `bypassPermissions`, they
just may not have bounded it completely. Comparable to CSDK-205 (medium),
which flags the same "some risk removed, more may remain" shape for
`acceptEdits`.

**Fix type — config:**
Review the `disallowed_tools` list against every tool the session can reach,
confirming it denies shell execution and anything touching the network or
credentials, not just an obvious tool or two. If the session's real tool
needs are narrow, prefer naming them explicitly and using a non-bypass
`permission_mode` ("default" or "acceptEdits") instead of relying on
`bypassPermissions` plus a deny-list to cover everything else. Constructor
argument change, not a tool-logic change.

**Confidence 0.6:**
Lower than CSDK-202 (0.9) because the finding cannot evaluate whether the
present deny-list is actually adequate — a `disallowed_tools=["Bash"]` next
to no other side-effecting tool wired into the session is a materially
different risk than the same list next to a `WebFetch`/`Write`-heavy tool
set, and this rule cannot see that context. It also inherits the same
literal-value and Opaque-construction resolution limits as CSDK-202.

### CSDK-204 — Claude Agent SDK session sets no explicit max_turns limit (Severity: low, Confidence: 0.6, Fix type: config)

**What we detect:**
Every non-opaque `ClaudeAgentOptions(...)` construction in the project sets no
`max_turns` (predicate `repo_claude_options_max_turns_missing`). A
construction built with `**` unpacking (`Opaque: true`) is skipped — its kwarg
set is not statically knowable, so its silence on `max_turns` is not evidence
of a missing cap. The rule fires once per scan, when at least one concrete
construction exists and none of them set the kwarg; a project with no
`ClaudeAgentOptions` construction at all never fires.

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
Lower than CSDK-201/202 because the finding is about an omission rather than a
dangerous value present in code, so it carries a higher false-positive
surface: an options object built but never used to drive a real session, a
cap enforced by a wrapper or retry harness outside the constructor call
itself, or a genuinely short-lived session where no cap is needed in
practice. False negatives include a `max_turns` value passed via a variable
the scanner cannot resolve to a literal, and — see the coverage gap below —
any TypeScript project, since discovery of `ClaudeAgentOptions(...)` is
Python-only today.

### CSDK-205 — Claude Agent SDK session auto-approves edits with no tool deny-list (Severity: medium, Confidence: 0.7, Fix type: config)

**What we detect:**
A `ClaudeAgentOptions(...)` construction that sets
`permission_mode="acceptEdits"` (predicate
`repo_claude_options_permission_mode_is: [acceptEdits]`), combined with no
non-opaque construction in the project setting `disallowed_tools` (predicate
`repo_claude_options_disallowed_tools_missing`). Both conjuncts must hold
(`match: all:`) — the rule does not fire on `acceptEdits` alone, and it does
not fire on a missing deny-list alone. `bypassPermissions` is deliberately
excluded from the mode list here; that value is CSDK-202's rule, and CSDK-205
would otherwise double-report the same `ClaudeAgentOptions(...)` call.

**Why it is flaggable:**
Claude SDK's permission model is not a conventional allow-list: `allowed_tools`
only auto-approves the tools it names, it does not restrict which tools can
run. An unlisted tool still executes — it just falls back to whatever the
current `permission_mode` allows. `acceptEdits` already removes the approval
prompt for file writes/edits, so with no `disallowed_tools` deny-list, nothing
in the session's own configuration bounds the rest of the tool surface: shell
execution, network fetches, and any other tool the session can reach all run
under the same permissive posture edits do, with no config-level statement of
which ones should be off-limits. This is the same LLM06 (Excessive Agency)
mechanism as CSDK-201/202, narrowed to the combination the SDK actually makes
dangerous — a missing deny-list, not a missing allow-list.

**Real-world consequence:**
A session built this way behaves safely for its intended purpose (auto-editing
files without interrupting a human) but carries no explicit boundary stopping
a prompt-injected or mistaken model action from reaching a tool the developer
never intended it to use — there was never a deny-list to consult. Unlike
`bypassPermissions`, this is a plausible, even common, configuration for a
legitimate file-editing workflow, which is exactly why the missing deny-list
matters: the developer likely believes `allowed_tools` (if set) is already
doing the restricting job `disallowed_tools` actually does.

**Why severity is medium and not high:**
Lower than CSDK-201/202 because `acceptEdits` only removes the prompt for file
edits, not for every tool — shell and network calls still prompt unless a
separate mechanism also loosens them. Higher than CSDK-204 because this is a
present, exploitable gap in the access-control surface, not a missing
execution bound with a runtime default as a backstop.

**Fix type — config:**
Pass `disallowed_tools=` to `ClaudeAgentOptions(...)`, naming the tools the
session must never call. It is a constructor argument change, not a
tool-logic change.

**Confidence 0.7:**
Lower than CSDK-201/202 (0.9) because this rule stacks two absence/value
checks rather than one direct value match, so it inherits `disallowed_tools`
missing's higher false-positive surface: an options object built but never
used, a deny-list enforced by a wrapper outside the constructor call, or a
project where no tool the session can reach is actually dangerous. It also
inherits `repoClaudeOptionsMissingKwarg`'s tri-state gap — a construction that
sets `disallowed_tools=[]` (empty list) or `disallowed_tools=None` still reads
as "set" and silences the rule, the same gap CSDK-204 has for
`max_turns=None`. Higher than CSDK-204 (0.6) because a present, permissive
`permission_mode` value is stronger evidence than a pure omission. False
negatives include a `disallowed_tools` value passed via a variable the scanner
cannot resolve to a literal, and — same as CSDK-204 — any TypeScript project,
since discovery of `ClaudeAgentOptions(...)` is Python-only today.

---

## What this policy does not cover

- `permission_mode` / `defaultMode` values supplied dynamically from a variable,
  environment lookup, or config file the scanner cannot resolve to a literal.
- Bare `acceptEdits` mode with a `disallowed_tools` deny-list present.
  Auto-approving file edits is a narrower risk these rules deliberately do not
  flag on its own, since shell and network actions still prompt — CSDK-205
  only fires on the combination of `acceptEdits` *and* no deny-list.
- `allowed_tools` (with or without contents), on its own, at any severity.
  **This was investigated directly, prompted by outreach feedback proposing
  the opposite reading** — that a `bypassPermissions` session with an empty
  or narrowly-scoped `allowed_tools` should be treated as lower-risk or
  exempted from CSDK-201/202. That premise does not survive the Agent SDK's
  own reference docs: `allowed_tools` is described as "auto-approve without
  prompting… this does not restrict Claude to only these tools" — unlisted
  tools fall through to `permission_mode`, so an empty/narrow `allowed_tools`
  next to `bypassPermissions` is the *maximally* dangerous shape (every tool
  runs, none prompt), not a mitigated one. `allowed_tools` never narrows the
  tool surface in this SDK, so it is not read as a signal in either
  direction; `disallowed_tools` is the only construct here that does, which
  is exactly the correlation CSDK-202/206 make. See
  `docs/decisions/tool-allowlist-scope.md` in the engine repo.
- CSDK-202's own `Opaque`-site behavior differs from CSDK-204/CSDK-205's, by
  design: `repo_claude_options_mode_without_kwarg` does NOT skip `Opaque`
  constructions, so an unpack-built `bypassPermissions` site with no visible
  `disallowed_tools` still fires. `repoClaudeOptionsMissingKwarg` (behind
  CSDK-204/205) does skip them, because that helper answers "is any kwarg
  missing anywhere in the repo" (an unreadable site could be the one that
  sets it) rather than "is this specific risky site unmitigated" (an
  unreadable deny-list is not a mitigation).
- Per-tool allow/deny lists in `settings.json` (`permissions.allow` /
  `deny` / `ask`) that grant broad authority without flipping `defaultMode` —
  a separate settings-permission policy would cover that surface.
- Whether the agent's tools are themselves dangerous; this policy is about the
  approval gate, not what is behind it.
- **TypeScript session configuration (CSDK-204, CSDK-205).** Discovery of
  `ClaudeAgentOptions(...)` walks Python AST only. The TypeScript equivalent —
  `query({ options: { maxTurns, permissionMode, disallowedTools } } )` — is
  modeled as a `QueryMainAgent` agent-scope declaration, not a
  `ClaudeAgentOptionsDef`, so a TypeScript project with no `maxTurns`, or with
  `acceptEdits` and no `disallowedTools`, is currently invisible to these
  rules. Closing this gap needs agent-scope rules targeting
  `claude_query_main`, not a change to this policy.
- **CSDK-205 agent-scope analogue not yet shipped.** The same
  permissive-mode-plus-no-deny-list signal applies to a Claude
  `AgentDefinition(...)` (agent scope) the same way it applies to
  `ClaudeAgentOptions(...)` (repo scope) — `permissionMode` /
  `disallowedTools` land on `AgentDef.Kwargs` generically already, so no
  discovery change is needed there either. That agent-scope rule is scoped but
  not yet built; see `docs/decisions/tool-allowlist-scope.md` in the engine
  repo.
- **CSDK-204 exact default behavior.** The rule deliberately does not assert
  a specific default turn count in its `explanation` text; the SDK's default
  was not independently verified for this rationale doc, unlike the
  documented CrewAI default of 20 (CREW-110) or LangChain's default of 15
  (LC-102).

---

## Recommendations beyond the fix

```jsonc
// .claude/settings.json — gate everything by default; auto-approve only edits.
{
  "permissions": {
    "defaultMode": "acceptEdits",
    "deny": ["Bash(rm *)", "Bash(curl *)", "WebFetch"]
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
2. If a workflow genuinely needs unattended execution, run it in a disposable
   sandbox (container, ephemeral VM) and scope the agent's tools tightly, rather
   than reaching for `bypassPermissions` on a developer or production host.
3. Keep `settings.local.json` (developer-local, gitignored) for any personal
   loosening, so a bypass never lands in the shared, checked-in config.
4. Size `max_turns` to the task, not to "whatever the default allows." If a
   task legitimately needs many turns, prefer splitting it into bounded
   sub-sessions over raising the cap — a large cap defeats the point of having
   one.
