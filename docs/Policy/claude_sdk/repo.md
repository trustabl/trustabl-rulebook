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
references: [LLM06, LLM10]
---

# Policy Rationale: Repository Session Configuration Posture

**Policy ID:** `claude_sdk_repo`  
**File:** `claude_sdk/repo.yaml`  
**Rules:** CSDK-201, CSDK-202, CSDK-204, CSDK-205  
**Severities:** high, high, low, medium  
**Fix types:** config, config, config, config  
**References:** LLM06 (Excessive Agency), LLM10 (Unbounded Consumption)

---

## What this policy covers

Repo-scope rules for project-wide Claude Agent SDK session configuration
posture: two flavors of approval gating, one flavor of execution bounding,
and one flavor of tool-surface bounding.

Approval gating: the posture declared in `.claude/settings.json` /
`settings.local.json` (predicate `repo_claude_default_mode_is`) and the
posture set in code on a `ClaudeAgentOptions(...)` session object (predicate
`repo_claude_options_permission_mode_is`). Both fire once per scan, not per
tool or per agent. Each rule fires when the respective `bypassPermissions`
value is present.

Execution bounding: whether any `ClaudeAgentOptions(...)` construction in the
project sets an explicit `max_turns` (predicate
`repo_claude_options_max_turns_missing`). Fires once per scan when the project
has at least one such construction and none of them cap turns.

Tool-surface bounding: whether a `ClaudeAgentOptions(...)` construction that
sets `permission_mode="acceptEdits"` is paired with an explicit
`disallowed_tools` deny-list (predicates
`repo_claude_options_permission_mode_is: [acceptEdits]` combined with
`repo_claude_options_disallowed_tools_missing`). This is a distinct mechanism
from the other two: Claude SDK's `allowed_tools` only auto-approves listed
tools, it does not restrict which tools can run, so `disallowed_tools` is the
only construct in this SDK that actually narrows the tool surface.

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

### CSDK-202 — Session permission mode bypasses approvals (Severity: high, Confidence: 0.9, Fix type: config)

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

**Why severity is high and not medium:**
Identical blast radius to CSDK-201 — the approval control is gone for every tool
— and it executes in production paths, not just developer clones. Not critical
for the same reason: the bypass is the enabling condition, not the exploit
itself.

**Fix type — config:**
Drop the kwarg or set it to `default` / `acceptEdits`. It is a constructor
argument change, not a tool-logic change. Reserve `bypassPermissions` for
disposable sandboxes, never code that runs on a developer's or user's machine.

**Confidence 0.9:**
The match reads the literal `permission_mode` value off the parsed
`ClaudeAgentOptions` call. False positives are limited to dead code (an options
object built but never used) or a value overridden elsewhere at runtime; false
negatives include a mode passed via a variable the scanner cannot resolve to a
literal.

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
- `allowed_tools` (with or without contents). It only auto-approves; it never
  narrows the tool surface in this SDK, so an empty or absent `allowed_tools`
  is not itself a finding — see the CSDK-205 rationale above.
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
