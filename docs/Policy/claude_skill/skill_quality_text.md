---
policy_id: claude_skill_quality_text
category: claude_skill
topic: skill_quality_text
rules:
  - id: CSKILL-080
    severity: high
    confidence: 0.75
    scope: skill
    fix_type: config
  - id: CSKILL-081
    severity: high
    confidence: 0.7
    scope: skill
    fix_type: config
  - id: CSKILL-082
    severity: high
    confidence: 0.8
    scope: skill
    fix_type: config
  - id: CSKILL-083
    severity: low
    confidence: 0.5
    scope: skill
    fix_type: config
  - id: CSKILL-084
    severity: medium
    confidence: 0.6
    scope: skill
    fix_type: config
  - id: CSKILL-085
    severity: low
    confidence: 0.5
    scope: skill
    fix_type: config
  - id: CSKILL-086
    severity: medium
    confidence: 0.65
    scope: skill
    fix_type: config
  - id: CSKILL-087
    severity: low
    confidence: 0.85
    scope: skill
    fix_type: config
references: [LLM02, LLM05, LLM06, AST03]
---

# Policy Rationale: Agent Skill Quality (Text-Match)

**Policy ID:** `claude_skill_quality_text`  
**File:** `claude_skill/skill_quality_text.yaml`  
**Rules:** CSKILL-080, CSKILL-081, CSKILL-082, CSKILL-083, CSKILL-084, CSKILL-085, CSKILL-086, CSKILL-087  
**Severities:** high, high, high, low, medium, low, medium, low  
**Fix types:** config — all eight rules fix by editing `SKILL.md` prose (name, description, or body); none require a bundled-file or code change  
**References:** OWASP LLM Top 10:2025 — LLM02, LLM05, LLM06 · OWASP Agentic Skills Top 10 — AST03

> This is the **second** `claude_skill` rule file. [`skill_safety.yaml`](skill_safety.md)
> detects structural/config facts read directly off the parsed `SkillDef` —
> tool grants, dynamic-context grammar, bundled-file contents. Every rule
> here instead runs a free-text keyword or phrase search over the skill's
> `name`, `description`, or `body` string. None of these eight rules read
> bundled files, and — except CSKILL-082 — none read `allowed-tools` either.
> Detection and threat model are both different; hence a separate file and a
> separate doc, not an addendum to `skill_safety.md`.

---

## What this policy covers

Eight quality and data-governance rules over Claude Code Agent Skills
(`SKILL.md`), each implemented as a case-insensitive **substring** search
(`strings.Contains`, not a word-boundary regex) via one of three predicates —
`skill_name_has_text`, `skill_description_has_text`, `skill_body_has_text` —
against a fixed keyword or phrase list, or the negation of one. Two rules
(CSKILL-083, CSKILL-085) fire on the **absence** of every word in their list
rather than the presence of any; one rule (CSKILL-082) compounds a
name-text match with the `skill_allows_tool` predicate CSKILL-050/060 also
use in `skill_safety.yaml`. Every match is over parsed frontmatter/body
strings, so — like `skill_safety.yaml` — these rules carry no `language:`
field and fire independent of the surrounding codebase.

---

## Why this policy spans three distinct risk categories

Unlike a single-threat-model policy, this file's eight rules split cleanly
into three unrelated concerns. Forcing them into one narrative would misstate
at least two of the three, so this section treats them separately.

**1. Security exposure from claimed-but-unspecified capability (CSKILL-080,
CSKILL-081).** A skill's `name` and `description` are the metadata a user or
reviewer reads to decide whether to trust it, and the `description` is
*always* loaded into Claude's context regardless of whether the skill fires.
When that text names a cryptographic operation or a sensitive-data class
without stating a bound primitive, a data-minimization boundary, or a
retention policy, the metadata gives neither the human reviewer nor Claude
itself a constraint to check the skill's eventual behavior against. This maps
to **OWASP LLM02 (Sensitive Information Disclosure)**: crypto claimed without
specifics is frequently crypto protecting — or failing to protect — the exact
sensitive fields CSKILL-081 flags independently, and broad, unminimized data
access (CSKILL-084) widens the exposure surface the same way.

**2. Privilege escalation via role/grant mismatch (CSKILL-082).** A skill
named for an audit, security, or compliance role carries an implicit
contract: observe and report, don't mutate. When that same skill's
`allowed-tools` pre-approve a side-effecting or exfiltration-capable tool,
the contract the name promises and the capability the frontmatter grants
diverge — and Claude can be steered (by an ambiguous request or by injected
content encountered mid-audit) into using the grant the name never
implied it needed. This is the same mechanic **OWASP Agentic Skills Top 10
AST03 (Over-Privileged Grants)** and **OWASP LLM06 (Excessive Agency)** name
for `skill_safety.yaml`'s CSKILL-050/060 — this rule is the text-match
variant, keyed on role-implying language in the name rather than an explicit
read-only claim in the description.

**3. Reliability and data-governance hygiene (CSKILL-083, CSKILL-084,
CSKILL-085, CSKILL-086, CSKILL-087).** These five rules are not attacks; they are
documentation gaps that degrade how predictably a skill behaves. A skill with
no error-handling language gives Claude no guidance on the unhappy path
(**LLM05, Improper Output Handling** — the same category `google_adk`'s and
`claude_sdk`'s error-handling rules cite, extended here to skill *prose*
rather than tool *code*). A skill with no stated purpose gives a reviewer
nothing to weigh its access against. A skill whose description is a
placeholder stub (`TODO`, `TBD`, `FIXME`) passes CSKILL-070's empty check
while still giving Claude no model-invocation signal — the same selection
failure CSDK-017 names for tool docstrings, applied here to `SKILL.md`
frontmatter. A skill that implies it writes,
caches, or logs data with no retention statement leaves that data's
lifetime undefined. None of these five map cleanly to a single OWASP
LLM Top 10 category — CSKILL-085 in particular is pure documentation
hygiene with no external taxonomy hook — and this doc says so rather than
forcing a citation that wouldn't survive scrutiny.

---

## Rule-by-rule defense

### CSKILL-080 — Skill claims cryptographic operations (Severity: high, Confidence: 0.75, Fix type: config)

**What we detect:** `skill_name_has_text` OR `skill_description_has_text`
matches any of `crypto`, `encrypt`, `decrypt`, `sign`, `hash`, `certificate`,
`signing`, `cipher`, `asymmetric`, `symmetric` — a case-insensitive substring
search of the skill's `name` field or its `description` field. The body is
never scanned by this rule.

**Why it is flaggable:** A name or description that raises a crypto term
with no primitive, key source, or algorithm named gives Claude no
constraint when it later writes the actual crypto code. Crypto fails
silently — a weak cipher, a reused IV, an unvalidated signature, a
hardcoded key all look like working code until they're attacked — so the
one moment a constraint could be imposed (the skill's own metadata) is the
moment this rule catches empty.

**Real-world consequence:** A skill named `cert-signer` whose `SKILL.md`
never names an algorithm, a key source, or a library is invoked by a user
who assumes some baseline of correctness; Claude fills the gap with
whatever it judges plausible in the moment — which may be an unauthenticated
hash, a self-signed cert with no expiry policy, or a hardcoded test key
promoted to production use.

**Why high and not critical:** This is a text claim, not executed code —
the rule cannot see whether the eventual implementation is actually unsafe,
only that the topic is invoked without the specifics that would bound it.
Not critical because a skill can state the missing details in its *body*
(unscanned by this rule) while its name/description stay generic; the miss
is real but the failure mode is a documentation gap upstream of an
unverified implementation, not a demonstrated flaw.

**Fix type — config:** Add the missing specifics to the description or
body text — no source or bundled-file change needed.

**Confidence 0.75:** Because the match is a raw substring, several of these
tokens are common word fragments, not whole-word hits. `sign` is a substring
of `design`, `assign`, `signal`, and `significant` — a description that says
"designed to process incoming files" trips this rule on `design` containing
`sign`, with zero relation to cryptography. `hash` and `certificate` also
have legitimate non-crypto senses (a content hash used for cache-busting, a
completion certificate). **False negatives:** a skill can genuinely
implement crypto described entirely in the body using terms this rule
doesn't scan for at all (`AEAD`, `HMAC`, `JWT`, `PGP`, `bcrypt`, `argon2`),
or the crypto terms can appear only in the body, which CSKILL-080 never
reads.

### CSKILL-081 — Skill processes sensitive data (Severity: high, Confidence: 0.7, Fix type: config)

**What we detect:** `skill_body_has_text` OR `skill_description_has_text`
matches any of `password`, `secret`, `token`, `ssn`, `credit card`, `pii`,
`personal data`, `sensitive`, `confidential`, `private key` — substring
search over the body or the description (not the name).

**Why it is flaggable:** Naming a sensitive-data class without stating what
the skill does with it — reads it, redacts it, retains it — leaves no
data-minimization boundary for a reviewer to check. A skill that says
nothing beyond naming the field could be scoped tightly or could be
retaining everything it touches; the text alone doesn't distinguish the two.

**Real-world consequence:** A "customer-support" skill's body reads:
"look up the account using the customer's SSN and password" with no
stated minimization or retention rule. Whatever tool call executes that
lookup, and whatever gets echoed back into the transcript, now carries
those fields with no documented boundary on where they end up next.

**Why high and not critical:** A keyword hit proves the *topic* was
named, not that real sensitive data flows through the skill — it could be
a schema-field reference in the abstract, or defensive language ("never
share the customer's password") rather than actual handling logic. Real
damage depends on what the skill's tool calls (invisible to this rule)
actually do with the field once named.

**Fix type — config:** State which fields are read, why, and for how
long — a description/body edit.

**Confidence 0.7:** `secret` is a substring of `secretary` — a description
mentioning "routes the request to the department secretary" trips this
rule with no sensitive-data handling at all. `token` and `confidential` are
similarly overloaded: a "pagination token" or "session token" is a
routine engineering term, and "confidential" often appears defensively
("never expose confidential data") rather than descriptively. **False
negatives:** sensitive fields named by domain-specific terms outside this
list — date of birth, routing number, medical record number, passport
number — are invisible to the rule.

### CSKILL-082 — Over-privileged security skill (Severity: high, Confidence: 0.8, Fix type: config)

**What we detect:** The compound match `all: [skill_name_has_text(security |
audit | pentest | scan | vulnerability | compliance), skill_allows_tool(Bash
| Write | Edit | WebFetch | NotebookEdit)]`. The name half is a substring
search over `name`; the grant half is `PredSkillAllowsTool`, which matches
either a parsed `ToolGrants` entry's tool (so `Bash(git diff *)` matches on
`Bash` regardless of how narrow the pattern is) or a raw `allowed-tools`
token.

**Why it is flaggable:** A name that claims a security, audit, pentest, or
compliance role sets an expectation of observe-and-report, not mutate — the
same role-vs-grant logic `skill_safety.yaml`'s CSKILL-060 applies to an
explicit read-only *description* claim, applied here to role-implying
*name* language instead. A skill that can be steered — by an ambiguous
request, or by an injected instruction encountered mid-"audit" — while
holding a side-effecting or exfiltration-capable grant turns a read-first
review into a privilege-escalation path.

**Real-world consequence:** A skill named `security-scanner` grants `Bash`
and `Write`. A user asks it to scan a repository; content in a scanned file
carries an injected instruction to "fix" what it found. The audit-named
skill, already holding write and shell access, executes it — the review
role never gated the mutation.

**Why high and not critical:** Both conditions must hold — a specific,
non-coincidental pairing — but not critical because a security or
compliance skill can legitimately need `Bash`/`Write` for genuine
remediation actions; the pairing is a strong role-mismatch signal, not
proof the grant is unjustified.

**Fix type — config:** Narrow `allowed-tools` to the read-only set an
audit role needs, or split remediation into a separately-named skill — a
frontmatter edit either way.

**Confidence 0.8:** Combining a name signal and a grant signal is stronger
evidence than either alone — a security-named skill with no side-effecting
grant doesn't fire, and a `Bash`-granted skill with an unrelated name
doesn't fire — but two gaps remain. First, the name-side match has the same
substring exposure as the other rules in this file: `audit` is a substring
of `auditorium`, `scan` is a substring of `scanner` and `scandal` — a
`meeting-auditorium-booker` skill with an unrelated `WebFetch` grant would
trip this rule on `audit` alone. Second, the grant-side match doesn't
distinguish a wildcard `Bash(*)` from a narrowly scoped `Bash(git diff *)`
— `PredSkillAllowsTool` matches on the grant's `Tool` field only, so a
`security-audit` skill that scoped its `Bash` grant to a single read-mostly
command still fires as if it held unrestricted shell.

### CSKILL-083 — Missing error-handling guidance (Severity: low, Confidence: 0.5, Fix type: config)

**What we detect:** `not: skill_body_has_text([error, exception, catch,
retry, fallback, fail, handle, recover])` — this rule fires only when
**none** of these eight words appears anywhere in the body, as a
case-insensitive substring.

**Why it is flaggable:** A body with zero error-handling language gives
Claude nothing to fall back on when a step fails: no instruction on
whether to retry, use a fallback, or stop and report. Without that
guidance, Claude may proceed on partial or unexpected results rather than
surfacing the failure to the user.

**Real-world consequence:** A "sync-inventory" skill's body never states
what to do if the sync API call fails partway through; Claude, given no
guidance, reports the sync as complete after a partial write.

**Why low and not medium:** Absence of these eight words does not mean
absence of resilience — a short, single-step skill (`format-date`) can be
entirely correct with nothing to say about failure, because there is
nothing in its one step that meaningfully fails. This is a documentation
nudge, not a demonstrated behavioral gap, so it stays at the pack's floor.

**Fix type — config:** Add one sentence naming the unhappy path — retry
once, fall back, or stop and report — to the body.

**Confidence 0.5 (mandatory — absence-based logic):** This is a
"not"-predicate rule, and its false-positive shape is the mirror image of a
presence rule's. A skill can describe genuinely correct error handling
without using any of the eight listed words at all — "if the lookup times
out, wait and try the request again" describes a retry without the word
`retry`; "flag anything that doesn't match for the user to review"
describes graceful degradation without `fallback` or `fail`. Those skills
are flagged despite being correct. The asymmetric failure mode runs the
other way too: because the rule only needs **one** incidental hit anywhere
in the body to stay silent, a skill that uses the word `error` once in an
unrelated spec note ("this endpoint returns a 400 error for malformed
input") suppresses the flag even though it states no guidance on what
Claude should *do* about that failure. Presence of the word, not presence
of guidance, is what the predicate actually checks.

### CSKILL-084 — Broad, unminimized data access (Severity: medium, Confidence: 0.6, Fix type: config)

**What we detect:** `skill_body_has_text` matches any of `all data`,
`entire`, `complete database`, `every record`, `full export`, `all files`,
`all records` — a substring search over the body only.

**Why it is flaggable:** Broad-access phrasing suggests the skill pulls
more than the task at hand needs. Requesting a full dataset or export when
a filtered subset would do widens the blast radius of any later bug, leak,
or injected instruction that acts on the retrieved data.

**Real-world consequence:** A "customer-insights" skill's body instructs
"query the entire customer database and summarize trends" — the resulting
tool call pulls a full table into context (and likely into logs) rather
than a filtered, task-scoped query.

**Why medium and not high:** The phrasing describes intent, not a
technical capability grant — the skill body itself cannot cause the
access; whatever tool actually executes the query (a separate MCP/SDK
tool, invisible to this rule) enforces the real boundary, and a
well-scoped tool makes the broad phrasing harmless. Not low because when
the underlying tool does honor an unscoped instruction, the effect is a
real, unminimized pull.

**Fix type — config:** Scope the body's data-access language to the
specific records or fields the task needs; state explicitly if a full
export genuinely is the task.

**Confidence 0.6:** `entire` is a common intensifier with plenty of
unrelated uses ("read the entire file before editing" refers to one
file's contents, not indiscriminate data access). **False negatives:**
paraphrased broad-access language evades the exact-phrase list entirely —
"pull everything from the users table," "grab the whole dataset," "export
all the customer info" — none contain the literal phrases this rule checks
for, so a body can request everything in the database while using none of
these seven strings.

### CSKILL-085 — Description states no purpose (Severity: low, Confidence: 0.5, Fix type: config)

**What we detect:** `not: skill_description_has_text([in order to, to
allow, to enable, purpose, used for, designed to, intended to])` — fires
only when **none** of these seven phrases appears in the description.

**Why it is flaggable:** A description with no purpose phrasing states
what the skill touches without stating why. A user or reviewer deciding
whether the skill's data access and tool grants are proportionate has no
stated intent to weigh them against — and Claude's own model-invocation
heuristic, which reads the description to judge relevance, has a thinner
signal for when the skill should and shouldn't trigger.

**Real-world consequence:** A description that reads "Handles customer
records and sends emails" states capability with no stated goal — nothing
tells a reviewer whether record access plus email-sending is proportionate
to what the skill is actually for.

**Why low and not medium:** This is a documentation gap, not a behavioral
one. A skill can be perfectly safe and well-scoped while its description
simply isn't phrased with one of these seven transitional phrases.

**Fix type — config:** Add one clause stating the skill's purpose to the
description.

**Confidence 0.5 (mandatory — absence-based logic):** Same asymmetry as
CSKILL-083, applied to the description field. A description can state a
clear purpose without any of the seven phrases — "Summarizes PR diffs into
release-note bullets" states intent through plain subject-verb-object
structure, no "to enable" required — and gets flagged anyway. Conversely, a
description can contain one of the phrases incidentally without conveying
real intent — "intended to be run after `npm install`" states a
precondition, not a purpose — and passes the rule while still leaving a
reviewer with nothing to weigh the skill's access against.

### CSKILL-086 — Data retention or logging implied (Severity: medium, Confidence: 0.65, Fix type: config)

**What we detect:** `skill_body_has_text` matches any of `log`, `store`,
`persist`, `save`, `retain`, `cache`, `database`, `write to`, `append to`,
`record` — substring search over the body only.

**Why it is flaggable:** Persistence language with no stated retention
policy leaves the lifetime, location, and access control of whatever gets
written or logged entirely undefined. Data that outlives the current
session needs an explicit boundary; a verb in the instructions is not one.

**Real-world consequence:** A skill body says "save the analysis results
to a local file for later reference" with no stated location or retention
period — Claude writes an artifact whose lifetime and exposure are
undefined, and if the analysis touched a sensitive field (CSKILL-081),
that persistence now has no documented boundary either.

**Why medium and not high:** Persistence language alone doesn't confirm
that what's retained is sensitive or high-volume — "cache the API
response for this session" is low-risk, bounded reuse — but the keyword
list can't tell "for this session" apart from indefinite retention, so it
stays above a documentation nudge.

**Fix type — config:** State what is stored, where, for how long, and
under what basis — or state explicitly that nothing persists beyond the
current turn.

**Confidence 0.65:** The substring match on `log` and `store` produces
concrete, verifiable false positives: `log` is contained in `catalog`,
`dialog`, and `logic` — a body describing "the skill's routing logic"
trips this rule with no logging involved at all. `store` is contained in
`restore` — "restore the previous version if the check fails" trips it via
`restore` alone. **False negatives:** persistence described without any of
these ten strings — "keep a copy," "write the results out," "maintain a
history of runs" — evades the list entirely; `write to` is listed as an
exact two-word phrase, so "write the results out" doesn't match it.

### CSKILL-087 — Skill description is a placeholder (Severity: low, Confidence: 0.85, Fix type: config)

**What we detect:** `skill_description_has_text` matches any of `todo`,
`tbd`, `fixme`, `placeholder`, `no description`, `does stuff` — a
case-insensitive substring search of the skill's `description` field
only. The name and body are never scanned. An empty description does not
match (CSKILL-070 in `skill_safety.yaml` covers that case).

**Why it is flaggable:** Claude Code always loads the skill description
into context and uses it as the primary signal for model-invocation —
whether Claude should auto-load the skill when it judges it relevant.
A stub that passes CSKILL-070 because *some* text is present still
gives the model nothing to select on and a reviewer nothing to weigh
the skill's `allowed-tools` against. That is the same selection-signal
failure CSDK-017 names for a tool docstring that reads
`"TODO: describe this tool"`, applied here to `SKILL.md` frontmatter.

**Real-world consequence:** A skill checked into a shared plugin with
`description: "TODO: fill this in"` is discoverable and model-invocable.
Claude treats the stub as the skill's entire selection signal, so it
either never auto-invokes a skill that would have been the right one,
or invokes it for the wrong job because the only remaining cue is the
directory name. A reviewer scanning `allowed-tools` has no stated
purpose against which to judge the grants.

**Why low and not medium:** A placeholder is a documentation gap, not
executed behavior. The skill's body and bundled scripts can still be
correct; the miss is that the field Claude and reviewers actually read
first is a stub. Not medium because the empty-description case
(CSKILL-070) is already the stronger signal, and this rule only fires
when *some* text is present.

**Fix type — config:** Replace the placeholder in the `description:`
frontmatter field — no source or bundled-file change needed.

**Confidence 0.85:** The six needles are the same closed list CSDK-017
uses, and they are uncommon as incidental English except `todo`, which
is a substring of `todos` / `todolist` — a description that says
"manages the user's todos" trips this rule with no placeholder intent.
`tbd`, `fixme`, `placeholder`, `no description`, and `does stuff` are
narrower. **False negatives:** a stub phrased outside the list
("coming soon", "WIP", "xxx", "fill me in", a single emoji) evades
the match entirely while remaining equally useless as a selection
signal.

---

## What this policy does not cover

- **Semantic verification.** Every rule here is lexical, not behavioral: a
  match proves a word appeared, never that the skill's actual behavior
  matches the claim. A skill can mention `encrypt` without ever encrypting
  anything (CSKILL-080 fires on a claim that may not correspond to real
  code at all), and a skill can implement genuinely correct error handling,
  purpose-scoping, or data minimization described in language none of these
  keyword lists anticipate.
- **Substring, not word-boundary, matching.** Every predicate is
  `strings.Contains`, so short or common fragments false-positive on
  unrelated words that happen to contain them: `sign` inside `design` /
  `assign` / `signal` (CSKILL-080), `secret` inside `secretary`
  (CSKILL-081), `audit` inside `auditorium` and `scan` inside `scanner`
  (CSKILL-082), `log` inside `catalog` / `dialog` / `logic` and `store`
  inside `restore` (CSKILL-086), `todo` inside `todos` (CSKILL-087).
- **Field asymmetry across rules.** CSKILL-080 scans name and description
  only, never body; CSKILL-084 and CSKILL-086 scan body only, never
  description; CSKILL-087 scans description only, never name or body; a
  skill can pass any given rule simply by moving the relevant language to
  a field that rule doesn't read.
- **Bundled-file content.** Unlike `skill_safety.yaml`'s CSKILL-010/011/030,
  none of these eight rules read a bundled script or data file — a skill
  whose `SKILL.md` prose is entirely clean while a bundled script performs
  the actual crypto, sensitive-data handling, or logging is invisible to
  this policy.
- **CSKILL-082's grant granularity.** The tool-grant half matches on
  `Tool` alone, so a narrowly scoped `Bash(git diff *)` grant fires
  identically to an unrestricted `Bash(*)` — the rule cannot tell a
  minimally-scoped remediation command from unrestricted shell.
- **Paraphrase evasion generally.** CSKILL-084's broad-access phrases and
  CSKILL-086's persistence verbs are closed lists; any rewording outside
  them (see each rule's confidence section for concrete examples) evades
  detection in both directions — a genuinely broad or persistent skill can
  evade the flag, and a narrow, ephemeral one can trip it on an incidental
  word.

---

## Recommendations beyond the fix

```yaml
---
name: release-notes-drafter
description: >
  Drafts release notes from merged commit messages, to enable consistent
  release-note entries at each release. Reads commit history only;
  writes nothing outside the current response.
allowed-tools: Read Grep Bash(git log *) Bash(git show *)
disable-model-invocation: true
---

Summarize commits since the last tag into grouped release-note bullets
(features, fixes, breaking changes).

Read only the commit range the user names — never the project's full
history — and quote each commit's own message rather than paraphrasing
scope you weren't given.

If the commit lookup errors or returns nothing for the requested range,
say so and ask the user to confirm the range; do not guess a fallback and
present it as the answer.

Nothing here outlives the current conversation turn.
```

1. **State purpose and boundary together.** Put the "to enable X" clause
   and the "reads only Y" clause in the same sentence, so a reviewer
   doesn't have to cross-reference two different parts of the file to
   judge whether the access is proportionate to the stated goal.
2. **Write guidance a user actually needs, not eight words that satisfy a
   linter.** CSKILL-083's keyword list is a floor, not a target — say
   concretely what happens on an empty result, an API error, or a partial
   match, in language that would help the next person reading the skill,
   not language chosen to trip the rule.
3. **Don't dodge CSKILL-081 by omission.** If a skill's purpose genuinely
   requires touching a password-reset flow or a PII lookup, name the field
   explicitly and state the retention boundary rather than avoiding the
   word to keep the rule quiet — a rule satisfied by omission is worse
   than one triggered honestly.
4. **Cross-reference [skill_safety.md](skill_safety.md).** Least-privilege
   tool grants and `disable-model-invocation` reduce this skill's blast
   radius on axes this text-match policy mostly cannot see — it reads
   `allowed-tools` only for CSKILL-082's specific name/grant pairing, not
   as a general check.
