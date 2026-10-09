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
references: [LLM02, LLM05, LLM06, AST03]
---

# Policy Rationale: Agent Skill Quality (Text-Match)

**Policy ID:** `claude_skill_quality_text`  
**File:** `claude_skill/skill_quality_text.yaml`  
**Rules:** CSKILL-080, CSKILL-081, CSKILL-082, CSKILL-083, CSKILL-084, CSKILL-085, CSKILL-086  
**Severities:** high, high, high, low, medium, low, medium  
**Fix types:** config — all seven rules fix by editing `SKILL.md` prose (name, description, or body); none require a bundled-file or code change  
**References:** OWASP LLM Top 10:2025 — LLM02, LLM05, LLM06 · OWASP Agentic Skills Top 10 — AST03

> This is the **second** `claude_skill` rule file. [`skill_safety.yaml`](skill_safety.md)
> detects structural/config facts read directly off the parsed `SkillDef` —
> tool grants, dynamic-context grammar, bundled-file contents. Every rule
> here instead runs a free-text keyword or phrase search over the skill's
> `name`, `description`, or `body` string. None of these seven rules read
> bundled files, and — except CSKILL-082 — none read `allowed-tools` either.
> Detection and threat model are both different; hence a separate file and a
> separate doc, not an addendum to `skill_safety.md`.

---

## What this policy covers

Seven quality and data-governance rules over Claude Code Agent Skills
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

Unlike a single-threat-model policy, this file's seven rules split cleanly
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
CSKILL-085, CSKILL-086).** These four rules are not attacks; they are
documentation gaps that degrade how predictably a skill behaves. A skill with
no error-handling language gives Claude no guidance on the unhappy path
(**LLM05, Improper Output Handling** — the same category `google_adk`'s and
`claude_sdk`'s error-handling rules cite, extended here to skill *prose*
rather than tool *code*). A skill with no stated purpose gives a reviewer
nothing to weigh its access against. A skill that implies it writes,
caches, or logs data with no retention statement leaves that data's
lifetime undefined. None of these four map cleanly to a single OWASP
LLM Top 10 category — CSKILL-085 in particular is pure documentation
hygiene with no external taxonomy hook — and this doc says so rather than
forcing a citation that wouldn't survive scrutiny.

---

## Rule-by-rule defense

### CSKILL-080 — Skill claims cryptographic operations (Severity: high, Confidence: 0.75, Fix type: config)

**What we detect:** `skill_text_matches` over the skill's `name` and
`description` fields against `crypto`, `cryptographic`, `encrypt`, `decrypt`,
`cipher`, `certificate`, `keypair`, `private key`, `sign`, `signature`,
`hash`, `hmac`, `asymmetric`, `symmetric`, with `exclude_context: [example,
for instance, e.g., such as, sample, documented, documentation, see the,
refer to, placeholder]`. Unlike the raw-substring `skill_*_has_text`
predicates, this splits each field into sentences and matches terms at word
boundaries (allowing inflections — `sign` also matches `signs`/`signed`/
`signing`, but not `design`/`assign`/`signal`), then discards a sentence hit
that also matches an exclude-context phrase (a documentation pointer or a
worked example, not a claim the skill itself performs the operation). The
body is still never scanned by this rule. This replaced a bare
`skill_name_has_text`/`skill_description_has_text` substring match after
confirmed false positives from outreach feedback: a skill listing "hash a
string" as an example tool call, and a substring artifact where a common
word fragment (not a whole-word crypto term) tripped the old match.

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

**Confidence 0.75:** Word-boundary matching with inflection support closes
the substring-artifact false positives the raw predicate had (`design`,
`assign`, `signal`, `hashmap` no longer match `sign`/`hash`), and
`exclude_context` closes the confirmed "worked example" false positive
("for example, hash a string" no longer fires). `certificate` still has a
legitimate non-crypto sense (a completion certificate) with no exclude-
context phrase to catch it, which is the residual false-positive surface.
**False negatives:** a skill can genuinely implement crypto described
entirely in the body using terms this rule doesn't scan for at all (`AEAD`,
`JWT`, `PGP`, `bcrypt`, `argon2`), or the crypto terms can appear only in the
body, which CSKILL-080 never reads; a term wrapped in an exclude-context
phrase that is not actually documentation-only ("for instance, this skill
encrypts every file it touches" — a genuine claim, not an example) also goes
silent, since the predicate cannot distinguish rhetorical framing from a
real disclaimer.

### CSKILL-081 — Skill processes sensitive data (Severity: high, Confidence: 0.7, Fix type: config)

**What we detect:** `skill_text_matches` over the skill's `description` and
`body` fields against a sensitive-data-class term list (`password`, `secret`,
`credential`, `token`, `api key`, `ssn`, `social security`, `credit card`,
`pii`, `personal data`, `sensitive data`, `confidential`, `private key`),
requiring the SAME sentence to also match an operational-verb term
(`require_context`: `read`, `write`, `store`, `save`, `send`, `transmit`,
`collect`, `process`, `handle`, `log`, `extract`, `parse`, `redact`,
`encrypt`, `upload`, `post`, `fetch`, `retrieve`, `access`), and discarding a
sentence that also matches `exclude_context` (`lives in`, `live in`,
`configured in`, `see the`, `documentation`, `example`, `for instance`,
`e.g.`). This replaced a bare `skill_body_has_text`/
`skill_description_has_text` substring match after confirmed false
positives from outreach feedback: a skill documenting "API keys live in
GitHub Actions secrets" was flagged for merely naming where a credential
lives, with no claim the skill itself touches it.

**Why it is flaggable:** Naming a sensitive-data class in the same sentence
as an operational verb — reads it, stores it, sends it — is a claim that the
skill actually handles that data, not just a reference to it, and doing so
without stating a data-minimization boundary leaves no way for a reviewer to
check whether the skill only touches the fields the task requires or
retains everything it touches.

**Real-world consequence:** A "customer-support" skill's body reads:
"look up the account using the customer's SSN and password" with no
stated minimization or retention rule. Whatever tool call executes that
lookup, and whatever gets echoed back into the transcript, now carries
those fields with no documented boundary on where they end up next.

**Why high and not critical:** A keyword-plus-verb hit proves the sentence
*claims* to handle the data, not that the skill's actual tool calls do so
correctly — it could still be defensive language phrased as an operation
("never send the customer's password anywhere") that the `require_context`
check cannot distinguish from a real one. Real damage depends on what the
skill's tool calls (invisible to this rule) actually do with the field once
named.

**Fix type — config:** State which fields are read, why, and for how
long — a description/body edit.

**Confidence 0.7:** The `require_context` same-sentence check closes the
confirmed "merely named, not handled" false positive (a sentence naming
where a credential lives, with no operational verb, no longer fires), and
word-boundary matching plus `sensitive data` (rather than a bare `sensitive`)
closes substring artifacts like `case-insensitive`. Overloaded terms remain
a residual gap: "the department secretary handles the request" would not
false-fire on `secret` (word boundaries now require the whole word, and
`secretary` is not a generated inflection of `secret`), but a sentence like
"store the pagination token" or "the session token expires" still fires,
since `token` in its routine engineering sense is indistinguishable from a
credential token by this rule. **False negatives:** sensitive fields named
by domain-specific terms outside this list — date of birth, routing number,
medical record number, passport number — are invisible to the rule, as is a
handling claim split across two sentences (e.g. "Handles customer PII." next
sentence: "Reads it from the request body.") since `require_context` only
looks within the same sentence as the data-class term.

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

---

## What this policy does not cover

- **Semantic verification.** Every rule here is lexical, not behavioral: a
  match proves a word appeared, never that the skill's actual behavior
  matches the claim. A skill can mention `encrypt` without ever encrypting
  anything (CSKILL-080 fires on a claim that may not correspond to real
  code at all), and a skill can implement genuinely correct error handling,
  purpose-scoping, or data minimization described in language none of these
  keyword lists anticipate.
- **Substring, not word-boundary, matching — CSKILL-082..087 only.**
  CSKILL-080 and CSKILL-081 were moved onto `skill_text_matches`, a
  sentence-scoped, word-boundary predicate (see their entries above); the
  remaining five rules in this pack still use the raw-substring
  `skill_*_has_text` predicates (`strings.Contains`), so short or common
  fragments still false-positive on unrelated words that happen to contain
  them: `audit` inside `auditorium` and `scan` inside `scanner` (CSKILL-082),
  `log` inside `catalog` / `dialog` / `logic` and `store` inside `restore`
  (CSKILL-086). These five were not moved onto the new predicate because no
  confirmed false positive has been reported against them yet — see
  `CLAUDE.md`'s two-repo rule model for the sync obligation this would carry
  if the fixture ever changed here without a matching production change.
- **Field asymmetry across rules.** CSKILL-080 scans name and description
  only, never body; CSKILL-084 and CSKILL-086 scan body only, never
  description; a skill can pass any given rule simply by moving the
  relevant language to a field that rule doesn't read.
- **Bundled-file content.** Unlike `skill_safety.yaml`'s CSKILL-010/011/030,
  none of these seven rules read a bundled script or data file — a skill
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
