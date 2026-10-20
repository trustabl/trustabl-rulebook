---
policy_id: agent_config_agents_md
category: agent_config
topic: agents_md
rules:
  - id: AGCFG-009
    severity: medium
    confidence: 0.6
    scope: repo
    fix_type: config
references: [LLM01]
---

# Policy Rationale: Hidden Text in AGENTS.md

**Policy ID:** `agent_config_agents_md`  
**File:** `agent_config/agents_md.yaml`  
**Rules:** AGCFG-009  
**Severities:** medium  
**Fix types:** config  
**References:** LLM01 (Prompt Injection)

---

## What this policy covers

`AGENTS.md` is the vendor-neutral guidance file that coding agents read from a
repository before they act. The agent treats it as instructions, and a human
reviewer sees it as rendered text. Any character that is invisible, or that
reorders what a reviewer sees, opens a gap between the two: an instruction can be
present for the model and absent for the person approving the change.

This policy has one rule. **AGCFG-009** flags an `AGENTS.md`, at any depth, that
contains zero-width characters, Unicode Tags-block characters
(U+E0000 to U+E007F), or bidirectional override characters. It is repo scope and
fires once per scan, attributed to the first path-sorted offending file and the
line of its first occurrence. The pack loads for every scan, because the file
exists whether or not the repo imports an SDK; the rule's own predicate does the
gating.

The rule is an objective code-point test. It does not judge what the instructions
say, and it reuses the same character checks as the skill injection markers
(CSKILL-040).

---

## Why hidden text is a distinct concern in a guidance file

A guidance file is high-trust and low-scrutiny. Agents follow it without asking,
and reviewers skim it, because it reads like documentation. A pull request that
changes one line of an `AGENTS.md` looks harmless in a diff viewer that does not
show invisible characters. Tags-block characters mirror ASCII and render as
nothing, so a whole sentence can be carried that way ("ASCII smuggling").
Bidirectional overrides change the order in which text is displayed without
changing the order in which it is read (the Trojan-Source technique).

Because the file is committed, whoever can land a change to it controls what the
agent is told, including a contributor who only has permission to propose
changes. The hidden form is the version of that risk a human review cannot catch.

---

## Rule-by-rule defense

### AGCFG-009 — AGENTS.md contains invisible or direction-overriding text (Severity: medium, Confidence: 0.6, Fix type: config)

**What we detect:** in a file named `AGENTS.md` (or `agents.md`) at any depth, any of
(a) zero-width characters: U+200B, U+200C, U+200D, or U+FEFF; (b) Unicode
Tags-block characters U+E0000 to U+E007F; (c) bidirectional controls U+202A to
U+202E or U+2066 to U+2069. Gated by `repo_agents_md_has_hidden_text`. One finding
carries the first offending file and line. The hidden text itself is never echoed.

**What is exempt, so ordinary files are not flagged:** a byte order mark at the
very start of the file; a zero-width joiner or non-joiner that sits between two
non-ASCII characters of the same kind, as in emoji sequences or in scripts such as
Persian and Hindi; and a subdivision-flag emoji, which is the one legitimate use of
the Tags block (a black-flag base followed by tags ending in the cancel tag). A
run of adjacent zero-width characters, or one placed inside ASCII text, is not
exempt.

**Why it is flaggable:** none of these characters has a reason to appear in plain
English guidance. A single invisible character inside an ASCII sentence, or any
Tags-block run that is not a flag emoji, is the carrier pattern.

**Real-world consequence:** a contributor opens a pull request that fixes a typo in
`AGENTS.md`. One line also carries a Tags-block payload that tells the agent to
send the contents of an environment file to a URL. The diff shows only the typo.
Once merged, every developer whose agent reads the file receives the instruction.

**Why severity is medium and not higher:** the file is not executable and acts only
through an agent that chooses to follow it, and the agent's own approval prompts
still apply. It is above low because the instruction reaches every user of the
repo and a human review cannot see it.

**Fix type — config:** remove the characters, and retype any line that carried them,
since they are easy to paste back in.

**Confidence 0.6:** the same figure as CSKILL-040, for the same reason. The
character test is exact, but the cases it cannot tell apart from an attack are real:
right-to-left prose that uses bidirectional controls is flagged and is a known false
positive, and some scripts use joiners in ways the exemption does not cover. A hit
means "look at this line with a tool that shows hidden characters", not "this file is
malicious".

---

## What this policy does not cover

- What the instructions say. A visible instruction that tells the agent to do
  something harmful is not judged here.
- `CLAUDE.md`, `.cursorrules` and other agent guidance files. Only `AGENTS.md` is
  read.
- Other invisible or confusable characters, such as homoglyphs, the word joiner
  U+2060 and variation selectors.
- Text hidden by other means, such as HTML comments, collapsed sections or very long
  lines.
- Whether the file is tracked by git. The scanner sees the working tree.

---

## Recommendations beyond the fix

1. Review `AGENTS.md` changes with a tool that shows hidden characters, and treat a
   change you cannot fully see as unreviewed.
2. Keep guidance in plain visible text, and avoid pasting from sources that may carry
   invisible characters.
3. Restrict who can change guidance files, and require review for them as you would
   for CI definitions.
4. Re-run the scan after editing, since retyped lines can reintroduce the characters
   if they are pasted.
