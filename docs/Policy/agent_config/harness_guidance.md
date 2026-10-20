---
policy_id: agent_config_harness_guidance
category: agent_config
topic: harness_guidance
rules:
  - id: AGCFG-010
    severity: medium
    confidence: 0.6
    scope: repo
    fix_type: config
references: [LLM01]
---

# Policy Rationale: Hidden Text in Harness Guidance Files

**Policy ID:** `agent_config_harness_guidance`  
**File:** `agent_config/harness_guidance.yaml`  
**Rules:** AGCFG-010  
**Severities:** medium  
**Fix types:** config  
**References:** LLM01 (Prompt Injection)

---

## What this policy covers

Some agent adaptation frameworks keep an agent's configuration as a tree of plain
files that a separate process proposes edits to and a person later adopts or
reviews. The default OpenCode layout that one such framework stages looks like this:
`systemprompt.md`, `guardrails.md`, `LongTermMEMORY.md` and
`tool_descriptions/tool_guidance.md` at the root, with `scripts/`, `skills/`,
`sub_agents/` and `plugin/` beside them. The agent reads those files as
instructions. A reviewer sees them as rendered text.

This policy has one rule. **AGCFG-010** flags objectively hidden text in those
guidance files: zero-width characters, Unicode Tags-block characters
(U+E0000 to U+E007F), and bidirectional override characters. It is repo scope and
fires once per scan, attributed to the first path-sorted offending file and the line
of its first occurrence. It applies only to a directory that holds a
`systemprompt.md` and a `guardrails.md` side by side, because either name alone is
too common to treat as a harness file. The pack loads for every scan; the rule's
own predicate does the gating.

AGCFG-010 is the same character test as AGCFG-009, which covers `AGENTS.md`, applied
to a different set of files. They are separate rules with separate predicates on
purpose: widening AGCFG-009's predicate would silently change what an older engine
evaluates.

---

## Why hidden text is a distinct concern in a harness

A harness is edited over time, often by a process rather than a person, and adopted
after a review that is usually done on rendered text. That is the gap an invisible
character exploits. Tags-block characters mirror ASCII and render as nothing, so a
whole sentence can ride along in an otherwise ordinary line ("ASCII smuggling").
Bidirectional overrides change the order in which text is displayed without changing
the order in which it is read (the Trojan-Source technique).

The files in question are the ones the agent trusts most: the system prompt, the
guardrails that are meant to limit it, and its long-term memory. An instruction that
a reviewer cannot see in the guardrails file is the worst place for it to be.

---

## Rule-by-rule defense

### AGCFG-010 — Harness guidance file contains invisible or direction-overriding text (Severity: medium, Confidence: 0.6, Fix type: config)

**What we detect:** in `systemprompt.md`, `guardrails.md`, `LongTermMEMORY.md` or
`tool_descriptions/*.md` under a staged harness root, any of (a) zero-width
characters: U+200B, U+200C, U+200D, or U+FEFF; (b) Unicode Tags-block characters
U+E0000 to U+E007F; (c) bidirectional controls U+202A to U+202E or U+2066 to U+2069.
Gated by `repo_harness_guidance_has_hidden_text`. One finding carries the first
offending file and line. The hidden text itself is never echoed.

**What is exempt, so ordinary files are not flagged:** a byte order mark at the very
start of the file; a zero-width joiner or non-joiner between two non-ASCII
characters of the same kind (emoji sequences, or letters in scripts such as Persian
and Hindi); and a subdivision-flag emoji, which is the one legitimate use of the
Tags block. A run of adjacent zero-width characters, or one placed inside ASCII
text, is not exempt. These are the same exemptions as AGCFG-009. An empty file, such
as a baseline `guardrails.md` that has no rules yet, is not flagged.

**Why it is flaggable:** none of these characters has a reason to appear in plain
English guidance. A single invisible character inside an ASCII sentence, or any
Tags-block run that is not a flag emoji, is the carrier pattern.

**Real-world consequence:** an adopted harness's `guardrails.md` gains a line that
looks like ordinary policy. It also carries a Tags-block payload telling the agent to
ignore the guardrail above it. The reviewer sees the same text as before and adopts
the harness, and the agent follows the hidden instruction on every later task.

**Why severity is medium and not higher:** the file is not executable and acts only
through an agent that follows it, and the agent's own controls still apply. It is
above low because the instruction sits in the files the agent trusts most and a human
review cannot see it. It matches AGCFG-009 and the skill injection-marker rule.

**Fix type — config:** remove the characters, and retype any line that carried them,
since they are easy to paste back in.

**Confidence 0.6:** the same figure as AGCFG-009, for the same reason. The character
test is exact, but right-to-left prose that uses bidirectional controls is flagged and
is a known false positive, and some scripts use joiners in ways the exemption does not
cover. The directory signature adds one more limit: a docs folder that happens to hold
both a `systemprompt.md` and a `guardrails.md` is treated as a harness root. A hit
means "look at this line with a tool that shows hidden characters", not "this harness
is malicious".

---

## What this policy does not cover

- What the instructions say. A visible instruction that tells the agent to do
  something harmful is not judged here.
- The `scripts/`, `plugin/` and `sub_agents/` parts of the harness. They are
  inventoried by the scanner but no rule reads their content.
- Harness layouts that do not hold a `systemprompt.md` and a `guardrails.md` side by
  side, and other invisible or confusable characters such as homoglyphs, the word
  joiner U+2060 and variation selectors.
- Text hidden by other means, such as HTML comments or very long lines.
- Whether a person reviewed the harness, or how it was adopted.

---

## Recommendations beyond the fix

1. Review harness changes with a tool that shows hidden characters before adopting
   them, and treat a change you cannot fully see as unreviewed.
2. Keep guidance in plain visible text, and avoid pasting from sources that may carry
   invisible characters.
3. Check the guardrails file in particular. It is the file whose job is to limit the
   agent.
4. Re-run the scan after editing, since retyped lines can reintroduce the characters if
   they are pasted.
