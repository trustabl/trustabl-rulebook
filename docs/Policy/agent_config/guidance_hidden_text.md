---
policy_id: agent_config_guidance_hidden_text
category: agent_config
topic: guidance_hidden_text
rules:
  - id: AGCFG-013
    severity: medium
    confidence: 0.6
    scope: repo
    fix_type: config
references: [LLM01]
---

# Policy Rationale: Hidden Text in Agent Guidance Files

**Policy ID:** `agent_config_guidance_hidden_text`  
**File:** `agent_config/guidance_hidden_text.yaml`  
**Rules:** AGCFG-013  
**Severities:** medium  
**Fix types:** config  
**References:** LLM01 (Prompt Injection)

> **Verification status.** The vendor behavior below was read on 2026-10-29 from these
> pages: Claude Code, "How Claude remembers your project" (`code.claude.com/docs/en/memory`);
> Gemini CLI, "GEMINI.md" (`geminicli.com/docs/cli/gemini-md/`); Cursor, "Rules"
> (`cursor.com/docs/context/rules`); Windsurf, "Memories and rules"
> (`docs.devin.ai/desktop/cascade/memories`, the address `docs.windsurf.com` redirects to);
> GitHub Copilot, "Adding repository custom instructions"
> (`docs.github.com/en/copilot/how-tos/configure-custom-instructions/add-repository-instructions`).
> The advisory and the paper cited below were read on 2026-10-29. **Not verified, and
> therefore not assumed:** whether any of these tools removes or ignores invisible or
> direction-overriding characters before loading a file (none of the pages read says so);
> whether any tool other than Claude Code removes HTML comments; which Copilot surfaces
> load a path-specific instructions file beyond the two the page names; and the behavior
> of versions older than the pages read on that day.

---

## What this policy covers

Coding agents load guidance files from a repository and treat them as instructions,
while a human reviewer reads the same file as rendered text or as a diff. Any character
that is invisible, or that reorders what a reviewer sees, opens a gap between the two:
an instruction can be present for the model and absent for the person approving the
change.

This policy has one rule. **AGCFG-013** flags a committed guidance file that contains
zero-width characters, Unicode Tags-block characters (U+E0000 to U+E007F), or
bidirectional override characters. The files it reads are `CLAUDE.md` (any depth),
`GEMINI.md` (any depth), `.cursor/rules/**/*.mdc`, `.windsurfrules`,
`.windsurf/rules/*.md`, `.devin/rules/*.md`, `.github/copilot-instructions.md` and
`.github/instructions/**/*.instructions.md`, with each path other than `CLAUDE.md` and
`GEMINI.md` taken from the repo root. It is repo scope and fires once per scan,
attributed to the first path-sorted offending file and the line of its first occurrence.
The pack loads for each scan, because the files have no SDK import; the rule's own
predicate does the gating.

It runs the same code-point test as **AGCFG-009** (`AGENTS.md`) and **AGCFG-010** (staged
OpenCode guidance files) over files those rules do not read, so one file produces one
finding. `SKILL.md` stays with **CSKILL-040**.

---

## Why a guidance file is flaggable

The tools below load these files into the agent's context without a step that asks the
user to approve their text:

- Claude Code reads `./CLAUDE.md` or `./.claude/CLAUDE.md` at the start of a session
  (Claude Code memory page).
- Gemini CLI searches the workspace directories and their parents for `GEMINI.md`, and
  "All found files are concatenated and sent to the model" (Gemini CLI page).
- Cursor includes a project rule in the session when its front matter sets the
  apply-in-session field to true, and attaches a rule with a glob when a matching file is
  in context; project rules are `.mdc` files under `.cursor/rules` (Cursor page).
- Windsurf puts a rule in its first activation mode (the full rule) into the system prompt
  on each message; it reads `.devin/rules/*.md`, falls back to `.windsurf/rules/*.md`, and
  still reads the legacy `.windsurfrules` (Windsurf page).
- GitHub Copilot adds `.github/copilot-instructions.md` automatically to requests, and
  applies a `.github/instructions/NAME.instructions.md` file through its `applyTo` glob
  for the cloud agent and code review (Copilot page).

The paper cited below states the same property for a harness it studied: it "treats
AGENTS.md (and CLAUDE.md) as trusted system-level instructions and loads them into the
session".

A Tags-block character mirrors an ASCII character and renders as nothing, so a sentence
can be carried in it. A bidirectional override changes the order in which text is
displayed without changing the order in which it is read. A zero-width character is
invisible inside a sentence. The advisory below describes an attack that hides
instructions in a rule file with zero-width joiners and bidirectional text markers.

---

## Rule-by-rule defense

### AGCFG-013 — Agent guidance file contains invisible or direction-overriding text (Severity: medium, Confidence: 0.6, Fix type: config)

**What we detect:** in a file of the kinds listed above, any of (a) zero-width characters:
U+200B, U+200C, U+200D, or U+FEFF; (b) Unicode Tags-block characters U+E0000 to U+E007F;
(c) bidirectional controls U+202A to U+202E or U+2066 to U+2069. Gated by
`repo_guidance_file_has_hidden_text`. The hidden text itself is not echoed: the hit
carries a fixed reason string, the path and the line. A hit inside a fenced code block
counts, exactly as it does for AGCFG-009, because the test reads code points and does not
parse Markdown.

**What is exempt, so ordinary files are not flagged:** the same exemptions as AGCFG-009.
A byte order mark at the very start of the file; a zero-width joiner or non-joiner between
two non-ASCII characters of the same kind, as in emoji sequences or in scripts such as
Persian and Hindi; and a subdivision-flag emoji, which is the one legitimate use of the
Tags block. A run of adjacent zero-width characters, or one placed inside ASCII text, is
not exempt.

**Why it is flaggable:** see the section above. The loading behavior is taken from each
vendor's page; the pack states no further reasoning for treating these characters as a
signal.

**Real-world consequence:** the advisory cited below reports that hidden characters in a
rule file let an attacker "silently manipulate AI-generated code output", and that the
technique was demonstrated against Cursor and GitHub Copilot. It also reports that GitHub
added a warning on github.com for files containing hidden Unicode text on 2025-05-01.

**Severity:** the pack sets medium and states no reasoning for it.

**Fix type — config:** remove the characters, and retype any line that carried them,
since they are easy to paste back in.

**Confidence 0.6:** the pack sets 0.6 and states no reasoning for it. The rule YAML states
that right-to-left prose that uses bidirectional controls is flagged and is a known false
positive.

---

## What this policy does not cover

- What the instructions say. A visible instruction that tells the agent to do something
  harmful is not judged here.
- HTML comments, instruction-override phrases and encoded text. None is tested. Claude
  Code's memory page states that block-level HTML comments in `CLAUDE.md` are stripped
  before the content reaches Claude's context and that comments inside code blocks are
  preserved; the other pages read do not say.
- A `.cursorrules` file, a Cursor rule that is not a `.mdc` file, and any guidance file
  outside the paths listed above, including nested copies of the paths that are read from
  the repo root.
- `AGENTS.md` (AGCFG-009), staged OpenCode guidance files (AGCFG-010) and `SKILL.md`
  (CSKILL-040).
- Other invisible or confusable characters, such as homoglyphs, the word joiner U+2060 and
  variation selectors.
- Whether any tool removes these characters before loading a file; the pages read do not
  say.
- Whether the file is tracked by git. The scanner reads the working tree.
- A file over the scan's per-file size cap (10 MiB) is not read.

---

## Recommendations beyond the fix

1. Review guidance-file changes with a tool that shows hidden characters, and treat a
   change you cannot fully see as unreviewed.
2. Keep guidance in plain visible text, and avoid pasting from sources that may carry
   invisible characters.
3. Require review for guidance files as you would for CI definitions.
4. Re-run the scan after editing, since retyped lines can reintroduce the characters if
   they are pasted.

---

## Sources

- Ziv Karliner, "New Vulnerability in GitHub Copilot and Cursor: How Hackers Can Weaponize
  Code Agents", Pillar Security, 2025-03-18. Retrieved 2026-10-29. Cited for the
  description of hidden zero-width joiners and bidirectional text markers in a Cursor rule
  file, the quoted sentence on AI-generated code output, and the GitHub warning date, and
  nothing more.
- Alexandre G.R. Day, Pradeep Yadlapalli, Sriram Venkatapathy, Thomas Paniagua, Nick
  Raines, Sahil Wadhwa, Himanshu Kumar, Andy Luo, Sudeep Panyam, Rikhiya Ghosh, Pranab
  Mohanty and Giri Iyengar, "Workspace Topology as an Attack Vector in Agentic Coding
  Assistants", arXiv:2608.14876, submitted 2026-08-14, Section 6.2. Retrieved 2026-10-29.
  Cited for the sentence on a harness treating `AGENTS.md` and `CLAUDE.md` as trusted
  system-level instructions, and nothing more. It does not test hidden characters.
- Anthropic, "How Claude remembers your project", `code.claude.com/docs/en/memory`.
  Retrieved 2026-10-29. Cited for `CLAUDE.md` loading and the HTML-comment statement, and
  nothing more.
- Gemini CLI documentation, "GEMINI.md", `geminicli.com/docs/cli/gemini-md/`. Retrieved
  2026-10-29. Cited for `GEMINI.md` discovery and loading, and nothing more.
- Cursor documentation, "Rules", `cursor.com/docs/context/rules`. Retrieved 2026-10-29.
  Cited for project-rule location, the `.mdc` extension and the apply-in-session and glob
  behavior, and nothing more.
- Windsurf documentation, "Memories and rules", `docs.devin.ai/desktop/cascade/memories`.
  Retrieved 2026-10-29. Cited for rule locations and the first activation mode, and nothing
  more.
- GitHub documentation, "Adding repository custom instructions for GitHub Copilot",
  `docs.github.com`. Retrieved 2026-10-29. Cited for the two instruction file forms and
  how they are added to requests, and nothing more.
