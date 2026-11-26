---
policy_id: agent_config_guidance_instructions
category: agent_config
topic: guidance_instructions
rules:
  - id: AGCFG-022
    severity: high
    confidence: 0.4
    scope: repo
    fix_type: config
references: []
---

# Policy Rationale: Agent Guidance Files That Instruct Risky Actions

**Policy ID:** `agent_config_guidance_instructions`  
**File:** `agent_config/guidance_instructions.yaml`  
**Rules:** AGCFG-022  
**Severities:** high  
**Fix types:** config  
**References:** none

> **Verification status.** The two papers cited below were read on 2026-11-26 as abstracts
> through the arXiv API (`export.arxiv.org`), not as full texts. **Not verified, and
> therefore not assumed:** which phrases the attack rules in those papers use; whether any
> assistant follows each of the four instruction types the pack lists; and whether real
> project files contain them. The phrase lists are this pack's own choice. The pack's
> precision on real guidance files is measured on the small sample in the batch report
> and nowhere else.

---

## What this policy covers

Coding assistants read files such as AGENTS.md, CLAUDE.md, GEMINI.md, Cursor `.mdc` rules,
Windsurf and Devin rules and the GitHub Copilot instruction files as instructions. The pack
loads for each scan, because the files it reads have no SDK import; the rule's predicate does
the gating.

This policy has one rule. **AGCFG-022** flags a sentence in one of those files that tells the
agent to pipe a download into a shell, read or send a credential file, switch off its approval
or sandbox, or push to a URL or mirror. It is repo scope and fires once per scan, attributed
to the first matching sentence. AGCFG-009 and AGCFG-013 read the same files for hidden
characters; this rule reads visible words, so the conditions do not overlap.

---

## Rule-by-rule defense

### AGCFG-022 - An agent guidance file instructs a risky action (Severity: high, Confidence: 0.4, Fix type: config)

**What we detect:** a sentence, split at a line break or at a full stop, exclamation mark or
question mark followed by a space, that matches one of five fixed groups, gated by
`repo_guidance_text_matches`:

- a pipe into `sh`, `bash`, `zsh` or `python` with `curl` or `wget` in the same sentence, or
  `bash <(curl`, `sh <(wget` and the like;
- a credential path (`~/.ssh`, `id_rsa`, `id_ed25519`, `.aws/credentials`, `~/.npmrc`,
  `~/.netrc`, `.git-credentials`, `~/.docker/config.json`, `~/.kube/config`) with a word for
  reading or sending in the same sentence, and no mention of an example or a gitignore;
- an approval or sandbox bypass flag or phrase (`--dangerously-skip-permissions`,
  `--dangerously-bypass-approvals-and-sandbox`, `--yolo`, `bypassPermissions`,
  `dangerouslyDisableSandbox`, "skip permissions", "bypass approvals" and the like);
- `git push` to an `http://`, `https://`, `git@` or `ssh://` URL, or `git push --mirror`.

A sentence that contains a word of refusal (do not, don't, avoid, must not, should not,
forbidden, prohibited, refuse) is skipped before any group is tried.

**Why it is flaggable.** The papers below describe rule files as an attack surface. They do
not list the phrases above. The mapping from a phrase to a risk is the pack's own: a pipe from
`curl` into a shell runs whatever the server returns on each run; a credential path with a read
verb names a secret the task has no stated need for; an approval bypass flag removes the prompt that
stands between an instruction and its effect; a push to a URL sends the repository to a
location the project has not configured as a remote.

**The problem class in the literature.**

- *Aletheia: Permission-Minimality Testing for Coding-Agent Rules* (arXiv 2609.39678, submitted
  30 September 2026). The abstract says coding agents read repository rules such as AGENTS.md
  and Cursor rules, and that "an attacker can exploit the same files to mislead the agent into
  requesting excessive permissions or performing unrelated operations, such as accessing
  credentials or transferring data".
- *GitInject: Real-World Prompt Injection Attacks in AI-Powered CI/CD Pipelines* (arXiv
  2606.09935, submitted 7 June 2026). The abstract says that "attacker-controlled configuration
  files from an unmerged contribution are loaded as operator-level instructions, allowing the
  agent--infrastructure interaction to expose credentials or corrupt review judgments".

Both are cited for that problem class and nothing more. Neither studies a check by reading a
file for fixed phrases. The pack sets severity high and states no reasoning for it.

**Real-world consequence:** an agent that follows one of these sentences runs a downloaded
script, reads or sends a secret, runs without its prompts, or pushes the repository elsewhere,
using the access of the developer or the CI job that started it.

**Fix type - config:** the fix edits the guidance file: remove the instruction or move it to a
script a person runs; link to a vendor's install page and pin a version and checksum instead of
piping a download into a shell; give the agent the narrowest credential through its own
environment; keep approval prompts on; push through a named remote. No tool source changes.

**Confidence 0.4:** the pack's explanation states these limits of the check:

- It reads fixed phrases in one sentence at a time.
- It cannot tell an instruction for a person from an instruction for the agent, so a project
  that documents a curl-to-shell installer for its own tool matches and is a false positive.
- A credential sentence needs a read or send word in the same sentence.
- Paraphrases, other languages, instructions split across sentences, encoded text and files
  outside the listed names (including `.clinerules` and `.cursorrules`) are not read.
- A push to a remote added earlier is not flagged.

---

## What this policy does not cover

- Hidden characters in guidance files (AGCFG-009, AGCFG-013).
- Install commands and package indexes in guidance files (AGCFG-023).
- Guidance files not on the list, and `SKILL.md` files (CSKILL rules).
- The truth of any instruction; the rule reads words, not behavior.

---

## Recommendations beyond the fix

1. Keep installers in a build step with a pinned version and checksum.
2. Give the agent a task-scoped credential through its environment.
3. Leave approval prompts on for a repository you did not write.
4. Review changes to guidance files in pull requests like code.

---

## Sources

- Aletheia, arXiv 2609.39678, abstract retrieved 2026-11-26. Cited for the problem class.
- GitInject, arXiv 2606.09935, abstract retrieved 2026-11-26. Cited for the problem class.
