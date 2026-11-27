---
policy_id: ci_agent_pr_controls
category: ci
topic: agent_pr_controls
rules:
  - id: CI-006
    severity: high
    confidence: 0.5
    scope: repo
    fix_type: code
  - id: CI-007
    severity: high
    confidence: 0.4
    scope: repo
    fix_type: config
references: [LLM06]
---

# Policy Rationale: Agent-Invocable Pull Request Approval and Code Ownership

**Policy ID:** `ci_agent_pr_controls`  
**File:** `ci/agent_pr_controls.yaml`  
**Rules:** CI-006, CI-007  
**Severities:** high, high  
**Fix types:** code, config  
**References:** LLM06

> **Verification status.** The three papers cited below were read on 2026-11-27 as abstracts on
> their arXiv pages. The GitHub CLI manual pages for `gh pr review` and `gh pr merge` and the
> GitHub CODEOWNERS page were retrieved on 2026-11-27. **Not verified, and therefore not
> assumed:** that any paper's setting matches a repo this rule reports; which identity a
> reported command runs as; whether branch protection or a ruleset requires code owner review in a
> reported repo. The scan reads repo files and has no GitHub API input.

---

## What this policy covers

Two repo-scope rules about the controls around a pull request when a coding agent works in the
repo. Both are narrower than the planning sheet rows they come from (CI-012, CI-009 and CI-010);
the halves that need pull request metadata, branch protection or the GitHub API are not built.
CI-006 loads for any scan that finds agent configuration; CI-007 loads with the other CI rules.

---

## Rule-by-rule defense

### CI-006 - Agent-invocable code approves a pull request or merges it with administrator privileges (Severity: high, Confidence: 0.5, Fix type: code)

**What we detect:** gated by `repo_agent_code_approves_prs`, a command line that runs `gh pr
review` with `--approve` (or `-a`), or `gh pr merge` with `--admin`, in: a fenced code block of a
SKILL.md or a slash command file, a script bundled in a skill, a command of a Claude Code settings
hook, or a `.sh` file under `.claude/`. The command word must start a shell segment.

**Why it is flaggable.** The GitHub CLI manual describes `--approve` as "Approve pull request"
and `--admin` as "Use administrator privileges to merge a pull request that does not meet
requirements". *Who Approved This?* (arXiv 2610.28683, submitted 19 October 2026) reports a
startup whose merge gate required a non-author approval and draws the lesson of "keeping agents'
credentials away from the controls they operate under". Code the agent can invoke that approves
or bypasses the gate puts the control inside the agent's reach. The paper is cited for that
lesson and does not study this command pattern.

**Real-world consequence:** a pull request is approved or merged by the agent's session, under
the account that session holds.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Fix type - code:** remove the command from the agent's skills, commands and hooks.

**Confidence 0.5:** the pack's explanation states these limits:

- Prose, inline code and comment lines are not read; workflow run steps and ordinary repo scripts
  are not read.
- The identity the command runs as is not judged, so a command under a bot or App identity is
  reported as well.
- The `gh api` forms (a review request with event APPROVE, a branch protection change) are not read.
- One finding is reported for each scan, at the first file in path order.

### CI-007 - Workflow that runs a coding agent, or an agent-config file, has no CODEOWNERS owner (Severity: high, Confidence: 0.4, Fix type: config)

**What we detect:** gated by `repo_codeowners_gap`, a repo with a workflow that has a coding-agent
step (the agents CI-001 reads) and either no CODEOWNERS file, or a CODEOWNERS file that names no
owner for that workflow file or for a present agent-config file (CLAUDE.md, AGENTS.md, GEMINI.md,
`.mcp.json`, `.claude/settings.json`). CODEOWNERS is read from `.github/`, the root and `docs/`,
the first found. The last matching pattern wins and a pattern with no owner clears ownership.

**Why it is flaggable.** GitHub documents that people with admin or owner permissions "can require
that pull requests have to be approved by code owners before they can be merged"; a path with no
owner cannot be covered by that requirement. *Co-Modifying Application Code and Deployment
Infrastructure* (arXiv 2610.12849, submitted 9 October 2026) reports that agent identity reduced
the odds of human review of pull requests that change application code and deployment
infrastructure, and calls for "strict path-based access controls". The paper does not study
CODEOWNERS and is cited for that statement and nothing more.

**Real-world consequence:** a change to the workflow that runs the agent, or to its configuration,
can merge without a named owner reviewing it.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Fix type - config:** add owner entries and require code owner review for the default branch.

**Confidence 0.4:** the pack's explanation states these limits:

- Branch protection and rulesets are not visible. A repo that does not require code owner review
  gains nothing from an owner entry; a repo that requires it by another route is reported when
  CODEOWNERS is silent.
- A workflow reached through a reusable workflow call is not listed as an agent workflow.
- This rule changes the claim of the planning sheet rows CI-009 and CI-010, which asked for pull
  request metadata and branch protection data. The owners approve this wording.

---

## What this policy does not cover

- Which account or token a command runs as, and whether a bot or App identity is used.
- Pull request metadata: author, reviewers, approvals, merged paths.
- Branch protection, rulesets, environment reviewers.

---

## Recommendations beyond the fix

1. Keep review approval with people; give an automated reviewer an identity that cannot satisfy
   the required human review.
2. Require code owner review in a ruleset and keep the CODEOWNERS file under review itself.
3. Cover the workflow directory and the agent-config files with the same owners.

---

## Sources

- Who Approved This? Coding Agents, Human Accounts, and Merge-Gate Evidence at a Fintech
  Startup, arXiv 2610.28683, abstract retrieved 2026-11-27. Cited for the lesson on agents'
  credentials and nothing more.
- Co-Modifying Application Code and Deployment Infrastructure: A Causal Study of AI Agent Pull
  Requests, arXiv 2610.12849, abstract retrieved 2026-11-27. Cited for the review-odds finding and
  the call for path-based access controls, and nothing more.
- GitHub CLI manual, `gh pr review` and `gh pr merge` (cli.github.com), retrieved 2026-11-27. Cited
  for the descriptions of `--approve` and `--admin`.
- GitHub Docs, About code owners (docs.github.com), retrieved 2026-11-27. Cited for the file
  locations, the last-match rule and the required-review sentence.
