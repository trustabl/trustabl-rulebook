---
policy_id: agent_config_fetch_permissions
category: agent_config
topic: fetch_permissions
rules:
  - id: AGCFG-011
    severity: high
    confidence: 0.7
    scope: repo
    fix_type: config
references: []
---

# Policy Rationale: Pre-approved Web Fetch

**Policy ID:** `agent_config_fetch_permissions`  
**File:** `agent_config/fetch_permissions.yaml`  
**Rules:** AGCFG-011  
**Severities:** high  
**Fix types:** config  
**References:** none

> **Verification status.** The Claude Code behavior below was read on 2026-10-21
> from Anthropic's Claude Code documentation: the permissions page
> (`code.claude.com/docs/en/permissions`), the tools reference
> (`code.claude.com/docs/en/tools-reference`) and the settings page
> (`code.claude.com/docs/en/settings`). The host descriptions were read on the same
> day from each host's own documentation, named in the host table below. **Not
> verified, and therefore not assumed:** which domains are in Claude Code's built-in
> set of preapproved documentation domains, and how Claude Code treats `WebFetch()`
> with empty parentheses or a WebFetch specifier that does not start with `domain:`.

---

## What this policy covers

Claude Code reads permission rules from a project's `.claude/settings.json` and
`.claude/settings.local.json`. WebFetch rules name the hosts they apply to with a
`domain:` specifier, such as `WebFetch(domain:example.com)`. In Manual and
`acceptEdits` permission modes, WebFetch prompts before it fetches a page, except
for domains that permission rules already allow or deny and a built-in set of
preapproved documentation domains.

This policy has one rule. **AGCFG-011** flags a committed settings file whose
`permissions.allow` list holds a WebFetch rule that covers one of eight hosts where,
in the pack's words, "any account holder can publish content". It is repo scope and
fires once per scan, attributed to the first offending allow entry. The pack loads
for each scan, because the files it reads have no SDK import; the rule's own
predicate does the gating.

---

## Why this is not a pre-trust rule

The pack's policy description says this is not a pre-trust rule like AGCFG-004 and
AGCFG-005. Claude Code's permissions documentation says, for "`permissions.allow`
rules and `additionalDirectories` in `.claude/settings.json`":

- In a folder where the user trusted a parent folder but not the folder itself:
  "Not used until you accept the trust dialog, which appears again listing them".
- In a `claude -p` or SDK run in a folder that has not been trusted: "Not used."
- "The dialog lists the rules and directories the folder would grant so you can
  review them first."

The same page says of `.claude/settings.local.json`: "When the file is tracked in
git, or `.claude` is a symlink, Claude Code treats it as repository-supplied instead
and holds its rules until you trust the folder."

So the allow rules this policy judges do not act in a folder the user has not
trusted. A developer who accepts the trust dialog has been shown them. What AGCFG-011 judges is
what those rules grant once the folder is trusted: a fetch from a listed host with
no prompt.

---

## Rule-by-rule defense

### AGCFG-011 — Project settings pre-approve fetches from hosts that serve user-published content (Severity: high, Confidence: 0.7, Fix type: config)

**What we detect:** an entry in the `permissions.allow` list of a
`.claude/settings.json` or `.claude/settings.local.json` that covers one of these
hosts: `github.com`, `gist.github.com`, `raw.githubusercontent.com`, an arbitrary
`*.github.io` site, `huggingface.co`, `bitbucket.org`, `pastebin.com`, or an
arbitrary `*.readthedocs.io` site. Settings files are read from a `.claude/` folder
at any depth in the repo. Gated by `repo_settings_preapprove_user_content_fetch`.

How an entry is matched against a host:

- A bare `WebFetch` rule covers each listed host, and so does
  `WebFetch(domain:*)`.
- A `domain:` pattern is compared without regard to case, with a trailing `.`
  removed from the pattern and from the host.
- A pattern that starts with `*.` covers subdomains of the rest of the pattern at any
  depth, and not the rest itself: `WebFetch(domain:*.github.com)` covers
  `gist.github.com` and does not cover `github.com`.
- Any other `*` matches within one label: `WebFetch(domain:raw.*.com)` covers
  `raw.githubusercontent.com`.
- For the two `*.` entries, the check uses a stand-in subdomain that no one account
  owns (`any-account.github.io`, `any-project.readthedocs.io`), so a rule has to
  cover an arbitrary site on that suffix: `WebFetch(domain:*.github.io)` is flagged
  and `WebFetch(domain:alice.github.io)` is not.
- `WebFetch()` and specifiers without `domain:` are not judged.

How a finding is cancelled: the deny and ask lists of the settings files in the same
`.claude/` folder are pooled, and an allow entry is not reported for a host that any
of those deny or ask rules covers, with the same matching. A
`"deny": ["WebFetch(domain:raw.githubusercontent.com)"]` in `settings.local.json`
cancels an allow rule for that host in the `settings.json` beside it. A deny or ask
rule in a different `.claude/` folder of the repo does not. Each allow entry yields
one internal hit, for the first listed host it covers, that records the file, the
line and a reason naming the entry and the host; the finding text is the rule's
fixed explanation.

**The hosts.** The pack's explanation lists hosts "where any account holder can
publish content". Each host's own documentation, read on 2026-10-21:

| Host | Source | What it says |
|---|---|---|
| `github.com` | GitHub Docs, "About repositories" | "When you create a repository, you can choose to make the repository public or private." |
| `gist.github.com` | GitHub Docs, "Creating gists" | "Public gists show up in Discover, where people can browse new gists as they're created." |
| `raw.githubusercontent.com` | GitHub Docs, "Repository limits" | Files in a repository are available in their raw formats, "which are served through `raw.githubusercontent.com`". |
| `*.github.io` | GitHub Docs, "What is GitHub Pages?" | "GitHub Pages is a static site hosting service that takes HTML, CSS, and JavaScript files straight from a repository on GitHub, optionally runs the files through a build process, and publishes a website." The default location of a user or organization site is `http(s)://<owner>.github.io`. |
| `huggingface.co` | Hugging Face Hub documentation | "The Hugging Face Hub hosts Git-based repositories, which are version-controlled folders that can contain all your files." and "While many datasets are public, organizations and individuals can create private datasets to comply with licensing or privacy issues." |
| `bitbucket.org` | Atlassian Support, Bitbucket Cloud, "Set repository privacy and forking options" | "If your repository is public, anyone can access and fork it." |
| `pastebin.com` | Pastebin FAQ | "Pastebin is a website where you can store any text online for easy sharing." A new paste is public "(public by default)". |
| `*.readthedocs.io` | Read the Docs, "Custom domains" and Terms of Service | A project's documentation is served from "<project name>.readthedocs.io for Read the Docs Community." The Terms of Service say "On Read the Docs Community, all Content is public." |

**Why it is flaggable:** Claude Code's permissions page says that a `WebFetch`
rule in `allow` means "Claude fetches without prompting you", and that
`WebFetch(domain:*)` in `allow` means "Claude fetches without prompting you, and
sandboxed commands can reach any host." The tools reference says WebFetch prompts
"except for domains your permission rules already allow or deny". It also says how
the page reaches the agent: "For most fetches, it then runs the prompt against the
content in a separate model call, and Claude receives the result of that call
rather than the raw page." The settings page describes `.claude/settings.json` as
"settings your team checks into source control", and says that when `permissions.allow`
is set in more than one file, "Claude Code combines the lists instead of picking
one". A committed allow rule therefore applies to each developer who trusts the
folder, next to their own rules. The pack's explanation says that if a page on a
listed host contains text a stranger published, "that text can shape what the agent
reads, with no prompt that lets the developer stop the fetch."

**Real-world consequence:** if a committed `.claude/settings.json` allows
`WebFetch(domain:raw.githubusercontent.com)`, the agent can fetch a file from any
repository on that host without a prompt, because WebFetch rules match against the
hostname of the requested URL. If that file holds text that its author wrote to
steer an agent, the extraction result Claude receives can carry that text, and no
prompt gives the developer a chance to stop the fetch first.

**Why severity is high:** The pack sets high and states no reasoning for it. The
costs the explanation names are that text a stranger published on a listed host can
shape what the agent reads, and that no prompt lets the developer stop the fetch.

**Fix type — config:** the fix is an edit to the committed settings file. The pack's
fix is to remove the WebFetch allow rule for these hosts so each fetch prompts, or
narrow it to a host the project controls, such as its own docs site; to put a rule
for a host you trust for your own work in `~/.claude/settings.json`; or to add a
`WebFetch(domain:...)` rule to `permissions.ask` or `permissions.deny` in the
committed settings. No tool source code changes.

**Confidence 0.7:** the pack's explanation states these limits of the check:

- It reads the permissions block of the `.claude/` settings files in the repo and
  follows the documented `domain:` matching (an exact host, a leading `*.` for
  subdomains, `*` within one label).
- A deny or ask rule in a settings file in the same `.claude/` folder that covers
  the host cancels the finding; deny and ask rules in user or managed settings are
  not seen.
- A rule for one account's site, such as `WebFetch(domain:alice.github.io)`, is not
  flagged.
- `WebFetch()` and other specifiers without `domain:`, WebSearch rules, Bash rules
  for `curl` or `wget` and MCP fetch tools are not judged.
- The host list is fixed; other sites that host user content are not judged.

The pack states no other limits for this rule.

---

## What this policy does not cover

- Deny and ask rules in user or managed settings. They are not seen, so a finding
  can stand for a host that a developer's own settings or an organization's policy
  already refuses.
- Whether the folder has been trusted, and whether a run is interactive or a
  `claude -p` or SDK run. The check reads the repo's settings files and nothing
  else.
- A deny or ask rule in a different `.claude/` folder of the repo from the allow
  rule.
- A rule for one account's site, such as `WebFetch(domain:alice.github.io)`.
- `WebFetch()` and other specifiers without `domain:`, WebSearch rules, Bash rules
  for `curl` or `wget`, and MCP fetch tools.
- Sites outside the fixed host list that host user content.
- A settings file that is not valid JSON. It is skipped.
- What a fetched page contains. The check judges the host a rule covers, not the
  content served from it.

---

## Recommendations beyond the fix

A committed allow rule for a host the project controls:

```json
{
  "permissions": {
    "allow": [
      "WebFetch(domain:docs.example.com)"
    ]
  }
}
```

Committed rules that make listed hosts prompt or be refused for the whole team:

```json
{
  "permissions": {
    "ask": [
      "WebFetch(domain:github.com)",
      "WebFetch(domain:raw.githubusercontent.com)"
    ],
    "deny": [
      "WebFetch(domain:pastebin.com)"
    ]
  }
}
```

1. Keep committed WebFetch allow rules to hosts the project controls, such as its
   own docs site. A `WebFetch(domain:example.com)` rule covers that host and not its
   subdomains, and a `WebFetch(domain:*.example.com)` rule covers subdomains at any
   depth and not `example.com` itself.
2. Put a rule for a host you trust for your own work in `~/.claude/settings.json`,
   your user settings file, which is not part of the repository.
3. Use `permissions.ask` or `permissions.deny` in the committed settings for a host
   the team should be asked about or refused. Claude Code's permissions page says
   "Rules are evaluated in order: deny, then ask, then allow." and "a user-level
   deny blocks a project-level allow, because deny rules from any scope are
   evaluated before allow rules." The settings page says that committed allow rules
   wait until each teammate trusts the folder, and that "`deny` and `ask` rules
   apply right away."
4. Check `.claude/settings.local.json` before you commit it. Choosing "Yes, and
   don't ask again" for a domain on a WebFetch prompt saves a `WebFetch(domain:...)`
   allow rule to that file. The settings page says Claude Code keeps the file out of
   git when it creates it, and "if you create it by hand, add it to `.gitignore`
   yourself".
5. Review changes to `.claude/settings.json` in pull requests, and read the allow
   rules the trust dialog lists before you accept it.
