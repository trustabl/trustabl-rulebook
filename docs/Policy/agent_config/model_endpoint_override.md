---
policy_id: agent_config_model_endpoint_override
category: agent_config
topic: model_endpoint_override
rules:
  - id: AGCFG-014
    severity: medium
    confidence: 0.5
    scope: repo
    fix_type: config
references: []
---

# Policy Rationale: Model Endpoint Override in Project Settings

**Policy ID:** `agent_config_model_endpoint_override`  
**File:** `agent_config/model_endpoint_override.yaml`  
**Rules:** AGCFG-014  
**Severities:** medium  
**Fix types:** config  
**References:** none

> **Verification status.** The Claude Code behavior below was read on 2026-10-29 from
> Anthropic's pages at `code.claude.com/docs/en/`: `settings`, `settings-reference`
> (the `env` entry), `env-vars`, `permissions` (the section "What runs before you trust
> a folder"), `llm-gateway` and `llm-gateway-connect`. The Check Point Research post
> was read in full on 2026-10-29 from its web page. The CVE record for CVE-2026-21852
> was read on 2026-10-29 from the CVE Services API (`cveawg.mitre.org`), and the
> advisory GHSA-jh7p-qr78-84p7 from the GitHub advisories API. The paper cited below
> was read on 2026-10-29 as its arXiv abstract page (version 3). **Not verified, and
> therefore not assumed:** which environment variables Claude Code applies before the
> workspace is trusted, beyond the lists the settings reference gives; whether
> `ANTHROPIC_BASE_URL` is among the variables that page calls "safe"; the behavior of
> Claude Code versions other than the fixed version the advisory names; whether an
> Anthropic SDK reads `ANTHROPIC_BASE_URL`; and any gateway product's behavior.

---

## What this policy covers

Claude Code reads settings from `.claude/settings.json` and `.claude/settings.local.json`.
The `env` block of those files sets environment variables for the session. The
`ANTHROPIC_BASE_URL` variable sets the endpoint Claude Code sends API requests to. The
pack loads for each scan, because the files it reads have no SDK import; the rule's own
predicate does the gating.

This policy has one rule. **AGCFG-014** flags a committed settings file whose `env`
block sets `ANTHROPIC_BASE_URL` to a host other than `api.anthropic.com` and other than
a loopback address. It is repo scope and fires once per scan, attributed to the first
path-sorted offending file and line. It reads no file that AGCFG-006 reads, so one file
and key cannot fire both rules.

---

## Rule-by-rule defense

### AGCFG-014 — Project settings point Claude Code at a non-Anthropic API host (Severity: medium, Confidence: 0.5, Fix type: config)

**What we detect:** in each `.claude/settings.json` or `.claude/settings.local.json`, at
any depth in the repo, an `env` entry named `ANTHROPIC_BASE_URL` whose value is a URL with
the `http` or `https` scheme and a host that is not `api.anthropic.com`, not `localhost`
(or a name ending `.localhost`), and not a loopback address. Gated by
`repo_settings_env_redirects_model_endpoint`.

What is not flagged:

- A value whose host is `api.anthropic.com` (compared without case and without a trailing dot).
- A loopback host: `localhost`, `127.0.0.1` and the rest of `127.0.0.0/8`, `::1`.
- A value that is empty, contains a `$` (a variable reference), does not parse as a URL,
  or uses a scheme other than `http` and `https`.
- A value that is not a string, an `env` that is not an object, and a file that is not
  valid JSON.
- Any other variable, including `ANTHROPIC_BEDROCK_BASE_URL`, `ANTHROPIC_VERTEX_BASE_URL`,
  `OPENAI_BASE_URL` and `GOOGLE_GEMINI_BASE_URL`.
- Any other file: `.env` files, `.gemini/.env`, `.codex/config.toml`, workflow `env`
  blocks, user-level settings and managed settings.

How the host is read: the value is parsed inside one function (`modelEndpointClass`) and
reduced at once to one of `first_party`, `loopback`, `other` or `unjudged`. The class
alone leaves the function. The URL, its host, its userinfo and its query are not stored in a
struct, a reason, a log or a finding. The internal hit records the file, the line and a
fixed reason naming the key, and the finding text is the rule's fixed explanation. A URL
that carries a user name, a password or a query key is judged by its host and is not echoed.

**Why it is flaggable.** All behavior in this list is from Anthropic's pages, read on
2026-10-29.

- What the variable does. The environment variables reference describes
  `ANTHROPIC_BASE_URL` as "Override the API endpoint to route requests through a proxy or
  gateway."
- That the settings file can carry it. The settings reference's `env` entry says "Most
  variables in the environment variables reference can go here" and "Project and local
  settings can't set some of them." Its example of an `env` block sets `ANTHROPIC_BASE_URL` to
  `https://proxy.example.com`. The list of variables that project and local settings cannot
  set, on the same page, names variables for file locations, session content export,
  OpenTelemetry exporters, startup and sync, and others; it does not name
  `ANTHROPIC_BASE_URL`.
- When a project value applies. The settings reference lists "When Claude Code applies
  `env` values". For project and local settings the entry reads: "after you trust the
  workspace, or at startup in `-p` mode", and the page states that `-p` mode shows no trust
  dialog. The permissions page's table "What runs before you trust a folder" lists "the
  `env` block" among the content a repository can supply, and gives "Used" in both of its
  columns: when a parent folder was trusted, and for `claude -p` or the SDK in a folder
  where the trust dialog was not accepted. Neither page says which of these rules applies to
  `ANTHROPIC_BASE_URL` in particular; the settings reference also lists variables Claude
  Code classifies as safe, which apply at startup from the settings files, and does not say
  whether this variable is one.
- How Anthropic describes the intended use. The connect page says "Administrators can
  distribute the gateway address and credential through managed settings, device
  management, or an `apiKeyHelper`", and the gateway page's rollout steps say to
  "Distribute the configuration through a managed settings file". The connect page's
  settings-file scopes are `~/.claude/settings.json` and `.claude/settings.local.json`,
  and it warns: "Don't put the credential in a project's `.claude/settings.json`." The
  gateway page also says "Anthropic doesn't endorse, maintain, or audit third-party
  gateway products".

A committed `.claude/settings.json` that names an off-vendor host therefore chooses, for
the people who clone the repository, where Claude Code sends its requests once the
project's `env` values apply, and the host named there receives them.

**The pre-trust leak is fixed.** Check Point Research reported an earlier form of
this problem. Aviv Donenfeld and Oded Vanunu, "Caught in the Hook: RCE and API
Token Exfiltration Through Claude Code Project Files" (Check Point Research, 25 February
2026), describe `ANTHROPIC_BASE_URL` as the variable that "controls the endpoint for all
Claude Code API communications" and report that a project could set it in the `env` block
of `.claude/settings.json` so that, in the version they tested, Claude Code sent requests
carrying the API key to that host before the user answered the trust dialog. The post says
Anthropic fixed it "by ensuring that no API requests are initiated before users confirm the
trust dialog", and its timeline lists the fix on 28 December 2025 and the publication of
CVE-2026-21852 on 21 January 2026.

The CVE record for CVE-2026-21852 is titled "Claude Code Leaks Data via Malicious
Environment Configuration Before Trust Confirmation". It lists `@anthropic-ai/claude-code`
versions before 2.0.65 as affected, 2.0.65 as the version with the patch, weakness
CWE-522, and a CVSS v4.0 base score of 5.3 (Medium). The advisory
GHSA-jh7p-qr78-84p7 gives the same version range and first patched version, and a severity
of medium. Neither the record nor the advisory lists a credited reporter. The advisory
adds that users on standard auto-update "have received this fix already".

AGCFG-014 does not detect the pre-trust leak and does not claim to. It judges what the
file does after the fix: the host named in the file receives the requests. The advisory
and the post are cited for the history of the variable in project settings and nothing
more; neither describes a rule, and neither says anything about the host-based check this
rule makes.

**Real-world consequence:** a repository whose committed settings name an off-vendor host
sends the requests of each developer who applies those settings to that host, and the
host returns the responses Claude Code acts on. The pack's explanation states this and
does not state a figure for how many repositories do it.

**The problem class in the literature.** Fu, Li, Jiang and Dong, *Where Is the Tradeoff in
Using Third-Party API Routers for Agentic Software Development?* (arXiv 2607.23624,
submitted 26 July 2026, version 3 of 5 September 2026), study third-party API routers. Its
abstract says such a router "sits between the agent and the upstream provider", that "no
mechanism verifies alignment between the provider's output and the repository-level
actions ultimately executed by the agent", and that client-side mitigations "do not fully
restore end-to-end control". The paper is cited for the problem class of a router between a
coding agent and its provider and nothing more. It does not describe a repository's
configuration files or any environment variable that points an agent at a router, and
this policy does not attribute its host check, or any figure the paper reports, to it.

**Why severity is medium:** The pack sets medium and states no reasoning for it. The cost
the explanation names is that the host in the file receives the requests Claude Code sends
and returns the responses it acts on.

**Fix type — config:** the fix is an edit to the committed settings file. The pack's fix
removes `ANTHROPIC_BASE_URL` from the committed file; sets it in user-level settings or the
shell for a gateway the developer runs; or has an administrator distribute it through
managed settings, which is the route the gateway page describes. No tool source code changes.

**Confidence 0.5:** the pack's explanation states these limits of the check:

- A gateway an organization runs itself is a legitimate use, and the rule cannot tell it
  from a host the repository author does not control. The rule has no list of approved
  gateways, and the engine has no mechanism for one.
- The rule inspects the key name and the host of the URL.
- It does not judge a value that is empty, holds a variable reference or does not parse.
- It does not judge user-level or managed settings, a shell export, an `.env` file, a
  workflow `env` block, `.codex` or `.gemini` configuration, `ANTHROPIC_BEDROCK_BASE_URL`,
  `ANTHROPIC_VERTEX_BASE_URL`, `OPENAI_BASE_URL`, `GOOGLE_GEMINI_BASE_URL`, or code that
  passes a base URL to an SDK client.
- The finding names the file and the key, not the URL.

The pack states no other limits for this rule, and states no measurement of its
precision or recall.

---

## What this policy does not cover

- A cloud-provider endpoint variable such as `ANTHROPIC_BEDROCK_BASE_URL`.
- `OPENAI_BASE_URL`, `GOOGLE_GEMINI_BASE_URL` and other tools' endpoints. AGCFG-006 reads
  `*_BASE_URL` key names in `.gemini/.env` and `.codex/config.toml`.
- `.env` files, workflow `env` blocks and code-level `base_url` arguments.
- User-level and managed settings, and shell exports.
- Whether the folder has been trusted. The check reads the repo's settings files.
- Whether a host is an approved gateway.
- A settings file that is not valid JSON. It is skipped.

---

## Recommendations beyond the fix

A gateway address distributed by an administrator in a managed settings file, outside the
repository:

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "https://llm-gateway.example.com"
  }
}
```

1. Keep the gateway address out of `.claude/settings.json` in the repository.
2. Set it in `~/.claude/settings.json`, your shell, or the managed settings your
   administrator deploys.
3. Check `.claude/settings.local.json` before you commit it.
4. Review changes to `.claude/settings.json` in pull requests.

---

## Sources

- Aviv Donenfeld and Oded Vanunu, "Caught in the Hook: RCE and API Token Exfiltration
  Through Claude Code Project Files", Check Point Research, 25 February 2026 (CVE-2025-59536,
  CVE-2026-21852). https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/
  Retrieved 2026-10-29. Cited for the history of `ANTHROPIC_BASE_URL` in project settings
  and Anthropic's fix, and nothing more.
- CVE-2026-21852, CVE Services record. https://cveawg.mitre.org/api/cve/CVE-2026-21852
  Retrieved 2026-10-29.
- GHSA-jh7p-qr78-84p7, GitHub Security Advisory.
  https://github.com/anthropics/claude-code/security/advisories/GHSA-jh7p-qr78-84p7
  Retrieved 2026-10-29 through the GitHub advisories API.
- Claude Code settings reference, `env`: https://code.claude.com/docs/en/settings-reference
  Retrieved 2026-10-29.
- Claude Code settings: https://code.claude.com/docs/en/settings Retrieved 2026-10-29.
- Claude Code environment variables: https://code.claude.com/docs/en/env-vars
  Retrieved 2026-10-29.
- Claude Code permissions, "What runs before you trust a folder":
  https://code.claude.com/docs/en/permissions Retrieved 2026-10-29.
- Claude Code LLM gateway: https://code.claude.com/docs/en/llm-gateway and
  https://code.claude.com/docs/en/llm-gateway-connect Retrieved 2026-10-29.
- Donghao Fu, Jingxin Li, Xue Jiang and Yihong Dong, *Where Is the Tradeoff in Using
  Third-Party API Routers for Agentic Software Development?*, arXiv 2607.23624v3.
  https://arxiv.org/abs/2607.23624 Retrieved 2026-10-29. Cited for the problem class and
  nothing more.

---
