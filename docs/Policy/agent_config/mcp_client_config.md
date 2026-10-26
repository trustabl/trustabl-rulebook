---
policy_id: agent_config_mcp_client_config
category: agent_config
topic: mcp_client_config
rules:
  - id: MCPCFG-002
    severity: high
    confidence: 0.7
    scope: repo
    fix_type: config
  - id: MCPCFG-003
    severity: high
    confidence: 0.7
    scope: repo
    fix_type: config
references: [LLM06, LLM03]
---

# Policy Rationale: Project MCP Client Configuration

**Policy ID:** `agent_config_mcp_client_config`  
**File:** `agent_config/mcp_client_config.yaml`  
**Rules:** MCPCFG-002, MCPCFG-003  
**Severities:** high, high  
**Fix types:** config, config  
**References:** LLM06 (Excessive Agency), LLM03 (Supply Chain)

> **Verification status.** The Gemini CLI settings shape and the Codex
> project-config trust behavior are **not verified against vendor docs**. Gemini
> `mcpServers` is read with the same JSON shape as Claude Code and Cursor, and Codex
> `[mcp_servers.*]` as TOML tables with `command` and `args`.

---

## What this policy covers

MCP client configuration committed to a repository: `.mcp.json`,
`.cursor/mcp.json`, `.vscode/mcp.json` (`servers`), `claude_desktop_config.json`,
`.gemini/settings.json` and `.codex/config.toml`. This is the **consuming** side of
MCP, written from the point of view of someone opening the repo. It is distinct from
the `mcp` category, which audits servers a repo *implements*. MCPCFG-002 asks one
question: does a server entry start local, repo-controlled code? MCPCFG-003 asks
another: does a server entry start a package runner on a package or image that is
not pinned to an exact version? The pack loads for each scan, and each rule has its
own gating predicate.

---

## Evidence

CVE-2025-59536 (Claude Code ran `.mcp.json` servers before the trust dialog) shows
that a committed server list can execute on open. CVE-2025-54136 (MCPoison) and
CVE-2025-54135 (CurXecute) are Cursor issues in the same area of committed or
modified MCP config; no detail beyond the names is reproduced here. OWASP ASI04 and
ASI05, MITRE ATLAS AML.T0053. Source: Trustabl Agentic Security Baseline
2026-10-06, issue AGS-06.

---

## Rule-by-rule defense

### MCPCFG-002 — Project MCP config launches a local command (Severity: high, Confidence: 0.7, Fix type: config)

**What we detect:** a server entry with a `command` that is
(a) an interpreter (`bash`, `sh`, `zsh`, `cmd`, `powershell`, `pwsh`, `python`,
`python3`, `node`) given inline code (`-c`, `-e`, `/c`, `-Command`) or a
repo-relative script as its first non-flag argument, or (b) a command path inside
the repo (`./bin/server`, `scripts/run.sh`). Entries with a `url` or `httpUrl` are
skipped. `npx` / `uvx` style launches of a package, `python -m pkg`, and absolute
paths are silent for this rule; MCPCFG-003 checks whether a package launch is
pinned. Gated by `repo_mcp_config_launches_local_command`.

**Why it is flaggable:** the client runs `command` with the developer's privileges
when the server is enabled. A script in the repo is whatever the repo says it is,
and changes with each commit.

**Real-world consequence:** a committed `.mcp.json` points `bash -c` at a bundled
script; enabling the server, or a settings key that auto-enables it (AGCFG-004),
runs it.

**Why severity is high and not critical:** most clients prompt before starting a
project server, so execution usually needs one user approval. The critical case is
the combination with AGCFG-004, which is rated separately. **Fix type — config:**
use a pinned published package or an authenticated remote URL.

**Confidence 0.7:** a repo may legitimately ship its own MCP server and document
how to run it, which is flagged identically. A server started from a published
package is not flagged by this rule, pinned or not; MCPCFG-003 checks whether such
a package is pinned.

### MCPCFG-003 — Project MCP config launches an unpinned package (Severity: high, Confidence: 0.7, Fix type: config)

**What we detect:** a server entry whose `command` is a package runner (`npx`,
`bunx`, `pnpm dlx`, `uvx`, `uv tool run`, `pipx run` or `docker run`) on a package
or image that is not pinned to an exact version. Gated by
`repo_mcp_config_launches_unpinned_package`. The command is matched on its base
name, lowercased, with a trailing `.exe` removed. For each runner except
`docker run`, the check skips the runner's own flags up to the first positional
argument, along with the value of each flag it lists as taking one, and then
judges the package spec:

| Runner | Spec judged | Counts as pinned |
|---|---|---|
| `npx`, `bunx`, `pnpm dlx` | each `-p` / `--package` value; with none, the first positional argument | `name@X.Y.Z`, an exact semver with an optional pre-release or build suffix |
| `uvx`, `uv tool run` | each `--from` value; with none, the first positional argument | `name==X` or `name===X`, or `name@X` for any `X` other than `latest` |
| `pipx run` | the `--spec` value; with none, the first positional argument | `name==X` or `name===X` |
| `docker run` | all arguments after `run` | an argument that contains `@sha256:` followed by 64 hex digits |

A tag (`@latest`, `@next`), a range (`@^1.2.0`, `>=1.2`) or a bare name is unpinned.
uv's [tools guide](https://docs.astral.sh/uv/guides/tools/) says the `@` syntax
"cannot be used for anything other than an exact version", which is why `name@X`
counts as pinned for `uvx` and `uv tool run`. These entries are not judged, and so
are not flagged: a `url` or `httpUrl` server; a command path inside the repo, and
any entry MCPCFG-002 flags; an npm-style spec that is a path, a git source, a
`user/repo` shorthand, a URL, an `npm:` alias, or contains `$`; a Python spec that
is a path, a URL, a git source, a direct reference (`name @ url`), an archive file,
or contains `$`; an `npx`, `bunx` or `pnpm dlx` command given as a shell string
(`-c` or `--call` for `npx` and `bunx`; `-c` or `--shell-mode` for `pnpm dlx`) with
no package flag; and a `docker run` with an argument that contains `$`. The finding
names the server, not the spec.

**Why it is flaggable:** the pack's explanation says the code the client starts can
change with no change to the repo. The runners' own documentation describes how
an unpinned spec resolves:

- The [`npm exec`](https://docs.npmjs.com/cli/v11/commands/npm-exec) page, which
  also covers `npx`, says that packages not present in the local project "are
  installed to a folder in the npm cache, which is added to the PATH environment
  variable". The [`npm install`](https://docs.npmjs.com/cli/v11/commands/npm-install)
  page says `<name>@<tag>` installs "the version of the package that is referenced
  by the specified tag" and `<name>@<version range>` installs "a version of the
  package matching the specified version range".
- The [`bunx`](https://bun.com/docs/pm/bunx) page says "`bunx my-cli` asks the
  registry for newer versions of the package and of its dependencies once a day."
- uv's [tools concept page](https://docs.astral.sh/uv/concepts/tools/) says "uvx
  will use the latest available version of the requested tool on the first
  invocation."
- pipx's [run tutorial](https://pipx.pypa.io/latest/_sources/tutorial/run-applications.rst.txt)
  says "pipx caches each `pipx run` environment for 14 days so repeated runs start
  instantly" and "After the cache expires, the next run fetches the latest
  version."
- Docker's [`docker image pull`](https://docs.docker.com/reference/cli/docker/image/pull/)
  page says "If no tag is provided, Docker Engine uses the `:latest` tag as a
  default", and that pulling by digest "pins" an image "to a specific version in
  time."

**Real-world consequence:** if a committed `.mcp.json` starts a server with
`uvx example-mcp-server`, and a later release of that package carries harmful
code, a developer whose first run comes after that release can start that code
when the server is enabled. It can run with the developer's privileges, and the
repo shows no change.

**Why severity is high:** the pack sets high and states no reasoning for it. The
costs the explanation names are that the code the client starts can change with
no change to the repo, and that it runs with the developer's privileges when the
server is enabled.

**Fix type — config:** the pack's fix is to pin each server to an exact version:
`package@1.2.3` for npx, bunx and pnpm dlx; `package@1.2.3` or
`--from package==1.2.3` for uvx; `--spec package==1.2.3` for pipx run;
`image@sha256:<digest>` for docker run. It says to move the pin deliberately when
you decide to take a new release.

**Confidence 0.7:** the pack sets 0.7 for this rule and states these limits in its
explanation: "it reads the command and args of each server entry and nothing else.
A version pinned in a lockfile or package manifest is not seen, and npx and bunx
prefer a copy installed in the local project, so a repo that installs the package
is still flagged. Git, URL, local-path and environment-variable specs are not
judged, nor is a runner started through a shell (bash -c, cmd /c) or given a flag
before its subcommand. A docker image counts as pinned by an @sha256: digest, not
by its tag. Remote URL servers are out of scope, and a command inside the repo is
MCPCFG-002's." The pack states no other limits for this rule.

---

## What this policy does not cover

- Typosquatted package names. MCPCFG-003 judges the version part of a spec, not
  the package or image name.
- What a pinned version contains. MCPCFG-003 is silent once the spec names an
  exact version or a digest.
- A version pinned in a lockfile or package manifest. MCPCFG-003 reads the
  `command` and `args` of each server entry and nothing else.
- Git, URL, local-path and environment-variable specs, and a package runner
  started through a shell (`bash -c`, `cmd /c`) or given a flag before its
  subcommand.
- Remote servers without authentication, and remote servers that are malicious.
- MCP config outside the listed files, and user-level or enterprise config.
- What the launched script does; only that a repo-controlled launch exists.
- Gemini CLI and Codex trust behavior (unverified).

---

## Recommendations beyond the fix

```json
{
  "mcpServers": {
    "docs": { "command": "npx", "args": ["-y", "@example/mcp-server@1.2.3"] }
  }
}
```

The pinned forms from MCPCFG-003's fix for `uvx`, `pipx run` and `docker run`.
Replace the digest with the one for the image you have reviewed:

```json
{
  "mcpServers": {
    "search": { "command": "uvx", "args": ["--from", "example-mcp-server==1.2.3", "example-mcp-server"] },
    "lint": { "command": "pipx", "args": ["run", "--spec", "example-mcp-server==1.2.3", "example-mcp-server"] },
    "fetch": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "example/mcp-server@sha256:0000000000000000000000000000000000000000000000000000000000000000"]
    }
  }
}
```

1. Pin the exact package version, and prefer a registry you control.
2. If a local server is needed, document installation and register it in each
   developer's user-level config.
3. Never pair a project server list with `enableAllProjectMcpServers` (AGCFG-004).
4. Move a pin deliberately when you decide to take a new release, as MCPCFG-003's
   fix says.
