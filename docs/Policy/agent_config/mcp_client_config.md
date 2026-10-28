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
  - id: MCPCFG-004
    severity: high
    confidence: 0.6
    scope: repo
    fix_type: config
  - id: MCPCFG-005
    severity: medium
    confidence: 0.6
    scope: repo
    fix_type: config
references: [LLM06, LLM03]
---

# Policy Rationale: Project MCP Client Configuration

**Policy ID:** `agent_config_mcp_client_config`  
**File:** `agent_config/mcp_client_config.yaml`  
**Rules:** MCPCFG-002, MCPCFG-003, MCPCFG-004, MCPCFG-005  
**Severities:** high, high, high, medium  
**Fix types:** config, config, config, config  
**References:** LLM06 (Excessive Agency), LLM03 (Supply Chain)

> **Verification status.** The Gemini CLI settings shape and the Codex
> project-config trust behavior are **not verified against vendor docs**. Gemini
> `mcpServers` is read with the same JSON shape as Claude Code and Cursor, and Codex
> `[mcp_servers.*]` as TOML tables with `command` and `args`.
>
> **Verification status for MCPCFG-004 and MCPCFG-005.** Read on 2026-10-28:
> the `github/github-mcp-server` README, `docs/server-configuration.md`,
> `docs/remote-server.md` and Go source at commit `f692b2d981855ae4ee25e8bfff50d4733ff85b82`
> (`cmd/github-mcp-server/main.go`, `pkg/inventory/builder.go`,
> `pkg/github/server.go`), plus `spf13/cast` v1.10.0 and `spf13/viper` v1.21.0
> (the versions that server's `go.mod` names); the npm package
> `@modelcontextprotocol/server-github` 2025.4.8 (README, `package.json` registry
> entry, `dist/index.js`, `dist/common/utils.js`); the `supabase-community/supabase-mcp`
> README at tag v0.5.5 and the npm package `@supabase/mcp-server-supabase` 0.14.0
> (`dist/cli.cjs`); the Supabase pages `docs/guides/api/api-keys` and
> `docs/guides/getting-started/mcp`; the MCP specification revision 2026-07-28
> (authorization, security considerations, Streamable HTTP transport); RFC 6750;
> the Claude Code, Cursor, Gemini CLI and Codex MCP pages; and the four papers and
> posts listed under Sources. **Not verified, and therefore not assumed:** how
> VS Code signs in to a remote server; whether
> `claude_desktop_config.json` accepts a remote `url` entry (not checked); Windsurf (not
> read by the engine); the behavior of
> github-mcp-server and the Supabase server in versions other than those named; that
> `SUPABASE_SERVICE_ROLE_KEY` is a variable name any vendor page documents (the pack
> matches the substring `SERVICE_ROLE`); what a fine-grained GitHub token can
> restrict; and whether any of these patterns occurs in real repositories (the
> corpus holds no real client configs).

---

## What this policy covers

MCP client configuration committed to a repository: `.mcp.json`,
`.cursor/mcp.json`, `.vscode/mcp.json` (`servers`), `claude_desktop_config.json`,
`.gemini/settings.json` and `.codex/config.toml`. This is the **consuming** side of
MCP, written from the point of view of someone opening the repo. It is distinct from
the `mcp` category, which audits servers a repo *implements*. MCPCFG-002 asks one
question: does a server entry start local, repo-controlled code? MCPCFG-003 asks
another: does a server entry start a package runner on a package or image that is
not pinned to an exact version? MCPCFG-004 asks whether a server that is given a
credential also sets the scope options its own documentation offers, and MCPCFG-005
asks whether a remote server URL uses plain `http` on a host that is not local. The
pack loads for each scan, and each rule has its own gating predicate.

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

### MCPCFG-004 — Project MCP config starts a server with an unscoped credential (Severity: high, Confidence: 0.6, Fix type: config)

**What we detect:** a server entry (in `mcpServers` or `servers`, or a Codex
`[mcp_servers.<name>]` table) that matches one of four cases. Gated by
`repo_mcp_config_unscoped_credential`. The command is matched on its base name,
lowercased, with a trailing `.exe` removed, and a command inside the repo is skipped
(MCPCFG-002's).

1. **GitHub MCP server.** The `github-mcp-server` binary, or `docker run` with the
   image `ghcr.io/github/github-mcp-server` (a tag or digest is ignored). It fires
   when the entry passes `GITHUB_PERSONAL_ACCESS_TOKEN`, as an `env` key or a docker
   `-e` / `--env` argument, and none of the following is present:
   - Read-only: `--read-only` (or `--read_only`) among the server's own arguments,
     or `GITHUB_READ_ONLY` with a value that Go's `strconv.ParseBool` reads as true
     (`1`, `t`, `T`, `TRUE`, `true`, `True`). A flag given on the command line wins
     over the variable, and `--read-only=false` is not read-only.
   - A toolset option: `--toolsets` or `GITHUB_TOOLSETS` naming at least one toolset
     other than the keywords `all` and `default`.
   - `--tools` or `GITHUB_TOOLS`, unless a toolset option names `all` or `default`.

   A value that contains `$` counts as a set option, because its value is not in the
   file. Docker's own `--read-only` flag, which comes before the image name, is not
   the server's and is not credited.
2. **The deprecated npm GitHub package.** `npx`, `bunx` or `pnpm dlx` on
   `@modelcontextprotocol/server-github` (any version) when the entry passes
   `GITHUB_PERSONAL_ACCESS_TOKEN`.
3. **Supabase MCP server.** `npx`, `bunx` or `pnpm dlx` on
   `@supabase/mcp-server-supabase` (any version), or the `mcp-server-supabase`
   binary, started with neither `--read-only` nor `--project-ref` (bare or
   `--project-ref=<ref>`). No token is required.
4. **A `SERVICE_ROLE` credential.** Any entry whose `env` map, or docker `-e`
   argument, names a key containing `SERVICE_ROLE` (case-insensitive).

Not flagged: a server with no `GITHUB_PERSONAL_ACCESS_TOKEN` (case 1), the variable
`GITHUB_TOKEN`, a remote `url` or `httpUrl` server (including the hosted GitHub and
Supabase endpoints), a Docker `--env-file`, a server started through a shell, and
env names such as `ADMIN`, `ROOT` or `_SUPERUSER`. The finding text is the rule's
fixed explanation; the internal hit names the server and a fixed phrase and no env
value.

**Why it is flaggable.** Each statement below was read on 2026-10-28 on the page or
in the source named.

*GitHub MCP server.* The server's `docs/server-configuration.md` lists the options
that scope it: "`--toolsets` flag or `GITHUB_TOOLSETS` env var", "`--tools` flag or
`GITHUB_TOOLS` env var" and "`--read-only` flag or `GITHUB_READ_ONLY` env var". It
says "read-only mode acts as a strict security filter that takes precedence over any
other configuration, by disabling write tools even when explicitly requested", and
that with no toolset option the server uses the default toolsets (`context`,
`issues`, `pull_requests`, `repos`, `users`). The README's token guidance says "Only
grant necessary permissions" and "Keep tokens out of version control". The Go source
shows how the options are read:

- `cmd/github-mcp-server/main.go` calls `viper.SetEnvPrefix("github")`, a key replacer
  that turns `-` into `_`, and `viper.AutomaticEnv()`, and reads the option with
  `viper.GetBool("read-only")`. That is how `GITHUB_READ_ONLY` reaches the server.
- In `spf13/cast` v1.10.0 (`basic.go`), `ToBoolE` handles a string with
  `strconv.ParseBool`, so `yes` and `on` are not true. This is why the predicate
  credits exactly the values `ParseBool` accepts, which is narrower than the falsy
  list that `docs/remote-server.md` documents for the remote `X-MCP-Readonly` header.
- The same file registers `--tools` as a separate option. In
  `pkg/github/server.go`, `ResolvedEnabledToolsets` returns an empty list when tools
  are given with no toolsets, with the comment "`--tools=X` alone registers only X",
  and in `pkg/inventory/builder.go` `WithTools` is documented as "additional tools
  that bypass toolset filtering" and "These tools are additive". The builder treats the
  keyword `all` as enabling all toolsets and `default` as the default set. So the
  predicate credits `--tools` unless a toolset option names `all` or `default`.

*The deprecated npm package.* The npm registry marks each version of
`@modelcontextprotocol/server-github` deprecated with "Package no longer supported",
and its README begins "Deprecation Notice: Development for this project has been moved
to GitHub in the http://github.com/github/github-mcp-server repo." The published
source of version 2025.4.8 reads one environment variable,
`GITHUB_PERSONAL_ACCESS_TOKEN` (`dist/common/utils.js`), reads no command-line
argument, and returns a fixed tool list that includes `create_or_update_file`,
`push_files`, `create_issue` and `merge_pull_request` (`dist/index.js`). No flag or
variable can scope it, which is why the pack's fix is to move to `github-mcp-server`.

*Supabase MCP server.* The README at tag v0.5.5 says: "`--read-only`: Used to restrict
the server to read-only queries and tools. Recommended by default." and
"`--project-ref`: Used to scope the server to a specific project. Recommended by
default. If you omit this, the server will have access to all projects in your
Supabase account." It says read-only "prevents write operations on any of your
databases by executing SQL as a read-only Postgres user". It also says "you can omit
`SUPABASE_ACCESS_TOKEN` in this config and instead set it globally on your machine.
This allows you to keep your token out of version control", which is why the rule does
not require a token for this case. The current README is written for the hosted
server and no longer lists the flags, so the flags were checked in the package:
`dist/cli.cjs` of `@supabase/mcp-server-supabase` 0.14.0 parses `--access-token`,
`--project-ref` and `--read-only` with Node's `util.parseArgs` (`--read-only` as a
boolean, which takes no `=value`), reads `SUPABASE_ACCESS_TOKEN` when the flag is
absent, and passes `projectId` and `readOnly` to the server, whose tool handlers
refuse some actions with "Cannot create a project in read-only mode."

*`SERVICE_ROLE`.* Supabase's API keys page says secret keys "authorize access to your
project's data through the built-in service_role Postgres role. By design, this role
has full access to your project's data. It also has the BYPASSRLS attribute, so it
skips every Row Level Security policy you attach." The page names the role, not an
environment variable; the pack matches the substring `SERVICE_ROLE` in a key name.

**Real-world consequence.** Invariant Labs (Marco Milanta and Luca Beurer-Kellner,
published 2025-05-26, "GitHub MCP Exploited: Accessing private repositories via MCP")
describe an indirect prompt injection through a public issue that makes an agent read
private repositories and leak them. They write that "this is not a flaw in the GitHub
MCP server code itself, but rather a fundamental architectural issue that must be
addressed at the agent system level", and write that "it's critical to limit
agent access to only the repositories it needs to interact with—following the principle
of least privilege", and that token-based permissions "often impose rigid constraints
that limit an agent's functionality". They recommend runtime guardrails. This policy cites
the post for the attack class and nothing more: it does not attribute the server flags or
this rule's predicate to it, and it does not claim that a read-only flag prevents that
attack.
Background sources:

- Simon Willison (6 July 2025, "Supabase MCP can leak your entire SQL database", a
  link post) relays General Analysis's report: "The cursor assistant operates the
  Supabase database with elevated access via the service_role, which bypasses all
  row-level security (RLS) protections", and writes "If you configure their MCP as
  read-only you remove one leg of the trifecta".
- General Analysis (Rez Havaei, Rex Liu and Maximilian Li, 8 July 2025, reviewed 21
  October 2026) say that "Project scoping, read-only SQL, and tool-call review limit
  this path. Read-only access still permits reads of data available to the database
  role", and that they have not rerun the demonstration against the current server.
- Tural Hagverdiyev (arXiv 2610.05840, 5 October 2026, "Compromise Is Not Consequence:
  Evaluating Task-Scoped Authorization in LLM Agents with Paired Replay") reports
  from a controlled local experiment that "broad-bearer harmful execution ranges from
  8.9% to 37.8% across models; all three scoped conditions record zero". The paper
  does not study MCP servers or GitHub, and it says its results do not show
  "prevention of prompt injection". It is cited for that broad-versus-scoped lab
  result and nothing more.

**Why severity is high:** The pack sets high and states no reasoning for it. The
cost the explanation names is that an agent that follows instructions from untrusted
content can reach whatever the credential reaches.

**Fix type — config:** the fix is an edit to the committed config. The pack's fix is
to move off the deprecated npm package to `github-mcp-server` and add `--read-only`
(or `GITHUB_READ_ONLY=1`) or the narrowest `--toolsets` the task needs; for Supabase,
to add `--read-only` and `--project-ref=<project-ref>` and use a development project;
to replace a `service_role` credential with one that does not skip Row Level Security;
and to keep the token out of the committed file by reading it from the developer's own
environment. The "development project" advice is the v0.5.5 README's "Don't connect
to production".

**Confidence 0.6:** the pack sets 0.6 for this rule and states these limits in its
explanation:

- It reads the command, args, env and docker `-e` arguments of each server entry.
  Env names are read; the value of `GITHUB_READ_ONLY` and `GITHUB_TOOLSETS` is
  inspected to tell a set option from an unset one, and no other value is read or
  kept.
- A `$VAR` value counts as a set option, because its value is not in the file.
- A token forwarded through Codex's `env_vars` list (names of variables passed from the
  developer's environment) is not read.
- The scope of the token itself is not visible, so a fine-grained token limited to
  read access is still flagged. A GitHub token supplied outside the file is not seen.
- Supabase is judged without a token, and a server started with `--project-ref` but
  not `--read-only` is not flagged.
- Remote URL servers, a Docker `--env-file`, a server started through a shell, and
  names such as `ADMIN` or `ROOT` are not judged.
- A literal token in the file is the subject of the `--secret-scan` rule
  SECRET-LIT-001, not of this rule. A command inside the repo is MCPCFG-002's, and an
  unpinned package is MCPCFG-003's, so one entry can carry findings from this rule
  and MCPCFG-003.

**What this does not cover (false positives and evasion).** A read-scoped token is
flagged because the file does not show the token's scope. A server entry that reaches
the same tools through a wrapper script, a shell command or a remote URL is not seen.
The hosted GitHub server (`api.githubcopilot.com/mcp/`) and the hosted Supabase server
(`mcp.supabase.com/mcp`) document their own scope settings (the `X-MCP-Readonly` and
`X-MCP-Toolsets` headers, a `/readonly` path, and the `read_only` and `project_ref`
query parameters); this rule does not read them.

### MCPCFG-005 — Project MCP config points a client at a remote server over plain http (Severity: medium, Confidence: 0.6, Fix type: config)

**What we detect:** a server entry whose `url` or `httpUrl` (Gemini CLI's streaming
key) parses as a URL with the scheme `http` (case-insensitive), and whose host is
neither `localhost` nor an address that Go's `net.IP.IsLoopback` accepts (127.0.0.0/8
and `::1`). Gated by `repo_mcp_config_remote_plain_http`. A private address
(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), `host.docker.internal` and a `.local`
name are not loopback and are flagged. A URL that contains `$` is not judged, nor is
`ws://` or `https://`. The host is parsed, so `http://localhost.evil.invalid` is
flagged and `http://user@localhost/mcp` is not. The internal hit names the server and
a fixed phrase and not the URL.

**Why it is flaggable.** Read on 2026-10-28.

- The MCP specification (revision 2026-07-28, authorization page) says the client
  sends the token in the Authorization header: "Note that authorization MUST be
  included in every HTTP request from client to server."
- RFC 6750, section 5.3, says "Clients MUST always use TLS [RFC5246]
  (https) or equivalent transport security when making requests with bearer tokens.
  Failing to do so exposes the token to numerous attacks that could give attackers
  unintended access."
- The specification's security considerations page says "All authorization server
  endpoints MUST be served over HTTPS" and "All redirect URIs MUST be either
  `localhost` or use HTTPS". The pages read state no equivalent requirement for the MCP
  server URL itself; the pack's claim rests on the RFC statement, not on a rule in
  the specification about that URL.
- Claude Code's MCP page says, for its v2 client runtime, that it "Sends MCP OAuth
  credentials only to a token endpoint served over HTTPS or at `localhost`,
  `127.0.0.1`, or `::1`." This is the source for the local host names. It is about the
  token endpoint, and it applies to the v2 runtime.

A server URL with the `http` scheme gives the client no transport security, so a
bearer token sent on it is exposed in the way the RFC describes. The check cannot see
whether a token is sent.

**Why the "no credentials" case is not a rule.** A client can sign in to a remote
server with nothing in the committed file, so a missing header says nothing about
authentication. Claude Code: "Use `/mcp` to authenticate with remote servers that
require OAuth 2.0 authentication". Cursor: "With dynamic client registration, Cursor
registers as a public client with no client secret." Gemini CLI documents "Automatic
OAuth discovery" and `/mcp auth`. Codex: "Codex can connect to the server without
authentication" and "Run `codex mcp login <server-name>` separately to start an MCP
OAuth login." How VS Code signs in to a remote server was not verified. A rule
that fired on a remote URL with no `Authorization` header would fire on servers that
are configured as the clients document.

**Real-world consequence:** a committed config with `"url": "http://mcp.example.com/mcp"`
points a developer's client at a server over a channel with no transport security.
If the client sends a bearer token there, it crosses the network readable by a party on
the path.

**Background source.** Huijun Zhou, Xiaohan Zhang, Haozhe Zhang, Haoyang Zhang, Mi
Zhang and Min Yang (arXiv 2605.22333, 21 May 2026, "A First Measurement Study on
Authentication Security in Real-World Remote MCP Servers") report that "3,233 (40.55%)
of the validated servers expose tool interfaces with no authentication at all". The
sample is 7,973 live servers validated from candidates found through FOFA and Shodan,
and the authors note a bias toward publicly indexed infrastructure. The paper measures
server-side authentication. It does not measure `http` versus `https` and does not
study client configuration files, so it does not support this rule's predicate. It is
cited as background for the problem class of unauthenticated remote MCP servers, and its
figure is not used in the rule.

**Why severity is medium:** The pack sets medium and states no reasoning for it. The
cost the explanation names is that a server URL over `http` gives the client no
transport security.

**Fix type — config:** the fix is an edit to the committed config: serve the endpoint
over `https://` and use that URL, or use `localhost` or `127.0.0.1` for a server on
the developer's own machine.

**Confidence 0.6:** the pack sets 0.6 for this rule and states these limits in its
explanation:

- It reads the `url` and `httpUrl` keys of each server entry in the MCP client config
  files the pack covers.
- A scheme or host written with a variable reference (`$VAR`) is not judged.
- A private address, `host.docker.internal` or a `.local` name is judged as not local.
- A TLS-terminating proxy or a VPN in front of the host is not seen.
- Whether the server requires a token is not judged.
- Windsurf's `serverUrl` is not read. Stdio launches are MCPCFG-002 and MCPCFG-003's.

**What this does not cover (false positives and evasion).** A development server on a
private network or in a container is flagged, because no client page read gives an
exemption for those hosts. A URL that is built from a variable, or a server reached
through a proxy configured outside the file, is not seen.

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
- The scope of a token or key (MCPCFG-004 reads the launch options and env names, not
  what the credential can do), and credentials supplied outside the file.
- Remote GitHub and Supabase servers' own scope settings (headers, URL paths and query
  parameters), and any server not named in MCPCFG-004.
- Whether a remote server requires authentication (MCPCFG-005 judges the transport
  scheme, not authentication), and `ws://` URLs.

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

For MCPCFG-004, the scoped forms from the fix text. Replace the placeholders with
your own values and keep the token in the developer's environment:

```json
{
  "mcpServers": {
    "github": {
      "command": "github-mcp-server",
      "args": ["stdio", "--read-only", "--toolsets=repos,issues"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_PAT}" }
    },
    "supabase": {
      "command": "npx",
      "args": ["-y", "@supabase/mcp-server-supabase@0.14.0", "--read-only", "--project-ref=<project-ref>"]
    }
  }
}
```

For MCPCFG-005, use `https://` for a remote server and `localhost` or `127.0.0.1` for
one on the developer's own machine.

---

## Sources

Retrieved 2026-10-28 unless a version is named.

- Invariant Labs, Marco Milanta and Luca Beurer-Kellner, "GitHub MCP Exploited:
  Accessing private repositories via MCP", 2025-05-26.
  https://invariantlabs.ai/blog/mcp-github-vulnerability (primary source for MCPCFG-004).
- Tural Hagverdiyev, "Compromise Is Not Consequence: Evaluating Task-Scoped
  Authorization in LLM Agents with Paired Replay", arXiv 2610.05840, submitted 5
  October 2026. https://arxiv.org/abs/2610.05840
- Simon Willison, "Supabase MCP can leak your entire SQL database", 6 July 2025.
  https://simonwillison.net/2025/Jul/6/supabase-mcp-lethal-trifecta/
- Rez Havaei, Rex Liu and Maximilian Li, General Analysis, "Supabase MCP Security: How
  Prompt Injection Leaked Private Tables", 8 July 2025, reviewed 21 October 2026.
  https://generalanalysis.com/blog/supabase-mcp-blog
- Huijun Zhou, Xiaohan Zhang, Haozhe Zhang, Haoyang Zhang, Mi Zhang and Min Yang, "A
  First Measurement Study on Authentication Security in Real-World Remote MCP
  Servers", arXiv 2605.22333, submitted 21 May 2026. https://arxiv.org/abs/2605.22333
  (background for MCPCFG-005).
- `github/github-mcp-server`, README, `docs/server-configuration.md`,
  `docs/remote-server.md`, `cmd/github-mcp-server/main.go`, `pkg/inventory/builder.go`,
  `pkg/github/server.go` at commit f692b2d981855ae4ee25e8bfff50d4733ff85b82.
  https://github.com/github/github-mcp-server
- `spf13/cast` v1.10.0 `basic.go` and `spf13/viper` v1.21.0 `viper.go`.
- npm `@modelcontextprotocol/server-github` 2025.4.8 (README, registry entry, source).
- `supabase-community/supabase-mcp` README at tag v0.5.5, and npm
  `@supabase/mcp-server-supabase` 0.14.0 (`dist/cli.cjs`).
  https://github.com/supabase-community/supabase-mcp
- Supabase, "API keys". https://supabase.com/docs/guides/api/api-keys
- Model Context Protocol specification, revision 2026-07-28: authorization,
  authorization security considerations, Streamable HTTP transport.
  https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- M. Jones and D. Hardt, RFC 6750, "The OAuth 2.0 Authorization Framework: Bearer Token
  Usage", October 2012, section 5.3. https://www.rfc-editor.org/rfc/rfc6750
- Claude Code, "Connect Claude Code to tools via MCP". https://code.claude.com/docs/en/mcp
- Cursor, "Model Context Protocol". https://cursor.com/docs/context/mcp
- Gemini CLI, `docs/tools/mcp-server.md`. https://github.com/google-gemini/gemini-cli
- OpenAI Codex, MCP page. https://learn.chatgpt.com/docs/extend/mcp?surface=cli
