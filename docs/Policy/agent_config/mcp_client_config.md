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
references: [LLM06, LLM03]
---

# Policy Rationale: Project MCP Client Configuration

**Policy ID:** `agent_config_mcp_client_config`  
**File:** `agent_config/mcp_client_config.yaml`  
**Rules:** MCPCFG-002  
**Severities:** high  
**Fix types:** config  
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
question: does a server entry start local, repo-controlled code? The pack loads for
every scan; the rule's predicate gates it.

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
paths are silent. Gated by `repo_mcp_config_launches_local_command`.

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
how to run it, which is flagged identically. Pinned-package detection is
structural only: `npx -y pkg` without a version is not flagged either, so the rule
under-reports unpinned remote packages.

---

## What this policy does not cover

- Unpinned `npx` / `uvx` packages and typosquatted package names (supply-chain risk
  of the *published* package, not local code).
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

1. Pin the exact package version, and prefer a registry you control.
2. If a local server is needed, document installation and register it in each
   developer's user-level config.
3. Never pair a project server list with `enableAllProjectMcpServers` (AGCFG-004).
