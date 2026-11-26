---
policy_id: mcp_client_launch
category: mcp
topic: client_launch
rules:
  - id: MCP-205
    severity: high
    confidence: 0.4
    scope: repo
    fix_type: code
  - id: MCP-207
    severity: high
    confidence: 0.5
    scope: repo
    fix_type: code
references: [LLM06]
---

# Policy Rationale: MCP Client Launches and Opens Values Supplied by Others

**Policy ID:** `mcp_client_launch`  
**File:** `mcp/client_launch.yaml`  
**Rules:** MCP-205, MCP-207  
**Severities:** high, high  
**Fix types:** code, code  
**References:** OWASP LLM Top 10:2025 — LLM06 (Excessive Agency)

> **Verification status.** The advisories GHSA-w794-rj3p-xv45 and GHSA-378x-q589-34mv, the Pillar Security write-up, the MCP specification security best practices page and the SDK sources were read on 2026-11-26 as raw page text. GHSA-378x-q589-34mv is not served by the global advisory page and was read through the repository advisory interface. The NVD records CVE-2026-116109 and CVE-2026-114612 were not used: the first gives no command shape and the second describes a forged credential. **Not verified, and therefore not assumed:** which clients reach these calls with input from an untrusted person; the installed `open` version in any repository the rules report; and the exploitability of the opener on macOS and Linux.

---

## What this policy covers

**MCP-205** reads MCP stdio client constructions in Python and TypeScript for a shell given `-c` or a command taken from request-like input. **MCP-207** reads an OAuth redirect handler that opens the server-supplied URL with no check. Both are repo-scope rules with one finding per site.

---

## Rule-by-rule defense

### MCP-205 — MCP stdio client is started with a shell given -c or a command taken from request input (Severity: high, Confidence: 0.4, Fix type: code)

**What we detect:** `repo_mcp_stdio_client_nonliteral_command` (a `StdioServerParameters`, `MCPServerStdio` params, `MultiServerMCPClient` entry or `StdioClientTransport` whose command is a shell with a `-c` style flag, or whose expression text names a request-like source). Applies to `mcp` repositories.

**Why it is flaggable.** GitHub advisory GHSA-w794-rj3p-xv45 states that the MCP stdio transport "launched whatever command / args a user put in an MCP server configuration, with no allowlist and (before 1.10.3) wrapped in bash -c", and that the SDK "starts the process with anyio.open_process, so the command runs before any MCP handshake". The advisory GHSA-378x-q589-34mv (read through the repository advisory interface) describes an endpoint that accepts the stdio transport and "spawns the attacker-supplied command with attacker-supplied args". The MCP specification security best practices page lists a malicious startup command in a client configuration under "Local MCP Server Compromise", with "arbitrary code execution". Each source is cited for those statements and nothing more.

**Real-world consequence:** a person who can submit the command runs it on the host with the client's privileges before any protocol handshake.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Fix type — code:** the fix is an edit to the launch code: an allow-list of executables, no shell wrapper, and authorization before the spawn.

**Confidence 0.4:** the pack's explanation states these limits of the check:

- It reads the call in one file; a command that is an identifier assigned once to a string literal is treated as a literal.
- A configuration value, a function parameter or any expression with none of the listed words is not judged, so a client that launches the servers its user configured is not reported.
- The listed words are matched as whole words; the rule does not show that the person who supplies the value is untrusted.
- A file that names an allow-list is not judged for a request-derived command, and the rule does not check that the list is applied; a shell with `-c` is reported without that exemption.

**Field check, run on 2026-11-26** (prototype of the detector over cloned public repositories at the commits listed in the report `~/trustabl-reports/static-batch-2.md`; not a random sample; each repository was scanned once, with a 120 second cap). Sample: 10 repositories that build stdio clients were scanned (`modelcontextprotocol/python-sdk` 77001c9, `mcp-use/mcp-use` bc8fb6f, `grll/mcpadapt` 538cd85, `HexamindOrganisation/hexgate` af5318c, `alirezadir/Agentic-AI-Systems` 43e62b5, `evalstate/fast-agent` 184ffe0, `alisaitteke/photoshop-mcp` d68a74f, `apify/mcpc` cdeae24, `nicobailon/pi-mcp-adapter` f7a63f3, `artokun/comfyui-mcp` f4c4077). The first version of the rule reported any non-literal command: 8 sites in 6 repositories. All 8 were clients that start a server from the user's own configuration, which the cited advisories do not describe, so they were false positives and the rule was narrowed to the two shapes above. After the change 0 sites remained in the 3 repositories re-scanned (`mcp-use/mcp-use`, `HexamindOrganisation/hexgate`, `alirezadir/Agentic-AI-Systems`); the other 3 repositories with hits were judged from the saved lines, which name `config.command`, `process.execPath` and `command_or_url`, none of them a listed word. **0 hits after tightening: the precision of the narrowed rule is not measured.**

### MCP-207 — MCP client passes a server-supplied URL to an operating-system opener with no check (Severity: high, Confidence: 0.5, Fix type: code)

**What we detect:** `repo_mcp_client_opens_server_url` (a Python function of one parameter in a file that imports `mcp`, or a TypeScript `redirectToAuthorization` method or property, whose body passes the parameter to an opener and contains no scheme, origin or host check). Applies to `mcp` repositories.

**Why it is flaggable.** The Pillar Security write-up of the opencode vulnerability states that the authorization endpoint "is a free-form string. The server being authenticated picks it", that "there was no scheme check on that path, there was no comparison against the origin of the server you configured", that on Windows the `open` package at 10.1.2 put the target in a PowerShell command without escaping it, and that "normal scheme validation does not stop it". The MCP specification security best practices page states that clients "MUST validate authorization URLs", "MUST NOT use shell commands" to open URLs and must allow the http and https schemes. Each source is cited for those statements and nothing more.

**Real-world consequence:** a server that a client is configured to trust chooses a URL string that the client hands to an opener; on the Windows path in the write-up that string reaches a PowerShell command.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Fix type — code:** the fix is an edit to the handler: parse the URL, allow https, compare the origin, and use an argument-vector opener.

**Confidence 0.5:** the pack's explanation states these limits of the check:

- It reads one function body at a time; a handler in another file or a URL passed through a helper before the opener is not seen.
- The write-up's exploited sink is the Windows and WSL PowerShell path of the `open` package, and its text says macOS and Linux use an argument vector, so a hit that runs on those systems is a departure from the specification and not shown to be exploitable.
- Any scheme, origin or host text in the body counts as a check without the rule judging the check.
- The version of the `open` package is not read.

**Field check, run on 2026-11-26** (prototype of the detector over cloned public repositories at the commits listed in the report `~/trustabl-reports/static-batch-2.md`; not a random sample; each repository was scanned once, with a 120 second cap). Sample: the same 10 repositories as MCP-205. 1 hit, in `modelcontextprotocol/python-sdk` `examples/clients/simple-auth-client/mcp_simple_auth_client/main.py` (`_default_redirect_handler` prints the URL and calls `webbrowser.open(authorization_url)` with no check): a match of the pattern in an example client, whose opener runs outside the PowerShell path. 0 other hits. **Small sample: one hit.**


---

## What this policy does not cover

- Commands read from a configuration object, a parameter or a differently named variable (MCP-205).
- Handlers in another file, and the `open` package version (MCP-207).

---

## Recommendations beyond the fix

1. Keep an allow-list of executables for any client that starts servers from submitted data.
2. Open authorization URLs after a scheme and origin check, with an argument-vector launcher.

---

## Sources

- GitHub advisory GHSA-w794-rj3p-xv45: https://github.com/advisories/GHSA-w794-rj3p-xv45 Retrieved 2026-11-26. Cited for the stdio launch statements and the vulnerable and fixed code shapes, and nothing more.
- GitHub advisory GHSA-378x-q589-34mv (repository advisory interface): https://github.com/heymrun/heym/security/advisories/GHSA-378x-q589-34mv Retrieved 2026-11-26. Cited for the statement about the stdio transport and the attacker-supplied command, and nothing more.
- MCP specification, Security Best Practices: https://modelcontextprotocol.io/specification/draft/basic/security_best_practices Retrieved 2026-11-26. Cited for the local server compromise and authorization URL validation statements, and nothing more.
- Pillar Security, "Open and Shut: Remote Code Execution in opencode via MCP OAuth": https://www.pillar.security/blog/open-and-shut-remote-code-execution-in-opencode-via-mcp-oauth Retrieved 2026-11-26. Cited for the free-form authorization endpoint, the missing checks and the `open` package behavior, and nothing more.
