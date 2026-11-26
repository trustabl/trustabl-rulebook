---
policy_id: mcp_server_auth_transport
category: mcp
topic: server_auth_transport
rules:
  - id: MCP-206
    severity: high
    confidence: 0.6
    scope: repo
    fix_type: config
  - id: MCP-208
    severity: high
    confidence: 0.4
    scope: repo
    fix_type: code
  - id: MCP-209
    severity: high
    confidence: 0.5
    scope: repo
    fix_type: config
references: [LLM06]
---

# Policy Rationale: MCP Server Authentication and Transport Lifetime

**Policy ID:** `mcp_server_auth_transport`  
**File:** `mcp/server_auth_transport.yaml`  
**Rules:** MCP-206, MCP-208, MCP-209  
**Severities:** high, high, high  
**Fix types:** config, code, config  
**References:** OWASP LLM Top 10:2025 — LLM06 (Excessive Agency)

> **Verification status.** The advisories GHSA-w4fh-qvv9-3v23, GHSA-jm63-cq47-j5jp, GHSA-22jm-h49p-29qw and GHSA-j9xx-59ph-wmr6 and the SDK sources were read on 2026-11-26 as raw page text or through the advisory API. The NVD records CVE-2026-116684 and CVE-2026-61546 were read through the NVD API. **Not verified, and therefore not assumed:** the installed package versions in any repository the rules report; and whether a proxy or an authorization layer outside the scanned code covers the server.

---

## What this policy covers

**MCP-206** reads bearer settings without an audience check, **MCP-208** a server or transport shared across HTTP requests, and **MCP-209** DNS-rebinding protection switched off with no authentication in the file. All are repo-scope rules with one finding per site.

---

## Rule-by-rule defense

### MCP-206 — MCP server verifies bearer tokens with no audience check (Severity: high, Confidence: 0.6, Fix type: config)

**What we detect:** `repo_mcp_server_bearer_without_audience` (a Python `AuthSettings(...)` in a file that names `token_verifier`, with `validate_token_resource` absent, `None` or `False`, and no `aud` or `audience` text outside comments). Applies to `mcp` repositories.

**Why it is flaggable.** GitHub advisory GHSA-w4fh-qvv9-3v23 states that a server is affected "if your HTTP server uses the SDK's bearer authentication (auth=AuthSettings(...) with token_verifier=), its authorization server also issues tokens for other services, and your TokenVerifier does not check the token's audience (aud) itself", that "upgrading alone changes nothing. The patched versions add a validate_token_resource setting that is off unless you set it", and that the fix sets `validate_token_resource=True` with `resource_server_url` and returns the audience as `AccessToken.resource`. The SDK source (`settings.py`, `bearer_auth.py`) defaults the setting to `None` and passes the resource URL to the bearer middleware when the setting is true and not otherwise. Each source is cited for those statements and nothing more.

**Real-world consequence:** a token issued by the same authorization server for a different service is accepted by this server.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Fix type — config:** the fix is a configuration change in the settings call and the verifier return value.

**Confidence 0.6:** the pack's explanation states these limits of the check:

- It reads Python and one file at a time; the TypeScript `requireBearerAuth` variant is not judged.
- Any `aud` or `audience` text outside comments in the file counts as an audience check, including in an unrelated name or string.
- A settings call with `validate_token_resource=True` is not judged, and the rule does not check that `verify_token` returns the resource.
- The installed `mcp` version is not read.

**Field check, run on 2026-11-26** (prototype of the detector over cloned public repositories at the commits listed in the report `~/trustabl-reports/static-batch-2.md`; not a random sample; each repository was scanned once, with a 120 second cap). Sample: 5 repositories that use `AuthSettings` or `TransportSecuritySettings` were scanned (`modelcontextprotocol/python-sdk` 77001c9, `tadata-org/fastapi_mcp` e5cad13, `phil65/agentpool` d9fac80, `samuelgursky/davinci-resolve-mcp` 412cde1, `evalstate/fast-agent` 184ffe0). 0 hits. **0 hits: precision is not measured.**

### MCP-208 — MCP server shares one server or HTTP transport across requests (Severity: high, Confidence: 0.4, Fix type: code)

**What we detect:** `repo_mcp_server_shares_transport` (a TypeScript file that imports `@modelcontextprotocol/server` and declares an `McpServer` or `Server` at module scope that a function connects, or an imported HTTP transport class at module scope that a function passes a request to). Applies to `mcp` repositories.

**Why it is flaggable.** GitHub advisory GHSA-jm63-cq47-j5jp states that the problem occurs "when clients shared one stateless transport, or one McpServer or Server instance", that "messages were matched to a connection by JSON-RPC id alone", and that it applies if "your code creates the transport or the server once at startup, instead of once per request or per session". It lists `@modelcontextprotocol/server` 2.0.0 through 2.2.0 as affected, and `@modelcontextprotocol/sdk` 1.26.0 and later, stdio servers and `createMcpHandler()` with a per-call factory as not affected. The advisory is cited for those statements and nothing more.

**Real-world consequence:** on an affected version, one client's responses or notifications reach another client.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Fix type — code:** the fix moves construction into the request handler or a factory, or keeps one server and transport per session.

**Confidence 0.4:** the pack's explanation states these limits of the check:

- It reads files that import `@modelcontextprotocol/server`; the older `@modelcontextprotocol/sdk` package is not judged, because the advisory states 1.26.0 and later is not affected.
- The installed version is not read: release 2.3.0 rejects a second connect, so a hit on a patched version marks code that fails on the second client.
- A server created in another module and a shared `InMemoryTaskStore` (GHSA-22jm-h49p-29qw, `@modelcontextprotocol/sdk` 1.24.0 through 1.31.0) are not judged.

**Field check, run on 2026-11-26** (prototype of the detector over cloned public repositories at the commits listed in the report `~/trustabl-reports/static-batch-2.md`; not a random sample; each repository was scanned once, with a 120 second cap). Sample: the 5 TypeScript MCP repositories named under MCP-204. 0 hits; none imports `@modelcontextprotocol/server`. **0 hits: precision is not measured.**

### MCP-209 — MCP server switches DNS-rebinding protection off and names no authentication (Severity: high, Confidence: 0.5, Fix type: config)

**What we detect:** `repo_mcp_server_dns_rebinding_disabled` (a Python `TransportSecuritySettings(...)` with `enable_dns_rebinding_protection=False` in a file that names none of `token_verifier`, `auth_server_provider`, `AuthSettings` or `auth=` outside comments). Applies to `mcp` repositories.

**Why it is flaggable.** GitHub advisory GHSA-j9xx-59ph-wmr6 states that the server "starts a local Streamable HTTP MCP listener by default and explicitly disables FastMCP's DNS-rebinding protection", and that there is "no bearer token, API key, session secret, strict Host allowlist, or strict Origin allowlist before MCP dispatch". The SDK source (`transport_security.py`) sets `enable_dns_rebinding_protection` to `True` by default and its FastMCP turns protection on for a loopback host when no settings are given. Each source is cited for those statements and nothing more.

**Real-world consequence:** a web page in the person's browser can reach the local listener through a rebound host name and call its tools.

**Why severity is high:** The pack sets high and states no reasoning for it.

**Fix type — config:** the fix is a configuration change: leave protection on and list the served hosts and origins.

**Confidence 0.5:** the pack's explanation states these limits of the check:

- It reads Python and one file at a time, and a literal `False`.
- Settings with empty allow-lists and middleware in another file are not judged; any auth name in the file counts as authentication.
- The sources describe one product and do not show that a proxy or tunnel setup is unsafe; the bind address is not read.

**Field check, run on 2026-11-26** (prototype of the detector over cloned public repositories at the commits listed in the report `~/trustabl-reports/static-batch-2.md`; not a random sample; each repository was scanned once, with a 120 second cap). Sample: the 5 repositories named under MCP-206. 2 hits, both matches of the pattern: `modelcontextprotocol/python-sdk` `examples/stories/_hosting.py` (a constant `NO_DNS_REBIND` for a harness whose docstring says the servers bind 127.0.0.1), and `samuelgursky/davinci-resolve-mcp` `src/utils/mcp_transport.py` (settings with protection off returned when the host is a wildcard and no host names are given, in a file with no auth name). **Small sample: two hits in two repositories.**


---

## What this policy does not cover

- TypeScript `requireBearerAuth` audience checks (MCP-206).
- The shared task store of `@modelcontextprotocol/sdk` (MCP-208).
- Allow-lists that are empty and middleware in another file (MCP-209).

---

## Recommendations beyond the fix

1. Configure the audience and return it from the verifier.
2. Build a server and transport per request or per session.
3. List the served hosts and origins instead of switching protection off.

---

## Sources

- GitHub advisory GHSA-w4fh-qvv9-3v23: https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-w4fh-qvv9-3v23 Retrieved 2026-11-26. Cited for the audience statements and the configuration steps, and nothing more.
- GitHub advisory GHSA-jm63-cq47-j5jp: https://github.com/advisories/GHSA-jm63-cq47-j5jp Retrieved 2026-11-26. Cited for the shared server and transport statements and the affected versions, and nothing more.
- GitHub advisory GHSA-22jm-h49p-29qw: https://github.com/advisories/GHSA-22jm-h49p-29qw Retrieved 2026-11-26. Cited for the shared task store statement, and nothing more.
- GitHub advisory GHSA-j9xx-59ph-wmr6: https://github.com/ankimcp/anki-mcp-server-addon/security/advisories/GHSA-j9xx-59ph-wmr6 Retrieved 2026-11-26. Cited for the disabled protection and missing authentication statements, and nothing more.
- MCP Python SDK source, `transport_security.py` and `server/auth/settings.py`: https://github.com/modelcontextprotocol/python-sdk Retrieved 2026-11-26. Cited for the default value of the settings and how the audience setting is consumed, and nothing more.
