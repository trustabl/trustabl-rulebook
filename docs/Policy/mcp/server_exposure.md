---
policy_id: mcp_server_exposure
category: mcp
topic: server_exposure
rules:
  - id: MCP-203
    severity: high
    confidence: 0.6
    scope: repo
    fix_type: code
references: [LLM06]
---

# Policy Rationale: MCP Server HTTP Exposure

**Policy ID:** `mcp_server_exposure`  
**File:** `mcp/server_exposure.yaml`  
**Rules:** MCP-203  
**Severities:** high  
**Fix types:** code  
**References:** LLM06 (Excessive Agency)

> **Verification status.** The MCP specification, the Python SDK source and the TypeScript SDK
> source were read as raw text on 2026-11-12, at these revisions: specification revision
> 2026-07-28 at commit `0b22bfed6e94` of `modelcontextprotocol/modelcontextprotocol`; Python
> SDK tags v2.3.0 and v1.27.0; TypeScript SDK tag v1.29.0. The standalone `fastmcp` package
> (a different package from the SDK) was read for two facts: its default host and its
> `auth` argument. **Not verified, and therefore not assumed:** how the TypeScript SDK's v2
> packages name their Express, Fastify and Hono helpers; whether any client or deployment puts
> a proxy, firewall or network policy in front of a server bound this way; and the behavior of
> versions other than those read. A scan of 24 public repositories that implement MCP servers,
> run on 2026-11-12 with the engine, produced one MCP-203 finding: `examples/get_file.py:40` in
> `PrefectHQ/fastmcp` (commit `713042447f2d`), which calls `.run(transport="sse",
> host="0.0.0.0", ...)` on the result of a same-file function that returns a `FastMCP`
> instance, with no auth or allow-list in the file; read by hand, it is a correct finding in an
> example file. No other repository produced one. A plain text search of the sample also finds
> a wildcard bind in the TypeScript SDK's own example file, which imports the helper from a
> relative path and is not read by the rule. The rule's own corpus fixture is the evidence that
> each form fires.

---

## What this policy covers

This policy has one rule, **MCP-203**, repo scope, attributed to the offending call. It flags
MCP server code that starts an HTTP transport bound to all network interfaces, with no
authentication and no host or origin allow-list named in the same file.

Python: a `FastMCP(...)` or `MCPServer(...)` imported from `mcp.server.fastmcp`,
`mcp.server.mcpserver`, `mcp.server` or `fastmcp`, reached as a variable bound in the file, as
the constructor call itself (`FastMCP(...).run(...)`), or as the result of a call to a function
defined at the top level of the same file whose single `return` is the constructor call or a
variable assigned once to it (one hop). Its `.run(transport=..., host=...)` call names an `sse`,
`http` or `streamable-http` transport and a literal `0.0.0.0`, `::` or `[::]` host; in SDK v1 the
host may sit on the constructor. `run_sse_async` and `run_streamable_http_async` (SDK methods
that take `host`) are read the same way, with the transport implied.
TypeScript: a `createMcpExpressApp({ host })` call, imported from
`@modelcontextprotocol/sdk/server/express.js`, with such a literal host. Credit that silences
the rule: an `auth`, `token_verifier` or `auth_server_provider` argument on the constructor or
a `transport_security` argument (Python); an `allowedHosts` key, an object spread, or an import
from the SDK's auth modules (TypeScript). A `**kwargs` splat on the constructor or run call
silences it. Files under test paths are not judged.

---

## Why a wildcard bind is flaggable

The Streamable HTTP transport section of the MCP specification ("Security & Endpoint") states
three requirements: servers "MUST validate the `Origin` header on all incoming connections to
prevent DNS rebinding attacks"; when running locally, servers "SHOULD bind only to localhost
(127.0.0.1) rather than all network interfaces (0.0.0.0)"; and servers "SHOULD implement
proper authentication for all connections".

The SDKs act on the second one for a loopback host and not for another host. Python SDK v2.3.0, in
`src/mcp/server/mcpserver/server.py`, has the comment "Auto-enable DNS rebinding protection
for localhost (IPv4 and IPv6)" and applies the protection
`if transport_security is None and host in ("127.0.0.1", "localhost", "::1")`; v1.27.0's
`fastmcp/server.py` has the same condition, and both default `host` to `"127.0.0.1"`. The
TypeScript SDK v1.29.0 `createMcpExpressApp` documents its `host` as defaulting to
`'127.0.0.1'`, enabling DNS rebinding protection "automatically" for `127.0.0.1`, `localhost`
and `::1`, and for `0.0.0.0` or `::` without `allowedHosts` writing a console warning and
nothing else; its own example is annotated "No automatic DNS rebinding protection". So a literal wildcard host
with no authentication, no `transport_security` and no `allowedHosts` leaves the server with
neither the SDK's Host and Origin check nor authentication. The pack states no further
reasoning for treating that as a signal.

---

## Rule-by-rule defense

### MCP-203 — MCP server is bound to all interfaces with no authentication or host allow-list (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:** the shapes in the section above, that is a Python `.run(...)`,
`run_sse_async(...)` or `run_streamable_http_async(...)` call and a TypeScript
`createMcpExpressApp({ host })` call, gated by
`repo_mcp_server_binds_all_interfaces_unprotected`, backed by `RepoInventory.MCPServerBinds`
(one record per bind, with its file, line and language). The host text is reduced to the
judgment during discovery and is not stored, and a host from a variable, an f-string or an
environment lookup is not judged.

**Why it is flaggable:** see the section above.

**Real-world consequence:** a tool server that answers any client able to reach its port.
The specification's DNS-rebinding sentence states that without these protections "attackers
could use DNS rebinding to interact with local MCP servers from remote websites". The pack does
not state a measured consequence for a wildcard bind.

**Severity:** the pack sets high and states no reasoning for it. The specification words the
localhost bind and the authentication as SHOULD and the Origin check as MUST.

**Fix type — code:** bind to `127.0.0.1`, or configure the SDK's authentication and an
allowed-host and origin list.

**Confidence 0.6:** The pack sets 0.6. The pack's explanation states these limits: the check reads
literal host values and one file at a time; in Python the server is found as a variable bound in
the file to the constructor, the constructor call itself, or the result of a call to a top-level
function of the same file whose single return statement is the constructor call or a variable
assigned once to it; a factory that is imported, decorated, defined twice, nested, has more than
one return statement or calls another factory is not followed; a host from a variable or an
environment lookup, a default host, a uvicorn or other ASGI launch of an MCP app, and
authentication or a proxy configured in another file or outside the repo are not seen, so the rule
can fire on a server protected elsewhere and stay silent on one that is not; credit is given for an
auth, token_verifier, auth_server_provider or transport_security argument in Python, and for
allowedHosts or an import of the SDK's auth modules in TypeScript; and files under test paths are
not judged.

---

## What this policy does not cover

- A host that comes from a variable, an environment lookup or a default, such as
  `os.getenv("MCP_HOST", "0.0.0.0")` or `process.env.HOST || '0.0.0.0'`. Two repositories in
  the sample use that form; the rule is silent on it.
- A loopback host, the SDK default host, and a server run over stdio.
- A factory that is imported, decorated, defined twice, nested, has more than one `return`, or
  calls another factory (more than one hop), and a server returned from another file.
- A server launched through uvicorn or another ASGI runner, such as
  `uvicorn.run(mcp.http_app(), host="0.0.0.0")`. The link from the app to an MCP object is not
  tracked.
- Authentication, a proxy or a firewall configured in another file or outside the repo. The
  rule can fire on a server protected elsewhere and stay silent on one that is not.
- An HTTP server on a loopback host with no authentication. The specification words
  authentication as SHOULD and the SDKs default to loopback, so it is not judged.
- Whether a custom Origin check exists. The specification's Origin requirement is a MUST, and
  the rule reads the SDK arguments and nothing else.
- The TypeScript SDK's v2 packages and its Fastify and Hono helpers, Go, Rust, PHP and C#
  servers, and servers whose `FastMCP` or `MCPServer` variable is bound in another file.
- Test paths.

---

## Recommendations beyond the fix

1. Bind to `127.0.0.1` for a local server, and publish a container port on loopback unless it
   must be reachable.
2. When a server must be reachable, configure the SDK's authentication and an allowed-host and
   origin list, and place it behind a network control.
3. Read the host from configuration and keep the default at loopback.
4. Re-run the scan after the change; a second server in the same file is judged separately.

---

## Sources

- Model Context Protocol, specification revision 2026-07-28, `basic/transports/streamable-http`,
  section "Security & Endpoint", repository `modelcontextprotocol/modelcontextprotocol` at
  commit `0b22bfed6e94`. Retrieved 2026-11-12. Cited for the three quoted requirements and the
  DNS-rebinding sentence, and nothing more.
- Python SDK, `modelcontextprotocol/python-sdk`, tag v2.3.0, `src/mcp/server/mcpserver/server.py`,
  and tag v1.27.0, `src/mcp/server/fastmcp/server.py`. Retrieved 2026-11-12. Cited for the
  default host, the loopback DNS-rebinding condition and the `auth`, `token_verifier`,
  `auth_server_provider` and `transport_security` arguments, and nothing more.
- TypeScript SDK, `modelcontextprotocol/typescript-sdk`, tag v1.29.0, `src/server/express.ts`
  and `src/server/auth/`. Retrieved 2026-11-12. Cited for the `createMcpExpressApp` host
  default, its `allowedHosts` option, its warning behavior and the auth helper names, and
  nothing more.
- Standalone `fastmcp` package, `PrefectHQ/fastmcp` at commit `713042447f2d`,
  `fastmcp_slim/fastmcp/settings.py` and `fastmcp_slim/fastmcp/server/server.py`. Read
  2026-11-12. Cited for the default host `127.0.0.1` and the `auth` argument, and nothing more.
