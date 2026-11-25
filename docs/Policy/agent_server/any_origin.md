---
policy_id: agent_server_any_origin
category: agent_server
topic: any_origin
rules:
  - id: AGSRV-001
    severity: high
    confidence: 0.6
    scope: repo
    fix_type: config
references: []
---

# Policy Rationale: Agent Server That Accepts Any Browser Origin

**Policy ID:** `agent_server_any_origin`  
**File:** `agent_server/any_origin.yaml`  
**Rules:** AGSRV-001  
**Severities:** high  
**Fix types:** config  
**References:** none

> **Verification status.** The CVE record was read on 2026-11-09 from the NVD JSON API and
> from the CVE JSON 5 file (`CVE-2026-107858`); the vendor behavior was read on the same date
> from the commits and the 1.13.0 release notes of `google/adk-java`, and from the source of
> `google/adk-js` and `google/adk-python` on their main branches. The NVD and cve.org web
> pages were not used. **Not verified, and therefore not assumed:** the date on which the
> Python and TypeScript origin checks first appeared; how `CORSMiddleware` treats
> `allow_credentials=True` together with a `*` origin, since that is behavior of the
> middleware library and its source was not read; which routes the TypeScript server
> exposes to a foreign origin when `*` is set, and what they do (the origin check, the
> host guard and the CORS configuration were read); which Python endpoints a foreign page
> can use beyond the exception the vendor states; whether any ADK documentation
> page, as opposed to source code, describes the Python and TypeScript options; and the
> Google issue tracker entry linked from the Java issue.

---

## What this policy covers

A development server for an agent accepts requests from the browser of the developer who runs
it. If the server's allowed-origin list is `*`, a web page the developer visits can send those
requests. The pack loads for each scan, because the files it reads have no single SDK import;
the rule's own predicate does the gating.

This policy has one rule. **AGSRV-001** flags a committed `*` origin list on a Google ADK
server. It is repo scope and fires once per scan, attributed to the first path-sorted
offending file and line.

---

## Rule-by-rule defense

### AGSRV-001 — Agent server is configured to accept any browser origin (Severity: high, Confidence: 0.6, Fix type: config)

**What we detect:** a `*` entry in the origin list of an ADK server, set in one of four
places. Gated by `repo_agent_server_allows_any_origin`.

- The `adk.web.cors.origins` key of a Spring `application*.properties`, `application*.yml`
  or `application*.yaml` file, at any depth. Java is read through this key and no other.
- The `allow_origins` list of a `get_fast_api_app(...)` call in a Python file that imports
  `google.adk`, outside test paths.
- The `allowOrigins` option of an `AdkApiServer(...)` call in a TypeScript or JavaScript
  file that imports `@google/adk-devtools`, outside test paths.
- An `--allow_origins` option of an `adk web` or `adk api_server` command, in a Dockerfile,
  Makefile, shell script, compose `command` or `entrypoint`, or `package.json` script.

What is not flagged:

- A value taken from an environment variable, a narrower origin list, or an origin pattern.
- Java source such as `setAllowedOrigins("*")`; the engine does not parse Java.
- An ADK Java server with no origins setting. Whether its default is open depends on the
  release in use, which is a dependency version question outside this check.
- Generic CORS middleware, and a bind address such as `--host`.
- A call inside a comment or a string literal, and a commented script line.
- A reverse proxy or network rule in front of the server.

**Why it is flaggable.** The mechanism is in the CVE record for the ADK Java development
server (`CVE-2026-107858`, assigner Google, published 2026-10-23, finders credited as George
Chen and Gouri Sankar A). The description states: "Because the server has no authentication
and requests originate from the developer's browser (so binding to localhost does not prevent
exploitation), a cross-origin page can send messages to the agent (triggering registered
tools), stream agent responses, and list, read, create, or delete sessions and artifacts."

The vendor's own change shows what the setting does. The Java development README, in the
commit that rejects DNS-rebinding requests, states: "Avoid `*`: it lets any website open in
your browser call the server." The Javadoc of the origin guard in that commit
states that `*` "turns both checks off".

In `google/adk-js` (main branch) the `allowOrigins` option comment states that `'*'`
"disables the DNS-rebinding guard". Two more lines of that source show what a `*` entry does.
`isRequestOriginAllowed` in `dev/src/server/origin_check.ts` returns true when
`allowedOrigins.includes('*') || allowedOrigins.includes(origin)` holds, and the middleware
built on it is documented as "Express middleware rejecting cross-origin state-changing
requests." Methods other than GET, HEAD and OPTIONS are the ones it checks. In
`dev/src/server/adk_api_server.ts` the CORS middleware is configured with
`origin: this.allowedOrigins.includes('*') ? '*' : this.allowedOrigins,` and
`credentials: true,`. So with `*` a foreign page's state-changing request is not rejected by
the origin check, the host guard is off, and responses carry the wildcard CORS header. Which
routes the TypeScript server then exposes, and what they do, was not read.

For ADK Python, `src/google/adk/cli/api_server.py` at commit `1cb926d` (the head of the main
branch on 2026-11-09) shows where the `allow_origins` argument of `get_fast_api_app` goes. When
the list is not empty, lines 1587-1600 parse it into literal origins and a regex and pass them
to `CORSMiddleware` as `allow_origins=literal_origins`, with `allow_credentials=True`. A `*`
entry is a literal origin: `_is_origin_allowed` returns true when `if "*" in
allowed_literal_origins:` holds (lines 175-176), and the DNS-rebinding guard's host check
returns no restriction for it (lines 314-317). The docstring at lines 437-440 says `*` and
`regex:` entries open the API to other sites, but not the endpoints that write agent files or
start runs; the vendor's text says those accept a browser request from the server's own
origin or from an origin listed literally. So for Python the wildcard reaches the browser-facing
API, with that exception stated by the vendor.

**Real-world consequence,** by language. The pack's explanation states these and does not state
a figure for how many repositories do it.

- **ADK Java (per the CVE record for the Java development server):** a cross-origin page can
  send messages to the agent, which triggers registered tools, stream its responses, and list,
  read, create or delete sessions and artifacts, even when the server is bound to localhost.
- **ADK Python (per the vendor's source):** a `*` entry opens the API to other sites, except the
  endpoints that write agent files or start runs. The docstring at `api_server.py` lines
  437-440 says this, and the 403 detail at lines 449-451 says those endpoints accept a browser
  request from the server's own origin or an origin listed literally. The Java consequence
  above is not claimed for Python.
- **ADK TypeScript (per the source read above):** a foreign page's state-changing request is
  accepted by the origin check, the DNS-rebinding guard is disabled, and responses carry the
  wildcard CORS header. What the reachable routes do is not claimed; the Java consequence is
  not claimed for TypeScript.

**Why severity is high:** The pack sets high and states no reasoning for it. The CVE record
carries a CVSS v4.0 base score of 7.2 (high) for the Java server issue; that score is stated
for that issue, not for this rule.

**Fix type — config:** the fix is an edit to the committed setting. The pack's fix lists the
exact origins that serve the UI, for example `http://localhost:8000`, and removes the `*`
entry; it leaves the setting unset when the UI is served from the same origin as the server.

**Confidence 0.6:** the pack's explanation states these limits of the check:

- It reads the four places above and no others.
- A value from an environment variable, a narrower list, an origin pattern, source files in
  test paths, Java source and generic CORS middleware are not judged.
- An ADK Java server with no origins setting is not judged.
- A call inside a comment or a string literal, and a commented script line, are not judged.
- A reverse proxy or network rule in front of the server is not seen, and a bind address is
  not judged.

On 2026-11-09 the detector's logic was run as a prototype over 28 public repositories that use
Google ADK (Python, TypeScript and Java). Ten of them are Java; none sets
`adk.web.cors.origins`. Across the 28 it found two Python servers that pass `allow_origins`
with a `*` entry to `get_fast_api_app`, and one Makefile target that runs
`adk api_server` with `--allow_origins="*"`. It also matched eight calls in the test directory
of the vendor's Python repository, which is why the check skips test paths. The pack states no
measurement of the rule's precision or recall.

---

## What this policy does not cover

- Java source that sets the wildcard in code (`setAllowedOrigins("*")`).
- The default of an ADK Java server that sets nothing.
- Bind addresses, TLS, and authentication of any server.
- Servers other than ADK.

---

## Recommendations beyond the fix

List the origins that serve your UI, for example in `application.properties`:

```properties
adk.web.cors.origins=http://localhost:8000
```

1. Name the exact origins instead of `*` in `adk.web.cors.origins`, `allow_origins`,
   `allowOrigins` or `--allow_origins`.
2. Leave the setting unset when the UI is served from the same origin as the server.
3. Review changes to server start commands and Spring configuration in pull requests.

---

## Sources

- NVD JSON API record for CVE-2026-107858:
  https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-107858 Retrieved
  2026-11-09. Cited for the description quoted above, the publication date, and the fixed
  version, and nothing more.
- CVE JSON 5 record for CVE-2026-107858 (assigner Google):
  https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/107xxx/CVE-2026-107858.json
  Retrieved 2026-11-09. Cited for the title and the credited finders, and nothing more.
- google/adk-java commit 1ae5078072e13e101318e32833f1db323ef084e1 and release v1.13.0:
  https://github.com/google/adk-java/commit/1ae5078072e13e101318e32833f1db323ef084e1
  Retrieved 2026-11-09. Cited for the README sentence and the guard comment quoted above,
  and nothing more.
- google/adk-js `dev/src/server/adk_api_server.ts` (main branch), retrieved 2026-11-09. Cited
  for the `allowOrigins` option comment and the CORS configuration, and nothing more.
- google/adk-js `dev/src/server/origin_check.ts` (main branch), retrieved 2026-11-09. Cited for
  `isRequestOriginAllowed` and the origin-check middleware description, and nothing more.
- google/adk-python `src/google/adk/cli/cli_tools_click.py` (main branch), retrieved
  2026-11-09. Cited for the `--allow_origins` option name, and nothing more.
- google/adk-python `src/google/adk/cli/api_server.py` at commit
  1cb926d5b8d702261ec82a26d3f1c4296e0db7d7:
  https://raw.githubusercontent.com/google/adk-python/1cb926d5b8d702261ec82a26d3f1c4296e0db7d7/src/google/adk/cli/api_server.py
  Retrieved 2026-11-09. Cited for how `allow_origins` reaches `CORSMiddleware` and what a `*`
  entry does in the origin check, and nothing more.
