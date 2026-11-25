---
policy_id: agent_server_unauthenticated_publish
category: agent_server
topic: unauthenticated_publish
rules:
  - id: AGSRV-002
    severity: critical
    confidence: 0.7
    scope: repo
    fix_type: config
references: []
---

# Policy Rationale: OpenHands Agent Server Bound to All Interfaces Without a Session Key

**Policy ID:** `agent_server_unauthenticated_publish`  
**File:** `agent_server/unauthenticated_publish.yaml`  
**Rules:** AGSRV-002  
**Severities:** critical  
**Fix types:** config  
**References:** none

> **Verification status.** The advisory and the CVE record were read on 2026-11-09 from the
> VulnCheck advisory page, the NVD JSON API and the CVE JSON 5 file (`CVE-2026-112346`). The
> vendor behavior was read on the same date from commit `7b66584` (pull request #5209) and
> from the `v1.52.0` source of `OpenHands/software-agent-sdk`: `__main__.py` and `config.py`
> of the agent server, the agent server `Dockerfile`, and `docker/workspace.py`. **Not
> verified, and therefore not assumed:** whether `ApptainerWorkspace` is exposed after the
> change in that commit; the user the container runs as; which server routes map to the shell
> and secrets access the advisory describes; how a request authenticates over WebSocket; the
> binary entrypoint's bind default (it is read as the same program, not inspected); and the
> defaults of any release other than `v1.52.0`.

---

## What this policy covers

The OpenHands agent server runs inside a sandbox container and takes HTTP and WebSocket
requests. Its configuration holds a list of session API keys, and its `--host` option sets
the address it binds. The pack loads for each scan, because the files it reads have no SDK
import; the rule's own predicate does the gating.

This policy has one rule. **AGSRV-002** flags a committed Docker Compose service, or a
`docker run` command, that runs the agent server image, sets the server's `--host` to a
non-loopback address, publishes the port on all host interfaces and names no session API key.
It is repo scope and fires once per scan, attributed to the first path-sorted offending file
and line.

---

## Rule-by-rule defense

### AGSRV-002 — OpenHands agent server is bound to all interfaces and published with no session key (Severity: critical, Confidence: 0.7, Fix type: config)

**What we detect:** a Compose service in a `docker-compose*.yml` or `compose*.yml` file, or a
`docker run` line in a Dockerfile, shell script or Makefile, that meets all of these. Gated by
`repo_agent_server_exposed_without_key`.

- The image is `ghcr.io/openhands/agent-server`, written literally or as the default inside
  `${VAR:-default}`.
- A port is published without a loopback host address: a short mapping such as `8010:8000`, a
  bare container port, or a long-syntax entry with no `host_ip` or with `0.0.0.0`.
- The server's `--host` is an IP literal other than a loopback address, such as `0.0.0.0`,
  `::` or `[::]`. It is read from the Compose `entrypoint` or `command` (a list or a string),
  or from the arguments after the image in a `docker run` line, as `--host VALUE` or
  `--host=VALUE`.
- The environment names neither `OH_SESSION_API_KEYS_0` (any `OH_SESSION_API_KEYS_` name) nor
  `SESSION_API_KEY`. Names are read, not values; a name set to an empty value counts as set.

What is not flagged:

- A service that sets no `--host`, a loopback `--host`, a `--host` that is a host name or a
  variable reference, and a `--host` that appears before the image in a `docker run` line.
- A service built from a local or renamed image.
- A service with an `env_file`, or a `docker run` command with `--env-file`.
- A port mapping whose host address is a variable, and a commented `docker run` line.
- A key set in another compose file that is merged at run time; each compose file is judged
  on its own. The config-file path option of the server is not read.
- An image tag whose server defaults differ from the source read here, which is a version
  question outside this check.
- Kubernetes Services, `uvicorn` commands, and the `DockerWorkspace` and `ApptainerWorkspace`
  launchers.
- Firewalls and networks outside the repo.

**Why it is flaggable.** All server behavior in this list is from the `v1.52.0` source, read
on 2026-11-09.

- How the bind address is set. `__main__.py` defines `--host` with `default=None` (lines
  215-223) and resolves it at lines 282-285. The config model in `config.py` has no host or
  bind field, and the server reads no environment variable for the address; the
  `OH_INTERNAL_SERVER_URL` variable that appears in `__main__.py` is set by the server, not
  read as input (line 296).
- The default is loopback. The loopback address is defined as `_LOOPBACK_HOST = "127.0.0.1"`
  (line 27). With no `--host` and no key the code takes the loopback branch of line 285.
- The default with a key is all interfaces. Line 285 reads
  `host = "0.0.0.0" if auth_enabled else _LOOPBACK_HOST`, where `auth_enabled` is true when
  at least one session API key is configured (`_auth_enabled`, lines 30-48, which returns
  `bool(config.session_api_keys)`). The `--host` help text (lines 218-221) says the same,
  naming `SESSION_API_KEY` and `OH_SESSION_API_KEYS_0`.
- An explicit host is used as given. The comment at lines 275-281 says an explicit wildcard
  host without a key is allowed, and lines 286-293 log a warning for it. So
  `--host 0.0.0.0` with no key starts an unauthenticated server on all interfaces.
- The image adds no host. The agent server `Dockerfile` ends its stages with an `ENTRYPOINT`
  and no `CMD`, for example
  `ENTRYPOINT ["tini", "--", "/agent-server/.venv/bin/python", "-m", "openhands.agent_server"]`
  (lines 571 and 576), and sets no host variable. An image started with no command and no key
  therefore binds loopback inside the container.
- What the launcher passes. `docker/workspace.py` builds the run command with `--host`,
  `0.0.0.0`, `--port` and `8000` after the image (lines 247-252). That is the explicit
  wildcard this rule looks for.
- What a missing key means. The server's configuration states for `session_api_keys`: "Empty
  list implies the server will be unsecured."

The VulnCheck advisory for CVE-2026-112346 (published 2026-10-26, severity critical, credited
finder `mil4n`) states: "Attackers who can reach the published container port can send
unauthenticated HTTP and WebSocket requests to execute arbitrary shell commands as root in the
sandbox, access the mounted workspace, and read plaintext secrets from the secrets store."

What the vendor's change did. Commit `7b66584` (pull request #5209, in release `v1.52.0`)
changes `DockerWorkspace` so that the host-side port flag becomes
`127.0.0.1:{host_port}:8000` instead of `{host_port}:8000`, and makes the workspace client read
`OH_SESSION_API_KEYS_0`, then `SESSION_API_KEY`, for its API key. The commit changes the
Docker launcher file and its test, and no other file. It does not change the address the
server binds inside the container, and it does not set a key. Whether `ApptainerWorkspace` is
exposed after the change was not verified. The server itself reads both key names: `config.py`
defines `V0_SESSION_API_KEY_ENV = "SESSION_API_KEY"` (line 23) and
`V1_SESSION_API_KEY_ENV = "OH_SESSION_API_KEYS_0"` (line 24), and `_default_session_api_keys`
(lines 34-45) reads the first through `os.getenv` as the default of `session_api_keys` (line
228). A Compose file that publishes the port with a short mapping, sets `--host 0.0.0.0` and
names neither variable is the setup the launcher built before that change, written in a repo.

**Real-world consequence:** a person who can reach the published port can run shell commands
in the sandbox and read its workspace and secrets store, according to the advisory. The pack's
explanation states this and does not state a figure for how many repositories do it.

**Why severity is critical:** The pack sets critical and states no reasoning for it. The
advisory rates the issue critical with a CVSS v4.0 base score of 9.3; that score is stated for
the advisory's issue, not for this rule.

**Fix type — config:** the fix is an edit to the committed Compose file or command. The
pack's fix publishes the port on loopback, for example `127.0.0.1:8010:8000`, and sets a
session API key in the service environment, such as `OH_SESSION_API_KEYS_0` taken from a
secret. It adds not to set `--host 0.0.0.0` without a session API key, and to send the same key
from the client in the `X-Session-API-Key` header.

**Confidence 0.7:** the predicate requires three literal facts in the committed file, and the
source read above says that together they describe a server on all interfaces with no
authentication. The pack's explanation states these limits of the check:

- It matches the image path `ghcr.io/openhands/agent-server` in a Compose service or in a
  `docker run` command; a local or renamed image is not judged.
- A `--host` counts when it is an IP literal other than a loopback address; a host name, a
  variable reference and a loopback address are not judged.
- Key names are read, not values.
- An `env_file`, a `--env-file` option, a variable host address, a commented `docker run` line,
  a key set in a merged compose file and the config-file path option are not judged.
- An image tag whose server defaults differ is a version question outside this check.
- Kubernetes Services, `uvicorn` commands and the workspace launchers are not read.
- Firewalls and networks outside the repo are not seen, so a host that is not reachable from
  other machines still matches.

On 2026-11-09 the detector's logic was run as a prototype over 12 public repositories that use
the OpenHands SDK or deploy it with Docker Compose, and the built scanner was run over the same
12 and 28 repositories that use Google ADK. No service met all three conditions. An earlier
form of the check, which did not require `--host`, matched one compose example in the vendor's
main repository that sets no `--host` and no key; the server binds loopback in that case, so
the check no longer flags it. Three of the 12 contain a Compose or deployment file for the
agent server, so the sample is thin on this surface. The pack states no measurement of the
rule's precision or recall.

---

## What this policy does not cover

- Whether `ApptainerWorkspace` publishes the server after the change in `v1.52.0`.
- A server started with no `--host` and a key set by a config file or another file; the check
  does not read the config file.
- Kubernetes Services and other ways to start the server.
- Authentication for servers other than the OpenHands agent server.
- Network controls outside the repo.

---

## Recommendations beyond the fix

Publish on loopback and set a key:

```yaml
services:
  agent-server:
    image: ghcr.io/openhands/agent-server:latest-python
    ports:
      - "127.0.0.1:8010:8000"
    environment:
      - OH_SESSION_API_KEYS_0
```

1. Publish the port on `127.0.0.1` unless another machine must reach it.
2. Set `OH_SESSION_API_KEYS_0` from a secret and send it as `X-Session-API-Key`.
3. Do not set `--host 0.0.0.0` without a session API key.
4. Review changes to Compose files and `docker run` commands in pull requests.

---

## Sources

- VulnCheck advisory "OpenHands Software Agent SDK < 1.52.0 Unauthenticated Sandbox Agent
  Server RCE":
  https://vulncheck.com/advisories/openhands-software-agent-sdk-unauthenticated-sandbox-agent-server-rce
  Retrieved 2026-11-09. Cited for the quoted description, the date, the severity and the
  credited finder, and nothing more.
- NVD JSON API record for CVE-2026-112346:
  https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-112346 Retrieved
  2026-11-09. Cited for the publication date and the affected-version statement, and nothing
  more.
- OpenHands/software-agent-sdk commit `7b66584` (pull request #5209) and release `v1.52.0`:
  https://github.com/OpenHands/software-agent-sdk/commit/7b66584 Retrieved 2026-11-09. Cited
  for what the change did, and nothing more.
- OpenHands/software-agent-sdk `openhands-agent-server/openhands/agent_server/__main__.py` at
  `v1.52.0`, retrieved 2026-11-09. Cited for the `--host` option, the bind default with and
  without a key, the explicit-host behavior, and the `_auth_enabled` check, and nothing more.
- OpenHands/software-agent-sdk `openhands-agent-server/openhands/agent_server/config.py` at
  `v1.52.0`, retrieved 2026-11-09. Cited for the `session_api_keys` description quoted above,
  the key variable names, and the absence of a host field, and nothing more.
- OpenHands/software-agent-sdk
  `openhands-agent-server/openhands/agent_server/docker/Dockerfile` at `v1.52.0`, retrieved
  2026-11-09. Cited for the image entrypoint and the absence of a
  default command, and nothing more.
- OpenHands/software-agent-sdk `openhands-workspace/openhands/workspace/docker/workspace.py` at
  `v1.52.0`, retrieved 2026-11-09. Cited for the arguments the Docker launcher passes after the
  image, and nothing more.
