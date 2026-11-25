---
policy_id: langchain_deep_agent_shell
category: langchain
topic: deep_agent_shell
rules:
  - id: LC-118
    severity: high
    confidence: 0.6
    scope: agent
    fix_type: config
references: [LLM06]
---

# Policy Rationale: Deep Agents With a Host-Shell Backend and No Approval on Execute

**Policy ID:** `langchain_deep_agent_shell`  
**File:** `langchain/deep_agent_shell.yaml`  
**Rules:** LC-118  
**Severities:** high  
**Fix types:** config  
**References:** LLM06 (Excessive Agency)

> **Verification status.** The deepagents behavior below was read on 2026-11-09 from raw
> source files of `github.com/langchain-ai/deepagents` at commit
> `e3a789816e2a38932360cae05ec53c133e79465e` (package version 0.7.34 in its
> `pyproject.toml`). The `HumanInTheLoopMiddleware` behavior was read the same day from
> `libs/langchain_v1/langchain/agents/middleware/human_in_the_loop.py` of
> `github.com/langchain-ai/langchain` at commit
> `82f2e3f995abbba1304128a48d2cfb268bc1c755`. The CVE record and the research write-up were
> read on 2026-11-09. The `references` entry is editorial: the engine does not model it.
> **Not verified, and therefore not assumed:** how releases of either package other than
> those commits behave; whether the TypeScript package `deepagents` (npm) has the same
> backend and approval option, which is why this policy covers Python and not that
> package; and whether any application other than the one in the CVE runs this pattern in
> production.

---

## What this policy covers

A Deep Agent is built by `create_deep_agent(...)` from the `deepagents` package. This policy
covers a call whose `backend=` is a `LocalShellBackend`, which runs shell commands on the
host, and whose `interrupt_on` does not ask for approval on the `execute` tool. The pack
loads with the LangChain category, because discovery stamps a Deep Agent with the LangChain
SDK.

This policy has one rule. **LC-118** is agent scope and fires once per `create_deep_agent`
call that matches. It reads the one file the call is in. It does not read the model, the
tools or the prompt.

---

## Why a host shell with no approval pause is a distinct concern in Deep Agents

Deep Agents add file and shell tools to an agent from its backend. The backend decides
whether a shell tool exists and where it runs. The approval decision is a separate setting,
`interrupt_on`, so a repository can pick the host shell and leave the approval setting
unset in the same call. LC-117 covers a LangChain `create_agent` that wires a shell tool; a
Deep Agent has no such tool in its tool list, so LC-117 does not see it. LC-115 covers a
LangGraph node. Neither rule reads a Deep Agent.

---

## Rule-by-rule defense

### LC-118 — Deep Agent with a host-shell backend and no approval on execute (Severity: high, Confidence: 0.6, Fix type: config)

**What we detect:** in a Python file that imports from `deepagents`, a `create_deep_agent(...)`
call bound to the package (`from deepagents import create_deep_agent`, an alias of it, or
`deepagents.create_deep_agent`). Gated by `agent_deep_agent_shell_execute_ungated`, with
`applies_to: langchain_deep_agent`. Two facts decide the match.

The backend resolves, in the same file, to a host shell when `backend=` is:

- a `LocalShellBackend(...)` call;
- a variable that is assigned exactly once in the call's function, or at module level, outside
  any `if`, `try`, loop or `match`, to a `LocalShellBackend(...)` call;
- a `CompositeBackend(...)` whose `default` (keyword or first positional argument) is one of
  those;
- a same-file subclass of `LocalShellBackend` that defines neither `execute` nor `aexecute`.

The `interrupt_on` argument is read as a literal dict and nothing else. It is ungated when it
is missing, `None`, `{}`, a dict with no `"execute"` key, or a dict that sets `"execute"` to
`False`.

What is not flagged:

- `"execute"` set to `True` or to a config in `interrupt_on`.
- A `LocalShellBackend` that appears solely in the `routes` of a `CompositeBackend`.
- A backend that is not a host shell, such as `StateBackend`, `StoreBackend`,
  `FilesystemBackend` or a sandbox.
- A subclass that overrides `execute` or `aexecute`.
- A backend built by a factory or a lambda, imported from another module, or assigned more
  than once or under a condition.
- A `middleware=` value that is not a literal list of calls, or a list that contains a
  `HumanInTheLoopMiddleware(...)` call.
- A file that registers a harness profile or sets `excluded_tools`.
- An `interrupt_on` that is a name, a call, or a dict with a `**` splat or a non-literal key.
- A call with `**kwargs` arguments.
- A call that is in a comment or a string.
- `async_create_deep_agent`, which the deepagents source read on 2026-11-09 does not define.

A match in a test path is reported and marked as test origin, like any finding in the pack.

**Why it is flaggable.** All behavior in this list is from the sources read on 2026-11-09.

- What `LocalShellBackend` does. Its module docstring says "It provides NO sandboxing or
  isolation - all operations run directly on the host machine with full system access." Its
  `execute` method uses `subprocess.run()` with `shell=True`, with the working directory set to
  the backend's `root_dir`.
- What the vendor recommends. The class docstring says to "Enable Human-in-the-Loop (HITL)
  middleware to review and approve ALL operations before execution. This is STRONGLY
  RECOMMENDED as your primary safeguard when using this backend."
- Where the vendor says it is appropriate and where it is not. The class docstring lists
  "Local development CLIs" and "Personal development environments where you trust the agent's
  code" as appropriate uses. It lists "Production environments (e.g., web servers, APIs,
  multi-tenant systems)" and "Processing untrusted user input or executing untrusted code" as
  inappropriate ones.
- When the `execute` tool exists. The `create_deep_agent` docstring says "The `execute` tool
  allows running shell commands if the backend implements SandboxBackendProtocol", and
  `LocalShellBackend` does. For a `CompositeBackend`, `supports_execution` "checks if the
  default backend supports execution", and `CompositeBackend.execute` says execution "is not
  path-routable" and delegates to the default backend. This is why a `LocalShellBackend`
  solely in `routes` is not flagged.
- What `interrupt_on` does. It is typed `dict[str, bool | InterruptOnConfig] | None` and the
  docstring calls it a "Mapping of tool names to interrupt configs" that pauses "agent
  execution at specified tool calls for human approval or modification". In
  `HumanInTheLoopMiddleware` "If a tool doesn't have an entry, it's auto-approved by default",
  and "`False` indicates that the tool is auto-approved." That is why a missing `interrupt_on`,
  a dict with no `execute` entry and `"execute": False` are all ungated.
- That the vendor itself leaves approval opt-in. The deepagents threat model says "HITL
  middleware (`interrupt_on={"execute": True}`) is available but opt-in, not default" and that
  `LocalShellBackend` "is **not the default**; it must be explicitly provided by the user".
- That file permissions are not a substitute. The filesystem middleware raises
  `NotImplementedError` with the message "Tool-level permissions for the execute tool are not
  implemented" for permissions on a backend that runs commands, unless each permission path
  is scoped to a composite route.
- Subagents. The `create_deep_agent` docstring says "Declarative `SubAgent` specs inherit the
  top-level `interrupt_on` config by default" and that a subagent's own `interrupt_on`
  "overrides the inherited top-level config". The `SubAgent` type in the source read has no
  `backend` key, so a declarative subagent works on the parent's backend.

A call that matches therefore gives the model a shell on the host and does not ask a person
before each command.

**Real-world consequence:** CVE-2026-77926 describes an application built this way. The CVE
text says it "allows authenticated non-admin users to run operating system commands through
the ChatBI common agent's ungated deepagents execute tool", reached through a chat endpoint
or an uploaded document. The agent construction at the commit the CVE cites
(`5d370adf3e695fc8b11137e5beeb01973cb46810`, `agent/common/enhanced_common_agent.py`) is a
`create_deep_agent(...)` call with `backend=LocalShellBackend(root_dir=str(workdir),
inherit_env=True, timeout=120)` and no `interrupt_on` argument. The research write-up says the
backend passes the server's environment to each command, and names the exposed secrets as
datasource credentials, database connection strings and API keys. The finders are Noy Pearl,
Michael Sromin and Ophir Dror. The pack's explanation states this class of exposure and does
not state a figure for how many repositories have it.

**Why severity is high:** The pack sets high and states no reasoning for it. The deepagents
threat model rates arbitrary shell command execution through `LocalShellBackend` as High
(its threat T3, marked Verified), and this policy cites it for that rating and nothing more.

**Fix type — config:** the fix is an edit to the arguments of the call. The pack's fix passes
`interrupt_on={"execute": True}` together with a checkpointer, or uses a backend that does
not run commands, or an isolated sandbox that extends `BaseSandbox`, and drops
`inherit_env=True` unless the commands need the server's environment variables. The
checkpointer is in the fix because the `HumanInTheLoopMiddleware` docstring says "The pause
is a LangGraph `interrupt`, so the agent needs a checkpointer".

**Confidence 0.6:** the pack's explanation states these limits of the check:

- It matches a local developer tool the same way as a deployed service, because it cannot
  tell them apart. The vendor lists local development CLIs as an appropriate use, so a match
  in a developer's own tool is a match on the pattern, not a statement that the tool is
  deployed to untrusted users.
- It reads `interrupt_on` as a literal dict in the call, treats an `execute` entry given as a
  config as a gate, and does not read its `when` predicate.
- It does not judge a `HumanInTheLoopMiddleware` in `middleware=`, or a `middleware=` value it
  cannot read in full, a harness profile or `excluded_tools`, an `interrupt_on` built at run
  time, a backend created in another module or returned by a factory, or a subclass that
  overrides `execute`.
- A subagent dict that sets its own `interrupt_on` overrides the parent's for that subagent,
  and that case is not checked. A call whose parent gates `execute` and whose subagent
  replaces `interrupt_on` without it is not flagged.
- It does not show that untrusted input can reach the agent. The pack has no Critical tier
  for a server-reachable agent: the engine's reachability data does not cover a Deep Agent,
  and the call in the CVE's application is returned from a method, not bound to a name.

An `InterruptOnConfig` can carry a `when` predicate that "returns `True` to interrupt or
`False` to auto-approve" per call, so an `execute` entry given as a config does not by
itself prove that each command pauses; the check treats it as a gate and does not read it.

On 2026-11-09 a prototype of the detector's logic was run over the Python files of public
repositories that mention `create_deep_agent` (215 repositories). It matched 3 calls in 2
repositories, a local agent harness and a tutorial about this backend, and both were judged
genuine matches of the pattern. The engine was then run on those two repositories, on a
repository whose call sets `interrupt_on={"execute": True}`, and on the Aix-DB file at the
commit the CVE cites: it matched the same 3 calls and the Aix-DB call, and did not match the
repository with the gate. Of the 37 repositories in that sample that instantiate or subclass
the deepagents `LocalShellBackend` in non-test Python, the engine flags a call outside test
paths in 2. In the other 35 it flags none outside test paths: in one the call sets
`interrupt_on={"execute": True}`; in one the `middleware=` list holds a name, which the rule
does not read; in two the matching call is in a test path; and in the remaining 31 no
`create_deep_agent` call has a `backend=` that the rule resolves to a host shell. The pack
states no measurement of the rule's precision or recall.

---

## What this policy does not cover

- A custom shell tool bound to a LangChain agent (LC-003 and LC-117 read tool shapes).
- A LangGraph node that shells out (LC-115).
- The TypeScript `deepagents` package.
- Whether the agent is reachable by untrusted input.
- Approval given through a `HumanInTheLoopMiddleware` in `middleware=`, a custom backend that
  guards `execute`, or a harness profile that removes the tool.
- A subagent that sets its own `interrupt_on` without `execute`.
- CVE-2026-109440 (LangAlpha), described below, which is not this pattern.

---

## Recommendations beyond the fix

Approval on the shell tool, with a checkpointer so a paused run can resume:

```python
agent = create_deep_agent(
    model=model,
    backend=LocalShellBackend(root_dir=workdir),
    interrupt_on={"execute": True},
    checkpointer=checkpointer,
)
```

1. Keep `LocalShellBackend` for a trusted local machine, as the vendor describes.
2. For a service that takes input from other people, use a backend that does not run
   commands, or an isolated sandbox that extends `BaseSandbox`, as the vendor recommends.
3. Do not set `inherit_env=True` unless the commands need the environment.
4. Review an `interrupt_on` dict for the `execute` key, and a subagent's own `interrupt_on`
   for the same key.

---

## Sources

- CVE-2026-77926, "Aix-DB 1.2.4 Authenticated RCE via ChatBI Common Agent Execute Tool", CNA
  VulnCheck, published 2026-10-20. Finders: Noy Pearl, Michael Sromin, Ophir Dror.
  https://www.vulncheck.com/advisories/aix-db-1.2.4-authenticated-rce-via-chatbi-common-agent-execute-tool
  Retrieved 2026-11-09. Cited for the statement that a deepagents `execute` tool without
  approval was reachable from a chat endpoint, and nothing more.
- Lasso Security vulnerability database entry for CVE-2026-77926.
  https://www.lasso.security/vulnerability-database/cve-2026-77926 Retrieved 2026-11-09.
  Cited for the root-cause description (the backend arguments and the absence of an
  `interrupt_on` argument), the environment and secrets exposure, and the remediation
  options, and nothing more.
- Aix-DB source at the commit the CVE cites.
  https://github.com/apconw/Aix-DB/blob/5d370adf3e695fc8b11137e5beeb01973cb46810/agent/common/enhanced_common_agent.py
  Retrieved 2026-11-09. Cited for the arguments of the `create_deep_agent` call at that
  commit, and nothing more.
- CVE-2026-109440, "LangAlpha through 2026.09.07 Indirect Prompt Injection RCE via Bash and
  ExecuteCode", CNA VulnCheck, published 2026-10-20.
  https://www.vulncheck.com/advisories/langalpha-through-2026.09.07-indirect-prompt-injection-rce-via-bash-and-executecode
  Retrieved 2026-11-09. Cited as background for the same missing-approval class on shell and
  code tools, and nothing more. It describes Bash and ExecuteCode tools in that application's
  workspace sandbox, which this rule does not read, so it is not an instance of this pattern.
- deepagents `LocalShellBackend`, `CompositeBackend`, `supports_execution`, `create_deep_agent`
  and `SubAgent`, and its threat model, at commit
  `e3a789816e2a38932360cae05ec53c133e79465e`:
  https://github.com/langchain-ai/deepagents/tree/e3a789816e2a38932360cae05ec53c133e79465e/libs/deepagents
  (`deepagents/backends/local_shell.py`, `deepagents/backends/composite.py`,
  `deepagents/middleware/filesystem.py`, `deepagents/middleware/subagents.py`,
  `deepagents/graph.py`, `THREAT_MODEL.md`). Retrieved 2026-11-09. Cited for the behavior of
  the backend, the `execute` tool, `interrupt_on`, subagent inheritance and the permissions
  limit, and the threat model's rating, and nothing more.
- langchain `HumanInTheLoopMiddleware` at commit
  `82f2e3f995abbba1304128a48d2cfb268bc1c755`:
  https://github.com/langchain-ai/langchain/blob/82f2e3f995abbba1304128a48d2cfb268bc1c755/libs/langchain_v1/langchain/agents/middleware/human_in_the_loop.py
  Retrieved 2026-11-09. Cited for how a missing entry and `False` are treated, the checkpointer
  requirement, and the `when` predicate, and nothing more.
