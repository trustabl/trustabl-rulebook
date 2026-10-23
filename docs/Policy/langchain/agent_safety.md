---
policy_id: langchain_agent_safety
category: langchain
topic: agent_safety
rules:
  - id: LC-101
    severity: high
    confidence: 0.85
    scope: agent
    fix_type: code
  - id: LC-102
    severity: low
    confidence: 0.6
    scope: agent
    fix_type: config
  - id: LC-103
    severity: medium
    confidence: 0.75
    scope: agent
    fix_type: code
  - id: LC-111
    severity: low
    confidence: 0.6
    scope: agent
    fix_type: config
  - id: LC-113
    severity: low
    confidence: 0.6
    scope: agent
    fix_type: config
  - id: LC-114
    severity: medium
    confidence: 0.6
    scope: agent
    fix_type: code
  - id: LC-116
    severity: high
    confidence: 0.6
    scope: agent
    fix_type: code
  - id: LC-117
    severity: high
    confidence: 0.7
    scope: agent
    fix_type: code
references: [LLM01, LLM02, LLM06, LLM10]
---

# Policy Rationale: LangChain Agent Safety

**Policy ID:** `langchain_agent_safety`
**File:** `langchain/agent_safety.yaml`
**Rules:** LC-101, LC-102, LC-103, LC-111, LC-113, LC-114, LC-116, LC-117
**Severities:** high, low, medium, low, low, medium, high, high
**Fix types:** code, config, code, config, config, code, code, code
**References:** LLM01 (Prompt Injection), LLM02 (Sensitive Information Disclosure), LLM06 (Excessive Agency), LLM10 (Unbounded Consumption)

---

## What this policy covers

Agent-scope rules for the constructor-shaped LangChain / LangGraph agents Trustabl
discovers: `create_react_agent` and `create_agent` (normalized class `ReactAgent` /
`CreateAgent`) and the legacy `AgentExecutor`. The rules cover the three highest-signal
agent-level risks: wiring a code-execution/shell built-in tool (LC-101), wiring a
raw HTTP `Requests*` built-in whose destination the model chooses (LC-103), and a
tool-calling loop with no explicit iteration cap (LC-102 / LC-111). LC-116 flags a
LangGraph graph or agent whose checkpointer is in-memory (`MemorySaver` /
`InMemorySaver`) while it is run from a server entrypoint, so its threads do not
survive a restart, a deploy, or a second worker. LC-117 narrows LC-101 to LangChain
v1 `create_agent`: when that agent wires one of the same code-execution or shell
built-ins, it checks that the two pieces a human-approval pause needs are present,
a non-empty `middleware=` list and a `checkpointer=`.

The raw `StateGraph` graph is in scope too: LC-101 and LC-103 apply to its tool set,
and LC-114 and LC-116 check how it is checkpointed.

---

## Why agent safety is a distinct concern in LangChain

An agent's entire capability surface is a list literal handed to a constructor.
`create_react_agent(model, [PythonREPLTool()])` grants arbitrary code execution
in one positional argument, with no keyword naming the risk, no
`allow_dangerous_*` flag to type, and nothing at the call site that reads
differently from wiring a calculator. The security boundary and an ordinary
argument list are the same object, which is why these rules attach to the
**agent** rather than to a tool: the defect is not what any single tool does, it
is what the assembled set adds up to.

That surface is also assembled through several shapes — `create_react_agent`,
`create_agent`, and the legacy `AgentExecutor` — that differ in how they bound a
run. `AgentExecutor` takes `max_iterations`; the graph-based constructors
enforce a recursion limit of their own instead. So "is this agent bounded?" has
no single answer in this ecosystem, and a reviewer who has internalized one
constructor's answer will read the other as safe. LC-102 and LC-111 deliberately
scope to `AgentExecutor` for that reason, and the gap is named below rather than
papered over.

The two risks are also unusually asymmetric for one policy file. LC-101 is a
capability that cannot be tuned — a REPL on the tool surface is either there or
not — while the iteration rules flag a missing *explicit* bound behind a
framework default that already prevents a true runaway. High and low severity
sit together here not by inconsistency but because a code-execution grant and an
unsized loop fail in different orders of magnitude.

---

## Rule-by-rule defense

### LC-101 — Agent wires a code-execution or shell built-in tool (Severity: high, Confidence: 0.85, Fix type: code)

**What we detect:** a LangChain agent (`ReactAgent` / `CreateAgent` / `AgentExecutor`)
whose resolved tool set includes `PythonREPLTool`, `PythonAstREPLTool`, or
`ShellTool` (predicate `agent_uses_hosted_tool_class`). Discovery recognizes these
built-ins when they appear in the agent's tool list — including the common
positional form, `create_react_agent(model, [PythonREPLTool()])` — and records them
as hosted-tool edges.

**Why it is flaggable:** these built-ins execute code or shell commands chosen by
the model. Once one is on the tool surface, a prompt injection or a confused model
has a direct path to arbitrary execution in the agent process. PythonREPLTool and
ShellTool have been the concrete vector in multiple published LangChain RCE
advisories — this is excessive agency (LLM06) in its most literal form: the agent is
granted the ability to run anything.

**Real-world consequence:** an agent built to "answer questions about a CSV" is
given a `PythonREPLTool`; a crafted question makes it run `__import__('os').system(...)`
and read the deployment's secrets.

**Severity high:** the capability is the defect; the fix is to remove the built-in or
sandbox-and-gate it. `PythonREPLTool` / `PythonAstREPLTool` run model-generated
Python via an in-process `exec()`/eval in the agent's own interpreter, and
`ShellTool` hands the model a host subprocess shell — no container, no allowlist,
no approval gate anywhere in the tool itself. It is kept off critical for the same
calibration reason as CREW-102 (CrewAI's `unsafe` host execution, also high): the
engine reserves that tier, and the rule still requires that the agent actually be
driven to the tool by model-influenced input — an agent exercised only on trusted,
non-injectable input never reaches it. **Confidence 0.85:** a few agents legitimately
need a REPL and have sandboxed it out of band, which the class-name match cannot
see.

### LC-102 — AgentExecutor has no explicit max_iterations limit (Severity: low, Confidence: 0.6, Fix type: config)

**What we detect:** an `AgentExecutor` with no effective `max_iterations` kwarg
(predicate `agent_kwarg_missing`).

**Why it is flaggable:** with no explicit `max_iterations`, the executor falls back
to LangChain's default of 15 — a generic ceiling, not one sized to this task. A
model that loops or oscillates still runs up to 15 tool round-trips (LLM10,
Unbounded Consumption), a cost the workflow may not tolerate, and the implicit cap
can shift between versions; when the looped tools have side effects it is a
correctness concern too.

**Severity low:** the framework default (15) already prevents a true runaway, so
this flags a missing *explicit, task-sized* cap — a hygiene nudge, not a defect.
**Confidence 0.6:** an executor relying on the default, wrapped by an external
timeout, or guarded by a custom loop is over-flagged.

### LC-103 — Agent wires a raw HTTP Requests built-in tool (Severity: medium, Confidence: 0.75, Fix type: code)

**What we detect:** a LangChain agent (`ReactAgent` / `CreateAgent` / `AgentExecutor` /
`StateGraph`) whose resolved tool set includes one of `langchain_community`'s raw HTTP
built-ins — `RequestsGetTool`, `RequestsPostTool`, `RequestsPutTool`,
`RequestsPatchTool`, `RequestsDeleteTool` (predicate `agent_uses_hosted_tool_class`).
Discovery records these as hosted-tool edges when the class is instantiated directly
in the agent's tool list. This is the *agent-scope* companion to the tool-scope SSRF
rules: LC-005 / LC-013 observe a hand-rolled `requests.get(url)` inside a tool body,
whereas LC-103 fires on the framework's own arbitrary-URL tool being handed to the
agent. Neither implies the other, and a repo can legitimately trip both.

**Why it is flaggable:** the HTTP method is fixed by the class, but the destination is
not — the model supplies the URL. That is a model-directed outbound HTTP capability
(LLM06, Excessive Agency), and the agent host's network position, not the tool, decides
what it can reach. LangChain gates this family behind `allow_dangerous_requests=True`
precisely because wiring it hands the model an unconstrained fetch.

**Real-world consequence:** a support agent given `RequestsGetTool` to read public
documentation is asked, via text it already retrieved, to fetch
`http://169.254.169.254/latest/meta-data/iam/security-credentials/` — instance
credentials come back inside the model's context (LLM02). The write-method variants
raise the ceiling from read to mutate: `RequestsDeleteTool` pointed at an internal
admin endpoint the host can reach issues a real DELETE. In both cases the response body
returns as conversation text, so a hostile page can attempt a second-order injection
(LLM01). None of this is guaranteed — it depends on what the host can actually reach —
but the wiring is what makes it reachable at all.

**Why severity is medium and not high:** the rule observes a *capability being wired*,
not a demonstrated unguarded request. `allow_dangerous_requests=True` means the author
already opted in knowingly, and the destination may be constrained out of band by a
proxy, an egress policy, or a `TextRequestsWrapper` pinned to one base URL. That is
weaker evidence than LC-005's high, which observes an actual dynamic-URL call flowing
from a tool parameter. Medium also matches how the pack rates the same shape in sibling
SDKs — CREW-107 (0.70), PYD-103 (0.75), VAI-009 (0.70).

**Fix type — code:** the remediation is to replace the generic built-in with a
purpose-built tool that pins its destination, which means writing tool and agent source.
Egress controls help, but removing the unconstrained-fetch capability is a code change.

**Confidence 0.75:** the gap is what a class-name match cannot see in either direction.
*False positives:* an agent whose egress is already proxied or host-allow-listed, a
`TextRequestsWrapper` pinned to a single vetted base URL, or a fixture/dev-only agent —
all still fire. *False negatives:* `RequestsToolkit`, which builds the same tools via
`get_tools()` rather than putting a class in the list; the
`Tool(func=requests_wrapper.get)` wrapper shape; and custom `BaseTool` subclasses that
hand-roll the same capability — none are in the closed class list. It sits above
CREW-107/VAI-009's 0.70 because these five classes have exactly one purpose and the
match is unambiguous, and below LC-101's 0.85 because outbound HTTP has far more
legitimate, adequately-constrained uses than an arbitrary-code REPL.

### LC-111 — TypeScript AgentExecutor has no explicit maxIterations limit (Severity: low, Confidence: 0.6, Fix type: config)

**What we detect:** a TS `AgentExecutor` with no effective `maxIterations` kwarg.

**Why it is flaggable / consequence:** identical to LC-102 in LangChain.js.

**Severity low / Confidence 0.6:** same profile as LC-102.

### LC-113 — AgentExecutor has no explicit max_execution_time limit (Severity: low, Confidence: 0.6, Fix type: config)

**What we detect:**
A Python `AgentExecutor` with no effective `max_execution_time` kwarg (absent or an
explicit `None`; predicate `agent_kwarg_missing`). It is the wall-clock companion to
LC-102 and reads the same constructor.

**Why it is flaggable:**
`max_iterations` (LC-102) counts tool round-trips, not seconds. One iteration that
blocks on a slow tool or a stalled model call is not counted, so the run can hang or
stretch well past any latency budget while holding tools and credentials live
(LLM10, Unbounded Consumption). `max_execution_time` is the executor's native
wall-clock cap.

**Real-world consequence:**
A support agent's lookup tool waits on an unresponsive internal API; the executor
sits inside iteration 2 of 15 for minutes, the request thread is pinned, and the
front end times out while the agent keeps running.

**Why severity is low and not medium:**
The impact is latency, availability and cost, bounded by external supervision; the
rule grants nothing new to the model and is a hygiene nudge that mirrors LC-102's
low.

**Fix type — config:**
One constructor kwarg, no tool source changes.

**Confidence 0.6:**
**False positives:** an executor wrapped by an external timeout, or whose tools each
carry a timeout that already bounds every step, is over-flagged, as is
`AgentExecutor(**cfg)` (the predicate does not consult the opaque flag). **False
negatives:** the check is presence-only, so an enormous value passes.
`create_react_agent` / `create_agent` graphs are out of scope because they are
bounded by the graph's recursion limit rather than this kwarg. The TypeScript
`AgentExecutor` is deliberately not covered: no `maxExecutionTime` option could be
verified for LangChain.js, and the rule will not advise an option that may not exist.
### LC-114 — LangGraph StateGraph is compiled with no checkpointer (Severity: medium, Confidence: 0.6, Fix type: code)

**What we detect:** a `StateGraph(...)` / `MessageGraph(...)` builder whose
`.compile(...)` call discovery resolved through a named builder variable
(`agent_kwargs_observed: true`), that sets no `checkpointer` (`agent_kwarg_missing`,
which also treats an explicit `checkpointer=None` as missing), in a repo that ships
no `langgraph.json` (`repo_langgraph_platform_config_present: false`). A bare
`builder.compile()` counts as resolved-and-empty; a chained
`StateGraph(...).compile()`, a `compile(**cfg)`, and a graph whose compiled result is
passed to another builder's `add_node` (a subgraph) are all treated as *unobserved*
and stay silent.

**Why it is flaggable:** a checkpointer is what persists graph state between steps.
Without one the run lives only in process memory: a crash, restart or deploy
discards completed steps and tool results, a retry re-executes side-effecting nodes
from the start, and `interrupt()` / `interrupt_before` cannot resume because there
is no saved state to resume from — so a graph that appears to have a human-approval
gate cannot actually pause for one.

**Real-world consequence:** a graph that sends an email in node 3 crashes in node 5;
the supervisor restarts the worker and the run replays from node 1, sending the
email twice. Or an `interrupt()` approval gate raises at runtime because the graph
was compiled without a checkpointer, and the team "fixes" it by deleting the gate.

**Why severity is medium and not high:** the failure needs a crash, restart or
interrupt to bite, and many short-lived graphs legitimately never need to resume.
It is a durability and approval-gate prerequisite rather than a direct exposure.
**Fix type — code:** the checkpointer is passed in the `.compile(...)` call.

**Confidence 0.6:** the gap covers (a) a subgraph compiled in another file, which
inherits its parent's checkpointer and is intentionally compiled bare; (b) a
Platform deployment whose `langgraph.json` lives outside the scanned tree;
(c) a checkpointer attached by a wrapper that returns the compiled graph. The
`agent_kwargs_observed` and `langgraph.json` clauses exist precisely to cut the two
largest false-positive classes: unresolved call sites and Platform repos.

### LC-116 — LangGraph graph with an in-memory checkpointer is run from a server entrypoint (Severity: high, Confidence: 0.6, Fix type: code)

**What we detect:** a LangGraph `StateGraph` or a `create_react_agent` /
`create_agent` agent that meets all three predicates:
- `agent_checkpointer_in_memory: true` — its checkpointer is `MemorySaver` /
  `InMemorySaver`;
- `agent_server_reachable: true` — it is run from a server entrypoint: a FastAPI or
  Flask route, or a Celery or Dramatiq task;
- `repo_langgraph_platform_config_present: false` — the repo ships no
  `langgraph.json`.

**Why it is flaggable:** an in-memory saver keeps every thread's state in a dict
inside one process. Behind a server, a restart, a deploy, a crash, or a second
worker loses all in-flight threads, their completed steps, and any `interrupt()`
pause awaiting human approval, and a retry re-executes side-effecting nodes from
the start. Because a checkpointer *is* configured, the graph looks durable when it
is not — a reviewer asking "does this graph have a checkpointer?" gets a yes.

**Real-world consequence:** an approval workflow behind a FastAPI route pauses at
`interrupt()` until a manager approves a refund. A deploy restarts the process
before the approval arrives; the thread is gone, the approval has nothing to resume,
and the resubmitted request re-runs the nodes that had already run. Or the service
scales to a second worker, and a resume request lands on the process that never
held the thread.

**Why severity is high and not medium (LC-114):** the pack rates LC-116 high where
LC-114 (no checkpointer) is medium, and the configured checkpointer hides the loss
from review.

**Fix type — code:** the saver is chosen in the `.compile(...)` call (the same
`checkpointer=` applies to `create_react_agent`): pass a durable one in production,
e.g. `builder.compile(checkpointer=PostgresSaver(...))`, `AsyncPostgresSaver` or
`RedisSaver`, keep `MemorySaver` for tests, and invoke with
`config={"configurable": {"thread_id": ...}}` so each conversation resumes from its
own persisted thread.

**Confidence 0.6:** the rule's limits are stated in the pack:
- reachability follows one hop per edge — the entrypoint itself, a same-file helper
  it calls, or an imported helper it calls — so a graph run through a helper of a
  helper is not seen;
- a graph built or compiled inside a factory function is not tracked;
- a saver chosen at runtime (an environment variable, a config object) is not
  resolved, and the rule stays silent;
- a subgraph is reported only when it is itself invoked from a server path;
- test paths are ignored;
- the rule is silent when the repo ships a `langgraph.json` (LangGraph Platform
  injects its own checkpointer).

Recall on real server code is unmeasured.

**Relationship to LC-114:** LC-114 requires the `checkpointer` kwarg to be missing
(`agent_kwarg_missing`); LC-116 requires an in-memory checkpointer to be present
(`agent_checkpointer_in_memory`). The two cannot both hold for the same graph, so
it draws at most one of them: no checkpointer is LC-114 (medium), an in-memory one
reached from a server entrypoint is LC-116 (high). An in-memory checkpointer that no
server entrypoint reaches draws neither. Both stay silent when the repo ships a
`langgraph.json`.

### LC-117 — LangChain privileged create_agent lacks human-approval prerequisites (Severity: high, Confidence: 0.7, Fix type: code)

**What we detect:** a Python LangChain v1 `create_agent(...)` agent (normalized class
`CreateAgent`, predicate `agent_class`) that meets both conditions:
- `agent_uses_hosted_tool_class` — its resolved tool set includes `PythonREPLTool`,
  `PythonAstREPLTool`, or `ShellTool`, the same closed list as LC-101;
- at least one of:
  - `agent_kwarg_list_empty: [middleware]` — `middleware=` is absent or an empty list
    literal `[]`;
  - `agent_kwarg_missing: [checkpointer]` — `checkpointer=` is absent or explicitly
    `None`.

The rule never applies to `create_react_agent`, `AgentExecutor`, a raw `StateGraph`,
or LangChain.js.

**Why it is flaggable:** in LangChain v1, a human-approval pause before a tool runs
comes from middleware. `HumanInTheLoopMiddleware(interrupt_on={...})` stops the run
before the named tool executes and raises an interrupt that the caller resumes with
a decision. That pause depends on two parts of the constructor. The middleware list
must exist for anything to intercept the tool call. A checkpointer must exist for
the paused run to be saved somewhere and resumed later: an interrupt with no saved
state has nothing to come back to. An agent that can run model-chosen Python or
shell commands and has neither part has no point where a person can approve a call
before it runs (LLM06, Excessive Agency). Each call goes straight from the model's
decision to execution.

**Real-world consequence:**
- A DevOps assistant built with `create_agent(model, tools=[ShellTool()])` is asked
  to "clean up disk space on the build host". The model picks `rm -rf` on a path it
  inferred from a log line, and nothing pauses the call for an operator to read
  first.
- A data agent with a `PythonREPLTool` summarizes a CSV that a user uploaded. A cell
  in the file contains instructions to `import os` and print the environment. The
  model follows them (LLM01), and the deployment's API keys land in the model's
  reply (LLM02). With an approval pause in place, the reviewer would have seen
  `os.environ` in the pending call.
- A team adds `HumanInTheLoopMiddleware` but no checkpointer. The interrupt cannot
  persist, the approval step fails at runtime, and the middleware gets removed to
  make the agent work again. LC-117 fires on both versions of that agent.

**Why severity is high and not medium:** the agent already holds an arbitrary
execution capability, and LC-117 adds that nothing in the agent's structure can
stop a call before it runs. It matches LC-101's high and does not go above it.
The harm comes from the same REPL or shell tool; the missing approval point only
removes the mitigation a reviewer would look for first. It is not critical for the
same reason LC-101 is not: the engine reserves that tier, and the harm still needs
the model to be steered to the tool, by a confused plan or by injected input.

**Fix type — code:** the fix is more than adding a constructor kwarg. The
middleware has to name the privileged tool in `interrupt_on`, the agent needs a
durable checkpointer, and the calling code has to pass a `thread_id`, detect the
interrupt, collect a decision, and resume the run with
`Command(resume={"decisions": [...]})`. That approval loop is application code.

**Confidence 0.7:** the rule checks that the structure exists, not what it does.
- *False positives:*
  - `create_agent(**cfg)`, where the middleware and checkpointer are inside the
    unpacked dict, which the predicates cannot see;
  - an agent deployed on LangGraph Platform, which supplies its own checkpointer.
    LC-117 has no `langgraph.json` exemption, unlike LC-114 and LC-116;
  - a REPL that is already sandboxed and gated out of band, the same gap as LC-101.
- *False negatives:*
  - any non-empty middleware list satisfies the first condition, including one with
    only `SummarizationMiddleware` or another middleware that never pauses;
  - `middleware=None` is not treated as empty, so it passes;
  - a middleware list passed as a variable (`middleware=MIDDLEWARE`) passes, because
    the predicate cannot read its contents;
  - an `interrupt_on` that names a different tool from the REPL or shell passes;
  - a throwaway `MemorySaver()` in production satisfies the checkpointer condition.
    LC-116 catches that case only when a server entrypoint reaches the agent.

The confidence sits below LC-101's 0.85 because LC-117 adds an inference from
missing kwargs to a missing approval point. That inference fails for the
unpacked-config and Platform cases above, which LC-101 does not depend on.

**Relationship to LC-101:** every agent that fires LC-117 also fires LC-101, because
both match the same tool classes and LC-117 only adds conditions. The two findings
say different things. LC-101 says the agent can execute arbitrary code; LC-117 says
nothing is in place to pause it when it does. Adding the middleware and a
checkpointer clears LC-117 only. LC-101 stays until the built-in is removed or
sandboxed, because an approval pause reduces the risk but does not remove the
capability.

---

## What this policy does not cover

v1 `create_agent` middleware quality (LC-117 checks only that a middleware list
and a checkpointer are present) and whether a code-execution tool is *actually*
sandboxed out of band. The iteration rules check `AgentExecutor` only —
`create_react_agent` / `create_agent` enforce their own recursion limit differently
and are out of scope here.
- For LC-103: only direct wiring of the five known `Requests*` classes. It does not
  see `RequestsToolkit` (same capability, assembled through `get_tools()`), the
  `Tool(func=requests_wrapper.get)` wrapper form, a custom `BaseTool` subclass that
  hand-rolls an arbitrary fetch, or any other library's HTTP tool. It also cannot tell
  whether an allow-list, an egress proxy, or a pinned base URL is already enforcing
  the destination, so a properly constrained deployment still fires.
- For LC-113: wall-clock limits enforced outside the executor, and the TypeScript
  `AgentExecutor` (no verified equivalent option, so no rule ships).
- For LC-114: a graph whose `compile(...)` is chained onto the constructor, built
  with `**` unpacking, or compiled in a different file than its builder is never
  linked to its kwargs, so the rule stays silent rather than guess. A subgraph
  compiled in another file than the parent that mounts it cannot be recognised as a
  subgraph and may be flagged. A `checkpointer=` pointing at a throwaway
  `MemorySaver()` in production satisfies LC-114 without giving real durability;
  LC-116 reports it only when a server entrypoint reaches the graph.
- For LC-116: a graph reached through more than one helper hop, built or compiled
  inside a factory function, or given a saver chosen at runtime is not seen, and
  recall on real server code is unmeasured.
- For LC-117: only Python `create_agent`. It does not check which tools
  `interrupt_on` names, whether any middleware in the list actually pauses, whether
  the checkpointer is durable, or whether the calling code ever resumes an
  interrupt. `middleware=None`, a middleware list held in a variable, and
  `create_agent(**cfg)` are not resolved. The first two pass silently; the third
  fires. There is no LangGraph Platform exemption, and `create_react_agent`,
  `AgentExecutor`, `StateGraph` with a REPL node, and LangChain.js `createAgent` are
  out of scope. A custom `@tool` that shells out is not one of the three built-in
  classes, so it is not seen.

---

## Recommendations beyond the fix

Remove REPL/shell built-ins from production agents; if code execution is required,
run it in an isolated sandbox and gate it behind a human-in-the-loop approval (a
LangGraph `interrupt_before` breakpoint or a tool-approval middleware); a graph that
serves requests needs a durable checkpointer for that pause to survive a restart
(LC-114, LC-116). Set `max_iterations` / `maxIterations` (and a `max_execution_time`)
sized to the task, and set `handle_parsing_errors` so a malformed model step surfaces
rather than retrying forever.

When a `create_agent` agent must keep a shell or REPL tool (LC-117), pause that tool
for approval and save the paused run in a durable checkpointer:

```python
from langchain.agents import create_agent
from langchain.agents.middleware import HumanInTheLoopMiddleware
from langchain_community.tools import ShellTool
from langgraph.checkpoint.postgres import PostgresSaver
from langgraph.types import Command


def run_with_approval(db_uri: str, thread_id: str, request: str, review) -> dict:
    """Run a shell-capable agent; every shell call waits for a reviewer's decision."""
    shell = ShellTool()
    with PostgresSaver.from_conn_string(db_uri) as checkpointer:
        checkpointer.setup()  # creates the checkpoint tables on first use
        agent = create_agent(
            model="anthropic:claude-sonnet-5-5",
            tools=[shell],
            middleware=[
                HumanInTheLoopMiddleware(
                    # Key by the tool's own name, so a renamed tool cannot slip past.
                    interrupt_on={shell.name: {"allowed_decisions": ["approve", "reject"]}},
                ),
            ],
            checkpointer=checkpointer,
        )
        config = {"configurable": {"thread_id": thread_id}}
        result = agent.invoke(
            {"messages": [{"role": "user", "content": request}]},
            config=config,
            version="v2",
        )
        while result.interrupts:
            # review() shows the pending tool calls to a person and returns one decision
            # per call, in order: {"type": "approve"} or {"type": "reject", "message": "..."}.
            decisions = review([interrupt.value for interrupt in result.interrupts])
            result = agent.invoke(
                Command(resume={"decisions": decisions}),
                config=config,  # same thread_id, so the paused run resumes
                version="v2",
            )
        return result.value
```

1. Name every privileged tool in `interrupt_on` by its `name` attribute, and add a
   test that fails when a tool on the agent is privileged but not listed.
2. Use `MemorySaver` / `InMemorySaver` only in tests. A paused run in an in-memory
   saver is lost on restart (LC-116).
3. Log each decision with the `thread_id`, the reviewer, and the exact pending
   arguments, so an approved command can be audited later.
4. Keep the shell or REPL inside a container or sandbox anyway. Approval reduces the
   risk of a bad call; it does not limit what an approved call can do (LC-101).

For outbound HTTP, prefer a purpose-built tool that pins the base URL and takes only a
path or query from the model over a generic `Requests*` built-in. Where open fetching is
genuinely required, allow-list the permitted hosts, reject private and link-local ranges,
re-validate the destination after every redirect rather than trusting the first check,
and route the agent's egress through a proxy that refuses internal addresses. Treat every
response body as untrusted input: keep it out of the system prompt and do not let it
widen the agent's tool permissions.
