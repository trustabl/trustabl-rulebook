---
policy_id: mcp_param_flow_sinks
category: mcp
topic: param_flow_sinks
rules:
  - id: MCP-215
    severity: high
    confidence: 0.5
    scope: tool
    fix_type: code
  - id: MCP-216
    severity: critical
    confidence: 0.55
    scope: tool
    fix_type: code
  - id: MCP-217
    severity: high
    confidence: 0.4
    scope: tool
    fix_type: code
  - id: MCP-218
    severity: high
    confidence: 0.35
    scope: tool
    fix_type: code
  - id: MCP-219
    severity: high
    confidence: 0.45
    scope: tool
    fix_type: code
  - id: MCP-220
    severity: critical
    confidence: 0.55
    scope: tool
    fix_type: code
references: [LLM02, LLM05, LLM06]
---

# Policy Rationale: MCP Tool Parameters That Reach a Dangerous Call

**Policy ID:** `mcp_param_flow_sinks`  
**File:** `mcp/param_flow_sinks.yaml`  
**Rules:** MCP-215, MCP-216, MCP-217, MCP-218, MCP-219, MCP-220  
**Severities:** high, critical, high, high, high, critical  
**Fix types:** code, code, code, code, code, code  
**References:** LLM02 (Sensitive Information Disclosure), LLM05 (Improper Output Handling), LLM06 (Excessive Agency)

> **Verification status.** The arXiv abstract for 2610.22301 was read through the arXiv API, the
> GitHub advisories GHSA-w7x8-q2gp-5cgg and GHSA-5324-3w58-qpp2 were read through the GitHub
> advisories API, all on 2026-11-27. GitHub advisory GHSA-v867-6qx2-gwmg (CVE-2026-118378), the
> source of MCP-218, was read through the same API on 2026-11-27. **Not read:** the full text of the arXiv paper, so the
> pack cites its abstract alone. **Not found, and therefore not assumed:** a true positive in
> public code. A scan of the Python MCP tools in `modelcontextprotocol/servers` (18 tools,
> commit `c799c85`) and of other cached repositories on 2026-11-27 produced no finding from
> these rules, because those tools pass their parameters to helper functions, which the check
> does not follow; the fixture is the sole place the rules are seen to fire. Precision and
> recall on real code are not measured. The advisories describe other products and library
> releases, not tools written with the MCP SDK.

---

## What this policy covers

An MCP tool receives its arguments from a model. This policy has six rules over one
predicate, `tool_source_reaches_sink`, which reads the flows that the one-function taint pass
records on the tool (`taint_flows` in the scan output). The sole source is a parameter of the
tool function. A flow is a parameter value that reaches an argument of a sink call in the same
function, through assignments, f-strings or template literals, concatenation, `format`, `join`
and a fixed list of string and path wrappers.

- **MCP-215** (Python) and **MCP-219** (TypeScript): the sink is a subprocess call, a
  GitPython call, or a file or path call. MCP-215 reads `subprocess.*`, `os.system`,
  `os.popen`, `os.spawn*`, the `os` and `shutil` file calls, `open`, `Path(...)` methods and
  `repo.git.*`. MCP-219 reads the `child_process` calls and the `fs` calls.
- **MCP-216** (Python) and **MCP-220** (TypeScript): the sink is `eval`, `exec` or `compile`
  in Python, and `eval`, `new Function` or a `vm` run call in TypeScript.
- **MCP-217** (Python): the sink is the `user_id`, `agent_id`, `run_id`, `app_id` or
  `namespace` argument of a call on a mem0 memory client, and the value must be built by
  joining the parameter with other text.

- **MCP-218** (Python): the sink is the statement argument of `execute`, `executemany`,
  `executescript`, `exec_driver_sql` or `sqlalchemy.text`; a value passed in the bound
  parameters argument alone is not a flow, and a receiver whose name contains sandbox, interpreter,
  kernel, executor or runner is not read as a database.

Each rule fires once per tool, at the sink line of the first matching flow, and the
explanation names the parameter and its line. MCP-215 overlaps CSDK-004, which checks a
path-named parameter against `open`, `Path`, `shutil.*` and `os.*` for Claude SDK tools; MCP-215
adds the subprocess and git sinks and any parameter name, for MCP tools.

The sink, source and propagation tables are in `internal/analysis/taint_sinks.go` and
`taint_py.go`; the rule text lists what ends a flow.

---

## Why a parameter reaching these calls is flaggable

The arXiv paper "My Credentials, Please: Detecting Filesystem Capability Laundering in MCP
Servers at Scale" (arXiv:2610.22301) studies a vulnerability class in which "attacker-steered
arguments cause a tool to access sensitive host files outside its declared contract and
deployment scope". Its abstract reports that 787 of 4,806 triaged servers (16.4%) exhibit
filesystem capabilities despite non-filesystem functional classifications, and names two CVEs
in Anthropic's Git MCP Server. The pack cites it for the class of attacker-steered arguments
reaching host file access, and nothing more. It does not cite the paper for the subprocess
sinks or for any rate.

GitHub advisory GHSA-w7x8-q2gp-5cgg (CVE-2026-73487) describes Flowise nodes that run
LLM-generated Python after a regex blocklist, where prompt injection through an
unauthenticated API reached code execution. The pack cites it for the class of model-generated
code reaching an execution call, and nothing more.

GitHub advisory GHSA-5324-3w58-qpp2 (CVE-2026-116575) describes a mem0 session scope key built
by joining `user_id`, `agent_id` and `run_id` with unescaped `&` and `=`, so that a caller who
set just `run_id` produced another tenant's scope string. The pack cites it for the join
mechanism and nothing more. The pack states no further reasoning for treating a joined scope
key as a signal.

---

## Rule-by-rule defense

### MCP-215 — MCP tool parameter reaches a subprocess, git or file call without normalization (Severity: high, Confidence: 0.5, Fix type: code)

**What we detect:** a Python `mcp_tool` with a flow from a parameter to a `shell`, `path_io` or
`file_write` sink. A `.resolve()` or `realpath` call on the value, `shlex.quote`, a cast to
`int`, `float` or `bool`, a `Literal` or `Enum` annotation, and an `if` test on the parameter
that raises or returns end the flow.

**Why it is flaggable:** the model chooses the value, so a path or an argument it supplies
reaches the call.

**Real-world consequence:** a path outside the intended directory is read or written, or an
unintended command argument is run, with the permissions of the server process.

**Severity:** the pack sets high and states no reasoning for it.

**Fix type — code:** resolve the path and check it against one root, pass a fixed executable
with an argument list, and check each value against an allowlist.

**Confidence 0.5:** The pack sets 0.5. The pack's explanation states these limits: just the
tool's own function is read; a helper that makes the call is not followed; attributes, module
variables, closures and dict or list elements are not followed; a resolved path is not
compared with a root by the check; a custom validator counts as an `if` test that raises
or returns; a wrapper outside the function is not seen; and a tool that exists to run commands
or read files is flagged.

### MCP-216 — MCP tool parameter reaches eval, exec or compile (Severity: critical, Confidence: 0.55, Fix type: code)

**What we detect:** a Python `mcp_tool` with a flow from a parameter to `eval`, `exec` or
`compile`.

**Why it is flaggable:** text the model wrote, or text placed in content it read, runs as
Python in the server process.

**Real-world consequence:** arbitrary code execution with the permissions of the server.

**Severity:** the pack sets critical and states no reasoning for it.

**Fix type — code:** parse data with `ast.literal_eval` or `json.loads`, map a fixed set of
operation names to functions, or run the code in a sandbox.

**Confidence 0.55:** The pack sets 0.55. The pack's explanation states these limits: just the
tool's own function is read; a helper that calls `eval` is not followed; a cast, an annotation
and an `if` test end the flow, and a blocklist test counts as a guard; `ast.literal_eval` and
`json.loads` are not sinks; and attribute and container flows are not followed.

### MCP-217 — MCP tool builds a memory scope key from parameters by concatenation (Severity: high, Confidence: 0.4, Fix type: code)

**What we detect:** a Python `mcp_tool` that joins a parameter with other text and passes the
result as a scope argument to a mem0 client call. A parameter passed alone is not flagged.

**Why it is flaggable:** a joined key is ambiguous when a value can carry the delimiter.

**Real-world consequence:** one caller's memory scope can equal another's.

**Severity:** the pack sets high and states no reasoning for it.

**Fix type — code:** keep identifiers in separate arguments, or validate each against a format
and reject the delimiter.

**Confidence 0.4:** The pack sets 0.4. The pack's explanation states these limits: a client is
recognized by a same-file binding to a mem0 constructor or by a name containing `mem0` or
`memory`; a bare parameter is not flagged; a key built in a helper is not seen; and the check
does not know the delimiter rules of the library version, so a fixed version is flagged too.

### MCP-218 — MCP tool parameter is built into SQL text passed to execute (Severity: high, Confidence: 0.35, Fix type: code)

**What we detect:** a Python `mcp_tool` with a flow from a parameter to the statement argument
of `execute` and the related calls. A bound value, a cast, a `Literal` or `Enum` annotation and
an `if` test on the parameter that raises or returns end the flow.

**Why it is flaggable:** GitHub advisory GHSA-v867-6qx2-gwmg describes a crafted `table_name`
given to a `describe_table` MCP tool that closed a quoted PRAGMA argument and ran stacked
statements, bypassing the mode that blocks writes and the write approval.

**Real-world consequence:** SQL the model or an attacker chose runs with the permissions of the
database connection the tool holds.

**Severity:** the pack sets high and states no reasoning for it.

**Fix type — code:** bind values, keep the statement text fixed, and check an identifier
against an allowlist before it is placed in the statement.

**Confidence 0.35:** The pack sets 0.35. The pack's explanation states these limits: just the
tool's own function is read; a helper that builds or runs the statement is not followed; bound
values are not flows; the method name is matched on any receiver except the code-runner names
above, so `execute` on a non-database object is flagged; and the check does not judge whether
an `if` test is a sound allowlist. A public scan of 21 repositories found one hit, a
`sandbox.execute(code)` call in `ggozad/haiku.rag` (commit `18f0b4f`), which is not SQL; the
receiver exclusion above was added for it and the repository then gave no hit. No true
positive was seen outside the fixture.

### MCP-219 — TypeScript MCP tool parameter reaches a child process or file call without normalization (Severity: high, Confidence: 0.45, Fix type: code)

**What we detect:** a TypeScript or JavaScript `mcp_tool` with a flow from a declared
parameter, read from the destructured first handler argument or as `args.name`, to a
`child_process` call or an `fs` call. `path.resolve`, a `Number()` cast, a `z.number`,
`z.boolean` or `z.enum` parameter, a schema `.parse` call and an `if` test that throws or
returns end the flow.

**Why it is flaggable:** as for MCP-215.

**Real-world consequence:** as for MCP-215.

**Severity:** the pack sets high and states no reasoning for it.

**Fix type — code:** resolve the path and check the prefix with a separator, use `execFile`
with an argument array, and check each value against an allowlist.

**Confidence 0.45:** The pack sets 0.45. The pack's explanation states these limits: just the
handler body is read; another function that makes the call is not followed; properties other
than declared parameters, class fields and module variables are not followed; a resolved path
is not compared with a root by the check; and bare `open` and `access` are not read unless
called on `fs`.

### MCP-220 — TypeScript MCP tool parameter reaches eval or new Function (Severity: critical, Confidence: 0.55, Fix type: code)

**What we detect:** a TypeScript or JavaScript `mcp_tool` with a flow from a declared
parameter to `eval`, `new Function` or a `vm` run call.

**Why it is flaggable:** as for MCP-216.

**Real-world consequence:** as for MCP-216.

**Severity:** the pack sets critical and states no reasoning for it.

**Fix type — code:** parse data with `JSON.parse`, map operation names to functions, or sandbox.

**Confidence 0.55:** The pack sets 0.55. The pack's explanation states these limits: just the
handler body is read; another function that calls `eval` is not followed; a cast, a numeric,
boolean or enum parameter, a schema `.parse` call and an `if` test end the flow; and
`JSON.parse` is not a sink.

---

## What this policy does not cover

- A parameter passed to a helper function, in the same file or another, and a sink inside a
  helper. Handler arguments passed whole to another function are not followed.
- Class state (`self.x`), module globals and closures over outer variables.
- Container elements beyond a literal: after `d = {"a": p}`, a read `d["a"]` is not tracked,
  and `lst.append(p)` does not taint `lst`.
- Sanitizers beyond the fixed list. A custom `validate(p)` counts as an `if` test that
  raises or returns.
- Dynamic code (`getattr`, names built at run time), decorators that rewrite arguments, and
  framework middleware that validates arguments.
- Tools that discovery does not find, such as handlers registered through shapes the SDK
  discovery does not read.
- Other SDKs. The taint pass computes flows for each Python and TypeScript tool kind; the
  rules in this policy apply to MCP tools. Clone rules for the OpenAI, Claude, CrewAI, ADK and
  Pydantic AI packs, a TypeScript MCP-217 and a TypeScript SQL rule are not built.

---

## Recommendations beyond the fix

1. Keep tool functions short and call the dangerous operation inside a function that checks its
   own input; the check reads one function, and a short function is easier to review as well.
2. Make the server the source of tenant, user and root values, and give the tool no parameter
   for them.
3. Run MCP servers with the narrowest file and network permissions the host allows, so a missed
   check has a smaller reach.

---

## Sources

- Zeqian Huang, Mingyue Tang, Aonan Guan, Qiming Sun and Pengzhou He, "My Credentials, Please:
  Detecting Filesystem Capability Laundering in MCP Servers at Scale", arXiv:2610.22301 (abstract
  read through the arXiv API). Retrieved 2026-11-27. Cited for the class of attacker-steered
  arguments causing a tool to access host files outside its declared contract, and nothing more.
- GitHub advisory GHSA-w7x8-q2gp-5cgg, "Flowise Prompt Injection to RCE and SSRF via
  CSV/Airtable Agent Python Validator Bypass" (CVE-2026-73487). Retrieved 2026-11-27. Cited for
  the class of model-generated code reaching an execution call, and nothing more.
- GitHub advisory GHSA-5324-3w58-qpp2, "Mem0: Cross-tenant conversation leak via unescaped
  delimiter collision in session-scope key" (CVE-2026-116575). Retrieved 2026-11-27. Cited for
  the join mechanism of a scope key, and nothing more.
- GitHub advisory GHSA-v867-6qx2-gwmg, "Tabularis before 0.28.0 contains an SQL injection
  vulnerability in its SQLite driver" (CVE-2026-118378). Retrieved 2026-11-27. Cited for the class
  of a tool parameter placed into SQL text, and nothing more; the code it describes is not Python.
