# Policy index

All shipped rules across every SDK. ID prefix denotes SDK: `CSDK-` Claude
Agent SDK, `OAI-` OpenAI Agents SDK, `ADK-` Google ADK. Within an SDK: `NNN`
tool-scope, `1NN` agent / subagent scope, `2NN` repo scope.

Risk score = `severity_weight × confidence × 100` (engine formula; weights:
low=0.15, medium=0.40, high=0.70). Higher = worse.

## Contributing a new policy

Every policy in this index follows the same authoring template. The template
lives at [docs/policy-rationale-doc-template-guide.md](docs/policy-rationale-doc-template-guide.md)
and defines the rule YAML schema, the paired rationale doc at
`docs/Policy/<category>/<topic>.md`, and the required sections (threat model,
detection mechanics, references). Users can contribute their own policies by:

1. Reading [CLAUDE.md](CLAUDE.md) for the rule-authoring contract (required
   fields, per-scope `applies_to` values, ID conventions, severity guidance).
2. Copying the template from
   [docs/policy-rationale-doc-template-guide.md](docs/policy-rationale-doc-template-guide.md)
   and filling every section.
3. Adding the YAML rule under `<sdk_category>/<topic>.yaml` and the paired
   rationale at `docs/Policy/<sdk_category>/<topic>.md`.
4. Mirroring the rule into the engine repo's `testdata/rules-fixture/` with at
   least one fire case and one silent case (see CLAUDE.md "Add a rule for X").
5. Opening a PR — the rule appears here once merged.

## Totals

| SDK                 | Tool   | Agent  | Subagent | Repo  | Total  | Per-SDK index                                              |
| ------------------- | ------ | ------ | -------- | ----- | ------ | ---------------------------------------------------------- |
| Claude Agent SDK    | 7      | 2      | 1        | 0     | 10     | [claude_sdk/POLICY_INDEX.md](claude_sdk/POLICY_INDEX.md)   |
| OpenAI Agents SDK   | 13     | 6      | 0        | 1     | 20     | [openai_sdk/POLICY_INDEX.md](openai_sdk/POLICY_INDEX.md)   |
| Google ADK          | 8      | 5      | 0        | 0     | 13     | [google_adk/POLICY_INDEX.md](google_adk/POLICY_INDEX.md)   |
| **All**             | **28** | **13** | **1**    | **1** | **43** |                                                            |

## All rules

|    | Id        | SDK/ADK    | Scope    | Applies To                          | Policy                                                                     | Severity | Confidence | Risk | Source                                                          |
| -- | --------- | ------ | -------- | ----------------------------------- | -------------------------------------------------------------------------- | -------- | ---------- | ---- | --------------------------------------------------------------- |
|  1 | CSDK-001  | Claude SDK | tool     | claude_sdk_tool                     | Tool has no description                                                    | low      | 0.95       | 14.3 | [claude_sdk/tool_definition.yaml](https://github.com/trustabl/trustabl-rules/blob/main/claude_sdk/tool_definition.yaml)        |
|  2 | CSDK-002  | Claude SDK | tool     | claude_sdk_tool                     | Tool parameters are not type-annotated                                     | medium   | 0.90       | 36.0 | [claude_sdk/tool_definition.yaml](https://github.com/trustabl/trustabl-rules/blob/main/claude_sdk/tool_definition.yaml)        |
|  3 | CSDK-003  | Claude SDK | tool     | claude_sdk_tool                     | Network call has no timeout                                                | high     | 0.85       | 59.5 | [claude_sdk/network.yaml](https://github.com/trustabl/trustabl-rules/blob/main/claude_sdk/network.yaml)                        |
|  4 | CSDK-004  | Claude SDK | tool     | claude_sdk_tool                     | Path parameter used in I/O without validation                              | high     | 0.70       | 49.0 | [claude_sdk/path_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/claude_sdk/path_safety.yaml)                |
|  5 | CSDK-005  | Claude SDK | tool     | claude_sdk_tool                     | Tool raises exceptions without a structured error contract                 | medium   | 0.60       | 24.0 | [claude_sdk/error_handling.yaml](https://github.com/trustabl/trustabl-rules/blob/main/claude_sdk/error_handling.yaml)          |
|  6 | CSDK-006  | Claude SDK | tool     | claude_sdk_tool                     | Mutating tool has no idempotency key                                       | medium   | 0.55       | 22.0 | [claude_sdk/idempotency.yaml](https://github.com/trustabl/trustabl-rules/blob/main/claude_sdk/idempotency.yaml)                |
|  7 | CSDK-007  | Claude SDK | tool     | claude_sdk_tool                     | Ambiguous tool name                                                        | low      | 0.90       | 13.5 | [claude_sdk/tool_definition.yaml](https://github.com/trustabl/trustabl-rules/blob/main/claude_sdk/tool_definition.yaml)        |
|  8 | CSDK-101  | Claude SDK | agent    | claude_agent_definition             | Claude subagent is granted the Bash tool                                   | high     | 0.80       | 56.0 | [claude_sdk/agent_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/claude_sdk/agent_safety.yaml)              |
|  9 | CSDK-102  | Claude SDK | agent    | claude_agent_definition             | Claude subagent is granted the WebSearch tool                              | high     | 0.80       | 56.0 | [claude_sdk/agent_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/claude_sdk/agent_safety.yaml)              |
| 10 | CSDK-110  | Claude SDK | subagent | claude_subagent                     | Subagent granted the built-in Bash tool                                    | high     | 0.90       | 63.0 | [claude_sdk/subagent_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/claude_sdk/subagent_safety.yaml)        |
| 11 | OAI-001   | OpenAI SDK | tool     | openai_tool                         | Tool function has no docstring                                             | low      | 0.90       | 13.5 | [openai_sdk/tool_definition.yaml](https://github.com/trustabl/trustabl-rules/blob/main/openai_sdk/tool_definition.yaml)        |
| 12 | OAI-002   | OpenAI SDK | tool     | openai_tool                         | Tool function has no type-annotated parameters                             | medium   | 0.85       | 34.0 | [openai_sdk/tool_definition.yaml](https://github.com/trustabl/trustabl-rules/blob/main/openai_sdk/tool_definition.yaml)        |
| 13 | OAI-003   | OpenAI SDK | tool     | openai_tool                         | Tool sets strict_mode=False                                                | medium   | 0.95       | 38.0 | [openai_sdk/decorator_config.yaml](https://github.com/trustabl/trustabl-rules/blob/main/openai_sdk/decorator_config.yaml)      |
| 14 | OAI-004   | OpenAI SDK | tool     | openai_tool                         | Tool has no failure_error_function                                         | medium   | 0.70       | 28.0 | [openai_sdk/decorator_config.yaml](https://github.com/trustabl/trustabl-rules/blob/main/openai_sdk/decorator_config.yaml)      |
| 15 | OAI-005   | OpenAI SDK | tool     | openai_tool                         | Network call has no timeout                                                | high     | 0.85       | 59.5 | [openai_sdk/network.yaml](https://github.com/trustabl/trustabl-rules/blob/main/openai_sdk/network.yaml)                        |
| 16 | OAI-006   | OpenAI SDK | tool     | openai_tool                         | Tool accepts path without normalization                                    | high     | 0.70       | 49.0 | [openai_sdk/path_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/openai_sdk/path_safety.yaml)                |
| 17 | OAI-007   | OpenAI SDK | tool     | openai_tool                         | Ambiguous tool name                                                        | low      | 0.90       | 13.5 | [openai_sdk/tool_definition.yaml](https://github.com/trustabl/trustabl-rules/blob/main/openai_sdk/tool_definition.yaml)        |
| 18 | OAI-008   | OpenAI SDK | tool     | openai_tool                         | Tool raises exceptions without a structured error contract                 | medium   | 0.60       | 24.0 | [openai_sdk/error_handling.yaml](https://github.com/trustabl/trustabl-rules/blob/main/openai_sdk/error_handling.yaml)          |
| 19 | OAI-009   | OpenAI SDK | tool     | openai_tool                         | Mutating tool has no idempotency key                                       | medium   | 0.55       | 22.0 | [openai_sdk/idempotency.yaml](https://github.com/trustabl/trustabl-rules/blob/main/openai_sdk/idempotency.yaml)                |
| 20 | OAI-010   | OpenAI SDK | tool     | openai_tool                         | Tool function prints to stdout for diagnostics                             | low      | 0.65       | 9.75 | [openai_sdk/observability.yaml](https://github.com/trustabl/trustabl-rules/blob/main/openai_sdk/observability.yaml)            |
| 21 | OAI-011   | OpenAI SDK | tool     | openai_tool                         | urllib network call has no timeout                                         | high     | 0.85       | 59.5 | [openai_sdk/network.yaml](https://github.com/trustabl/trustabl-rules/blob/main/openai_sdk/network.yaml)                        |
| 22 | OAI-012   | OpenAI SDK | tool     | openai_tool                         | Tool body spawns a subprocess                                              | high     | 0.90       | 63.0 | [openai_sdk/shell_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/openai_sdk/shell_safety.yaml)              |
| 23 | OAI-013   | OpenAI SDK | tool     | openai_tool                         | Tool body calls eval/exec/compile on dynamic input                         | high     | 0.90       | 63.0 | [openai_sdk/code_execution.yaml](https://github.com/trustabl/trustabl-rules/blob/main/openai_sdk/code_execution.yaml)          |
| 24 | OAI-101   | OpenAI SDK | agent    | openai_agent, openai_sandbox_agent  | Agent has no input_guardrails AND wires shell or filesystem-touching tools | high     | 0.85       | 59.5 | [openai_sdk/agent_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/openai_sdk/agent_safety.yaml)              |
| 25 | OAI-102   | OpenAI SDK | agent    | openai_agent, openai_sandbox_agent  | Agent uses tool_use_behavior="stop_on_first_tool"                          | high     | 0.95       | 66.5 | [openai_sdk/agent_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/openai_sdk/agent_safety.yaml)              |
| 26 | OAI-103   | OpenAI SDK | agent    | openai_agent, openai_sandbox_agent  | tool_choice="required" combined with reset_tool_choice=False               | high     | 0.95       | 66.5 | [openai_sdk/agent_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/openai_sdk/agent_safety.yaml)              |
| 27 | OAI-104   | OpenAI SDK | agent    | openai_agent                        | Raw Agent (not SandboxAgent) wires shell or filesystem-touching tools      | medium   | 0.75       | 30.0 | [openai_sdk/agent_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/openai_sdk/agent_safety.yaml)              |
| 28 | OAI-106   | OpenAI SDK | agent    | openai_agent, openai_sandbox_agent  | Agent wires MCP servers without input_guardrails                           | high     | 0.90       | 63.0 | [openai_sdk/mcp_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/openai_sdk/mcp_safety.yaml)                  |
| 29 | OAI-109   | OpenAI SDK | agent    | openai_agent, openai_sandbox_agent  | Agent uses WebSearchTool without input_guardrails                          | high     | 0.85       | 59.5 | [openai_sdk/agent_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/openai_sdk/agent_safety.yaml)              |
| 30 | OAI-201   | OpenAI SDK | repo     | openai_agents                       | Project uses default OpenAI tracing                                        | medium   | 0.80       | 32.0 | [openai_sdk/tracing.yaml](https://github.com/trustabl/trustabl-rules/blob/main/openai_sdk/tracing.yaml)                        |
| 31 | ADK-001   | Google ADK    | tool     | adk_function_tool                   | FunctionTool-wrapped function has no docstring                             | low      | 0.80       | 12.0 | [google_adk/tool_definition.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/tool_definition.yaml)        |
| 32 | ADK-002   | Google ADK   | tool     | adk_function_tool                   | FunctionTool-wrapped function has no type-annotated parameters             | medium   | 0.85       | 34.0 | [google_adk/tool_definition.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/tool_definition.yaml)        |
| 33 | ADK-003   | Google ADK   | tool     | adk_function_tool                   | Network call has no timeout                                                | high     | 0.85       | 59.5 | [google_adk/network.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/network.yaml)                        |
| 34 | ADK-004   | Google ADK    | tool     | adk_function_tool                   | Path parameter used in I/O without normalization                           | high     | 0.70       | 49.0 | [google_adk/path_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/path_safety.yaml)                |
| 35 | ADK-005   | Google ADK    | tool     | adk_function_tool                   | Tool raises exceptions without a structured error contract                 | medium   | 0.60       | 24.0 | [google_adk/error_handling.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/error_handling.yaml)          |
| 36 | ADK-006   | Google ADK    | tool     | adk_function_tool                   | Mutating tool has no idempotency key                                       | medium   | 0.55       | 22.0 | [google_adk/idempotency.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/idempotency.yaml)                |
| 37 | ADK-007   | Google ADK    | tool     | adk_function_tool                   | Ambiguous tool name                                                        | low      | 0.90       | 13.5 | [google_adk/tool_definition.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/tool_definition.yaml)        |
| 38 | ADK-008   | Google ADK    | tool     | adk_function_tool                   | BashTool missing shell metacharacter blocking                              | high     | 0.90       | 63.0 | [google_adk/builtin_tools.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/builtin_tools.yaml)            |
| 39 | ADK-101   | Google ADK    | agent    | adk_llm_agent                       | LlmAgent has no description                                                | medium   | 0.85       | 34.0 | [google_adk/agent_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/agent_safety.yaml)              |
| 40 | ADK-102   | Google ADK    | agent    | adk_llm_agent                       | Agent with BashTool has no before_tool_callback                            | high     | 0.85       | 59.5 | [google_adk/agent_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/agent_safety.yaml)              |
| 41 | ADK-103   | Google ADK    | agent    | adk_llm_agent                       | Sub-agent is granted BashTool                                              | high     | 0.90       | 63.0 | [google_adk/agent_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/agent_safety.yaml)              |
| 42 | ADK-104   | Google ADK    | agent    | adk_llm_agent                       | Agent has no safety_settings                                               | medium   | 0.75       | 30.0 | [google_adk/agent_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/agent_safety.yaml)              |
| 43 | ADK-105   | Google ADK    | agent    | adk_llm_agent                       | Agent uses web search built-in without before_tool_callback                | high     | 0.85       | 59.5 | [google_adk/agent_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/agent_safety.yaml)              |
