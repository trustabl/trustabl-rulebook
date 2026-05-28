# Google ADK policy index 

13 rules — 8 tool · 5 agent

Risk score = `severity_weight × confidence × 100` (engine formula; weights: low=0.15, medium=0.40, high=0.70). Higher = worse.

|    | Id       | SDK/ADK    | Scope | Applies To         | Policy                                                     | Severity | Confidence | Risk | Source                                            |
| -- | -------- | ---------- | ----- | ------------------ | ---------------------------------------------------------- | -------- | ---------- | ---- | ------------------------------------------------- |
|  1 | ADK-001  | Google ADK | tool  | adk_function_tool  | FunctionTool-wrapped function has no docstring             | low      | 0.80       | 12.0 | [tool_definition.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/tool_definition.yaml)      |
|  2 | ADK-002  | Google ADK | tool  | adk_function_tool  | FunctionTool-wrapped function has no type-annotated parameters | medium | 0.85     | 34.0 | [tool_definition.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/tool_definition.yaml)      |
|  3 | ADK-003  | Google ADK | tool  | adk_function_tool  | Network call has no timeout                                | high     | 0.85       | 59.5 | [network.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/network.yaml)                      |
|  4 | ADK-004  | Google ADK | tool  | adk_function_tool  | Path parameter used in I/O without normalization           | high     | 0.70       | 49.0 | [path_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/path_safety.yaml)              |
|  5 | ADK-005  | Google ADK | tool  | adk_function_tool  | Tool raises exceptions without a structured error contract | medium   | 0.60       | 24.0 | [error_handling.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/error_handling.yaml)        |
|  6 | ADK-006  | Google ADK | tool  | adk_function_tool  | Mutating tool has no idempotency key                       | medium   | 0.55       | 22.0 | [idempotency.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/idempotency.yaml)              |
|  7 | ADK-007  | Google ADK | tool  | adk_function_tool  | Ambiguous tool name                                        | low      | 0.90       | 13.5 | [tool_definition.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/tool_definition.yaml)      |
|  8 | ADK-008  | Google ADK | tool  | adk_function_tool  | BashTool missing shell metacharacter blocking              | high     | 0.90       | 63.0 | [builtin_tools.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/builtin_tools.yaml)          |
|  9 | ADK-101  | Google ADK | agent | adk_llm_agent      | LlmAgent has no description                                | medium   | 0.85       | 34.0 | [agent_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/agent_safety.yaml)            |
| 10 | ADK-102  | Google ADK | agent | adk_llm_agent      | Agent with BashTool has no before_tool_callback            | high     | 0.85       | 59.5 | [agent_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/agent_safety.yaml)            |
| 11 | ADK-103  | Google ADK | agent | adk_llm_agent      | Sub-agent is granted BashTool                              | high     | 0.90       | 63.0 | [agent_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/agent_safety.yaml)            |
| 12 | ADK-104  | Google ADK | agent | adk_llm_agent      | Agent has no safety_settings                               | medium   | 0.75       | 30.0 | [agent_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/agent_safety.yaml)            |
| 13 | ADK-105  | Google ADK | agent | adk_llm_agent      | Agent uses web search built-in without before_tool_callback | high    | 0.85       | 59.5 | [agent_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/google_adk/agent_safety.yaml)            |
