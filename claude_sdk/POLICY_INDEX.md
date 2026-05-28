# Claude Agent SDK policy index 

10 rules — 7 tool · 2 agent · 1 subagent

Risk score = `severity_weight × confidence × 100` (engine formula; weights: low=0.15, medium=0.40, high=0.70). Higher = worse.

|    | Id        | SDK/ADK    | Scope    | Applies To              | Policy                                                     | Severity | Confidence | Risk | Source                                          |
| -- | --------- | ---------- | -------- | ----------------------- | ---------------------------------------------------------- | -------- | ---------- | ---- | ----------------------------------------------- |
|  1 | CSDK-001  | Claude SDK | tool     | claude_sdk_tool         | Tool has no description                                    | low      | 0.95       | 14.3 | [tool_definition.yaml](https://github.com/trustabl/trustabl-rules/blob/main/claude_sdk/tool_definition.yaml)    |
|  2 | CSDK-002  | Claude SDK | tool     | claude_sdk_tool         | Tool parameters are not type-annotated                     | medium   | 0.90       | 36.0 | [tool_definition.yaml](https://github.com/trustabl/trustabl-rules/blob/main/claude_sdk/tool_definition.yaml)    |
|  3 | CSDK-003  | Claude SDK | tool     | claude_sdk_tool         | Network call has no timeout                                | high     | 0.85       | 59.5 | [network.yaml](https://github.com/trustabl/trustabl-rules/blob/main/claude_sdk/network.yaml)                    |
|  4 | CSDK-004  | Claude SDK | tool     | claude_sdk_tool         | Path parameter used in I/O without validation              | high     | 0.70       | 49.0 | [path_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/claude_sdk/path_safety.yaml)            |
|  5 | CSDK-005  | Claude SDK | tool     | claude_sdk_tool         | Tool raises exceptions without a structured error contract | medium   | 0.60       | 24.0 | [error_handling.yaml](https://github.com/trustabl/trustabl-rules/blob/main/claude_sdk/error_handling.yaml)      |
|  6 | CSDK-006  | Claude SDK | tool     | claude_sdk_tool         | Mutating tool has no idempotency key                       | medium   | 0.55       | 22.0 | [idempotency.yaml](https://github.com/trustabl/trustabl-rules/blob/main/claude_sdk/idempotency.yaml)            |
|  7 | CSDK-007  | Claude SDK | tool     | claude_sdk_tool         | Ambiguous tool name                                        | low      | 0.90       | 13.5 | [tool_definition.yaml](https://github.com/trustabl/trustabl-rules/blob/main/claude_sdk/tool_definition.yaml)    |
|  8 | CSDK-101  | Claude SDK | agent    | claude_agent_definition | Claude subagent is granted the Bash tool                   | high     | 0.80       | 56.0 | [agent_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/claude_sdk/agent_safety.yaml)          |
|  9 | CSDK-102  | Claude SDK | agent    | claude_agent_definition | Claude subagent is granted the WebSearch tool              | high     | 0.80       | 56.0 | [agent_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/claude_sdk/agent_safety.yaml)          |
| 10 | CSDK-110  | Claude SDK | subagent | claude_subagent         | Subagent granted the built-in Bash tool                    | high     | 0.90       | 63.0 | [subagent_safety.yaml](https://github.com/trustabl/trustabl-rules/blob/main/claude_sdk/subagent_safety.yaml)    |
