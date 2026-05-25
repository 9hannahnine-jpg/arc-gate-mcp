# arc-gate-mcp

**Runtime governance for MCP tool calls.**

Arc Gate MCP sits between your agent and any MCP server. It intercepts all tool call results and enforces instruction-authority boundaries before the agent processes them.

When a tool result contains injected instructions — a poisoned document, a malicious webpage, a hostile database row — Arc Gate blocks them before they reach the agent.

## Install

```bash
pip install arc-gate-mcp
```

## Usage

### Full proxy (wraps any MCP server)

```python
from arc_gate_mcp import ArcGateMCPProxy

proxy = ArcGateMCPProxy(
    upstream_url="http://localhost:8000/sse",
    policy_mode="rag_assistant",
)
proxy.run()
```

### Per-tool guard

```python
from arc_gate_mcp import ArcGateToolGuard

guard = ArcGateToolGuard(policy_mode="rag_assistant")

@mcp.tool()
async def read_document(path: str) -> str:
    content = read_file(path)
    return guard.check(content, tool_name="read_document")
```

### CLI

```bash
arc-gate-mcp --upstream http://localhost:8000/sse --policy rag_assistant
```

## Policy modes

| Mode | Behavior |
|---|---|
| `balanced` | Block on detected injection |
| `browser_agent` | Strip injections, allow safe content |
| `finance_agent` | Strictest — block everything suspicious |
| `rag_assistant` | Strip injections, preserve safe data |

## Related

- [Arc Gate](https://github.com/9hannahnine-jpg/arc-gate) — OpenAI-compatible proxy version
- [arc-sentry](https://github.com/9hannahnine-jpg/arc-sentry) — Whitebox detector for self-hosted models

## License

AGPL-3.0. Commercial license available — contact 9hannahnine@gmail.com.
