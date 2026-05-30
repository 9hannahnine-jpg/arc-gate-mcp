# arc-gate-mcp

Runtime governance proxy for MCP tool calls. Blocks prompt injection and capability abuse before tool results reach your agent.

## What it does

arc-gate-mcp sits between your MCP client and any MCP server. Every tool result passes through Arc Gate governance before reaching your agent — blocking prompt injection attacks that exploit the MCP trust boundary.

## Installation

```bash
pip install arc-gate-mcp
```

## Usage

```bash
arc-gate-mcp --upstream "uvx mcp-server-fetch" --policy balanced
```

### With Claude Desktop

```json
{
  "mcpServers": {
    "arc-gate": {
      "command": "uvx",
      "args": ["arc-gate-mcp", "--upstream", "uvx mcp-server-fetch", "--policy", "browser_agent"]
    }
  }
}
```

## Policy modes

- `balanced` — general purpose
- `browser_agent` — web browsing agents
- `finance_agent` — financial data agents
- `rag_assistant` — document retrieval agents
- `strict` — maximum enforcement

## Links

- [Bendex Arc Platform](https://bendexgeometry.com)
- [PyPI](https://pypi.org/project/arc-gate-mcp/)

## License

AGPL-3.0
