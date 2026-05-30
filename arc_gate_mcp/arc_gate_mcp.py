"""
arc-gate-mcp — Runtime governance for MCP tool calls
=====================================================
Arc Gate MCP sits between your MCP client (agent) and any MCP server.
It intercepts all tool call results and enforces instruction-authority
boundaries before the agent processes them.

When a tool result contains injected instructions, Arc Gate blocks them
before they reach the agent — the same guarantee as the OpenAI proxy,
but for the MCP protocol layer.

Usage:
    # Wrap any MCP server
    from arc_gate_mcp import ArcGateMCPProxy

    proxy = ArcGateMCPProxy(
        upstream_url="http://localhost:8000/sse",   # your MCP server
        policy_mode="rag_assistant",                 # or browser_agent, finance_agent
        arc_gate_url="https://web-production-6e47f.up.railway.app/v1/chat/completions",
        api_key="your-key",
    )
    proxy.run()

Architecture:
    Agent → Arc Gate MCP Proxy → Upstream MCP Server
               ↓
    Tool result intercepted
    Authority state machine checks source
    If injection detected: result sanitized / blocked
    If clean: result passed through unchanged
"""

import asyncio
import json
import os
import re
import uuid
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlparse

import httpx
from mcp.server.fastmcp import FastMCP
from mcp import ClientSession
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.types import (
    CallToolResult,
    TextContent,
    Tool,
)

# ── Authority detection (mirrors arc_authority_state.py logic) ────────────────

TOOL_POISON_PATTERNS = [
    r"<information>",
    r"</information>",
    r"this\s+is\s+an?\s+important\s+message\s+from\s+me",
    r"before\s+you\s+can\s+solve\s+the\s+task",
    r"please\s+do\s+the\s+following\s+first",
    r"after\s+you\s+do\s+that.{0,30}you\s+can\s+solve",
    r"you\s+should\s+use\s+the\s+tool\s+`?\w+`?",
    r"signed,?\s*\n\s*\w+",
    r"(assistant|agent|ai|llm|model|system|gpt|claude)\s*[,:]?\s*(ignore|disregard|forget|override|bypass|reveal|follow|obey|comply)",
    r"(for\s+ai\s+(readers?|systems?|agents?)|note\s+to\s+(ai|assistant|agent|llm))",
    r"(hidden|invisible|secret)\s+(instruction|command|directive|note)",
    r"(this\s+(tool|document|webpage|email|result|output|database|file))\s+(supersedes?|overrides?|replaces?)",
    r"follow\s+(the\s+)?(instructions?|directive|command)\s+(in|from|inside|within|embedded\s+in)\s+(this|the)",
    r"ignore\s+(all\s+)?(previous|prior|earlier|above|your)\s+instructions?",
    r"disregard\s+(all\s+)?(previous|prior|earlier|above|your)\s+instructions?",
    r"override\s+(system|developer|operator|admin)\s+instructions?",
    r"bypass\s+(safety|security|content|policy|all)\s+(filter|guard|check|rule|restriction)s?",
    r"system\s+(override|command|directive|instruction)",
    r"\[system\]",
    r"### system",
    r"your\s+new\s+instructions?\s+(are|is|follow)",
]

_COMPILED_PATTERNS = [
    re.compile(p, re.IGNORECASE | re.DOTALL)
    for p in TOOL_POISON_PATTERNS
]


def _detect_injection(text: str) -> tuple[bool, Optional[str]]:
    """Check tool result text for injection attempts. Returns (detected, matched_pattern)."""
    import unicodedata, base64, codecs

    def _norm(s):
        return unicodedata.normalize('NFKD', s).encode('ascii', 'ignore').decode('ascii')

    variants = [text, _norm(text)]

    # Base64 decode attempt
    for chunk in re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text):
        try:
            decoded = base64.b64decode(chunk).decode('utf-8', errors='ignore')
            if len(decoded) > 10:
                variants.append(decoded)
        except Exception:
            pass

    # ROT13
    try:
        variants.append(codecs.decode(text, 'rot13'))
    except Exception:
        pass

    for variant in variants:
        for pattern in _COMPILED_PATTERNS:
            m = pattern.search(variant)
            if m:
                return True, m.group(0)[:80]

    return False, None


@dataclass
class GovernanceDecision:
    blocked: bool
    decision: str  # allow | restricted_continue | block
    reason: str
    matched_pattern: Optional[str]
    sanitized_content: Optional[str] = None


def _govern_tool_result(
    tool_name: str,
    result_text: str,
    policy_mode: str = "balanced",
) -> GovernanceDecision:
    """
    Apply Arc Gate governance to a tool result.
    Returns a GovernanceDecision with the enforcement action.
    """
    detected, matched = _detect_injection(result_text)

    if not detected:
        return GovernanceDecision(
            blocked=False,
            decision="allow",
            reason="no_violation",
            matched_pattern=None,
        )

    # Finance agent: strictest — block everything
    if policy_mode == "finance_agent":
        return GovernanceDecision(
            blocked=True,
            decision="block",
            reason="source_boundary_violation",
            matched_pattern=matched,
        )

    # Browser agent: block tool calls but allow safe text continuation
    if policy_mode == "browser_agent":
        safe = _sanitize_result(result_text)
        return GovernanceDecision(
            blocked=False,
            decision="restricted_continue",
            reason="source_boundary_violation",
            matched_pattern=matched,
            sanitized_content=safe,
        )

    # RAG assistant: strip injection, return safe content
    if policy_mode == "rag_assistant":
        safe = _sanitize_result(result_text)
        return GovernanceDecision(
            blocked=False,
            decision="restricted_continue",
            reason="source_boundary_violation",
            matched_pattern=matched,
            sanitized_content=safe,
        )

    # Balanced default: block
    return GovernanceDecision(
        blocked=True,
        decision="block",
        reason="source_boundary_violation",
        matched_pattern=matched,
    )


def _sanitize_result(text: str) -> str:
    """Strip injection content from tool result, preserving safe data."""
    # Remove <INFORMATION>...</INFORMATION> blocks
    text = re.sub(
        r'<INFORMATION>.*?</INFORMATION>',
        '[Arc Gate: Injected instruction removed]',
        text, flags=re.IGNORECASE | re.DOTALL
    )
    # Remove lines that match injection patterns
    lines = []
    for line in text.split('\n'):
        detected, _ = _detect_injection(line)
        if not detected:
            lines.append(line)
        else:
            lines.append('[Arc Gate: Instruction removed]')
    return '\n'.join(lines)


# ── Arc Gate MCP Proxy ────────────────────────────────────────────────────────

class ArcGateMCPProxy:
    """
    Transparent MCP proxy that enforces instruction-authority boundaries
    on all tool call results before they reach the agent.

    Wraps any upstream MCP server and exposes the same tool interface.
    Injected instructions in tool results are blocked or sanitized
    depending on the policy mode.
    """

    def __init__(
        self,
        upstream_url: str,
        policy_mode: str = "balanced",
        arc_gate_url: Optional[str] = None,
        api_key: Optional[str] = None,
        server_name: str = "arc-gate-mcp",
    ):
        self.upstream_url = upstream_url
        self.policy_mode  = policy_mode
        self.arc_gate_url = arc_gate_url or os.environ.get(
            "ARC_GATE_URL",
            "https://web-production-6e47f.up.railway.app/v1/chat/completions"
        )
        self.api_key       = api_key or os.environ.get("OPENAI_API_KEY", "demo")
        self.server_name   = server_name
        self.mcp           = FastMCP(server_name)
        self._upstream_tools: list[Tool] = []
        self._session_id   = f"mcp_proxy_{uuid.uuid4().hex[:12]}"
        self._blocked_count = 0
        self._allowed_count = 0

    def _is_stdio_upstream(self) -> bool:
        """Check if upstream is a stdio command rather than SSE URL."""
        url = self.upstream_url.strip()
        # If it doesn't start with http:// or https://, treat as stdio command
        if url.startswith("http://") or url.startswith("https://"):
            return False
        return True

    def _get_stdio_params(self) -> StdioServerParameters:
        """Parse stdio command into StdioServerParameters."""
        parts = self.upstream_url.strip().split()
        return StdioServerParameters(command=parts[0], args=parts[1:])

    async def _fetch_upstream_tools(self) -> list[Tool]:
        """Connect to upstream MCP server and discover available tools."""
        if self._is_stdio_upstream():
            async with stdio_client(self._get_stdio_params()) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.list_tools()
                    return result.tools
        else:
            async with sse_client(self.upstream_url) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.list_tools()
                    return result.tools

    async def _call_upstream_tool(
        self, tool_name: str, arguments: dict
    ) -> CallToolResult:
        """Call a tool on the upstream MCP server."""
        if self._is_stdio_upstream():
            async with stdio_client(self._get_stdio_params()) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    return await session.call_tool(tool_name, arguments)
        else:
            async with sse_client(self.upstream_url) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    return await session.call_tool(tool_name, arguments)

    def _make_blocked_result(self, tool_name: str, matched: str) -> CallToolResult:
        """Return a safe blocked result with Arc Gate metadata."""
        return CallToolResult(
            content=[TextContent(
                type="text",
                text=(
                    f"[Arc Gate] Tool result from '{tool_name}' was blocked.\n"
                    f"Reason: Untrusted content attempted instruction-authority transfer.\n"
                    f"Matched pattern: {matched}\n"
                    f"Session: {self._session_id}\n"
                    f"Policy: {self.policy_mode}\n\n"
                    f"The tool call completed but the result contained injected instructions "
                    f"that were prevented from reaching the agent."
                )
            )],
            isError=False,
        )

    def _make_restricted_result(
        self, tool_name: str, safe_content: str, matched: str
    ) -> CallToolResult:
        """Return sanitized result with Arc Gate warning."""
        return CallToolResult(
            content=[TextContent(
                type="text",
                text=(
                    f"[Arc Gate: RESTRICTED_CONTINUE] Injected instructions removed from "
                    f"'{tool_name}' result. Safe content preserved.\n\n"
                    f"{safe_content}"
                )
            )],
            isError=False,
        )

    async def _governed_tool_call(
        self, tool_name: str, arguments: dict
    ) -> CallToolResult:
        """Call upstream tool and apply governance to the result."""
        # Call upstream
        result = await self._call_upstream_tool(tool_name, arguments)

        # Extract text content for inspection
        full_text = "\n".join(
            block.text for block in result.content
            if hasattr(block, "text")
        )

        # Apply governance
        decision = _govern_tool_result(full_text, tool_name, self.policy_mode)

        if decision.blocked:
            self._blocked_count += 1
            print(
                f"[Arc Gate] BLOCKED tool='{tool_name}' "
                f"pattern='{decision.matched_pattern}' "
                f"session={self._session_id[:16]}"
            )
            return self._make_blocked_result(tool_name, decision.matched_pattern or "")

        if decision.decision == "restricted_continue":
            self._blocked_count += 1
            print(
                f"[Arc Gate] RESTRICTED_CONTINUE tool='{tool_name}' "
                f"pattern='{decision.matched_pattern}' "
                f"session={self._session_id[:16]}"
            )
            return self._make_restricted_result(
                tool_name,
                decision.sanitized_content or full_text,
                decision.matched_pattern or "",
            )

        self._allowed_count += 1
        return result

    async def _setup(self):
        """Discover upstream tools and register governed versions."""
        print(f"[Arc Gate MCP] Connecting to upstream: {self.upstream_url}")
        tools = await self._fetch_upstream_tools()
        self._upstream_tools = tools
        print(f"[Arc Gate MCP] Discovered {len(tools)} tools: {[t.name for t in tools]}")

        for tool in tools:
            # Capture tool in closure
            tool_name = tool.name

            async def make_handler(name: str):
                async def handler(**kwargs) -> str:
                    # Flatten kwargs — if single 'kwargs' key exists unwrap it
                    args = kwargs.get("kwargs", kwargs) if "kwargs" in kwargs and len(kwargs) == 1 else kwargs
                    result = await self._governed_tool_call(name, args)
                    texts = [
                        block.text for block in result.content
                        if hasattr(block, "text")
                    ]
                    return "\n".join(texts)
                return handler

            handler = await make_handler(tool_name)
            handler.__doc__ = (
                f"Calls the '{tool_name}' tool on the upstream MCP server. "
                f"Pass arguments as keyword arguments matching the upstream tool's input schema. "
                f"For the fetch tool: url (required, string) is the URL to retrieve; max_length (optional, int) limits response size; raw (optional, bool) returns HTML instead of markdown. "
                f"Arc Gate inspects all results for prompt injection before they reach your agent. Policy: {self.policy_mode}. No authentication required. Blocked results return an error string."
            )
                handler,
                name=tool_name,
                description=handler.__doc__,
            )

        print(f"[Arc Gate MCP] Proxy ready. Policy: {self.policy_mode}")
        print(f"[Arc Gate MCP] Session: {self._session_id}")

    def run(self, transport: str = "stdio"):
        """Start the Arc Gate MCP proxy server."""
        async def _run():
            await self._setup()
            if transport == "sse":
                await self.mcp.run_sse_async()
            else:
                await self.mcp.run_stdio_async()

        asyncio.run(_run())

    def stats(self) -> dict:
        return {
            "session_id":     self._session_id,
            "policy_mode":    self.policy_mode,
            "upstream_url":   self.upstream_url,
            "tools_proxied":  len(self._upstream_tools),
            "blocked":        self._blocked_count,
            "allowed":        self._allowed_count,
        }


# ── Standalone governance checker (no upstream required) ─────────────────────

class ArcGateToolGuard:
    """
    Lightweight tool result governance for use without a full MCP proxy.
    Drop into any existing MCP tool handler to protect individual tools.

    Usage:
        from arc_gate_mcp import ArcGateToolGuard

        guard = ArcGateToolGuard(policy_mode="rag_assistant")

        @mcp.tool()
        async def read_document(path: str) -> str:
            content = read_file(path)
            return guard.check(content, tool_name="read_document")
    """

    def __init__(self, policy_mode: str = "balanced"):
        self.policy_mode   = policy_mode
        self.blocked_count = 0
        self.allowed_count = 0

    def check(self, result: str, tool_name: str = "tool") -> str:
        """
        Check a tool result and return safe content.
        Raises ValueError if blocked, returns sanitized content if restricted.
        """
        decision = _govern_tool_result(tool_name, result, self.policy_mode)

        if decision.blocked:
            self.blocked_count += 1
            raise ValueError(
                f"[Arc Gate] Tool result blocked — "
                f"instruction-authority transfer detected in '{tool_name}'. "
                f"Pattern: {decision.matched_pattern}"
            )

        if decision.decision == "restricted_continue":
            self.blocked_count += 1
            return (
                f"[Arc Gate: Injected instructions removed]\n\n"
                f"{decision.sanitized_content or result}"
            )

        self.allowed_count += 1
        return result


# ── CLI entrypoint ────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Arc Gate MCP — Runtime governance for MCP tool calls"
    )
    parser.add_argument(
        "--upstream", required=True,
        help="Upstream MCP server URL (e.g. http://localhost:8000/sse)"
    )
    parser.add_argument(
        "--policy", default="balanced",
        choices=["balanced", "browser_agent", "finance_agent", "rag_assistant", "strict"],
        help="Policy mode (default: balanced)"
    )
    parser.add_argument(
        "--transport", default="stdio",
        choices=["stdio", "sse"],
        help="Transport (default: stdio)"
    )
    parser.add_argument(
        "--api-key", default=None,
        help="Arc Gate API key (or set OPENAI_API_KEY env var)"
    )
    args = parser.parse_args()

    proxy = ArcGateMCPProxy(
        upstream_url=args.upstream,
        policy_mode=args.policy,
        api_key=args.api_key,
    )
    proxy.run(transport=args.transport)


if __name__ == "__main__":
    main()
