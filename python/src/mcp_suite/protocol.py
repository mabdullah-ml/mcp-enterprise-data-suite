"""MCP JSON-RPC 2.0 protocol dispatcher exposing SQL and Vector KB tools."""

from __future__ import annotations

from typing import Any

from mcp_suite.security.governance import (
    AuthorizationError,
    GovernanceController,
    RateLimitExceededError,
)
from mcp_suite.security.sql_guard import SQLGuardrailError
from mcp_suite.servers.sql_analytics_server import SQLAnalyticsMCPServer
from mcp_suite.servers.vector_kb_server import VectorKnowledgeBaseMCPServer

PROTOCOL_VERSION = "2024-11-05"


class EnterpriseMCPRouter:
    """Handles MCP JSON-RPC 2.0 requests (`initialize`, `tools/list`, `tools/call`)."""

    def __init__(
        self,
        governance: GovernanceController | None = None,
        db_path: str = ":memory:",
        max_sql_rows: int = 200,
    ) -> None:
        self.governance = governance or GovernanceController()
        self.sql_server = SQLAnalyticsMCPServer(
            governance=self.governance, db_path=db_path, max_rows=max_sql_rows
        )
        self.kb_server = VectorKnowledgeBaseMCPServer(governance=self.governance)

    def close(self) -> None:
        self.sql_server.close()

    def list_tools(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "sql_list_tables",
                "description": "List enterprise analytics tables available for read-only querying.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "sql_describe_table",
                "description": "Inspect column names and types for a whitelisted SQL table.",
                "inputSchema": {
                    "type": "object",
                    "required": ["table_name"],
                    "properties": {"table_name": {"type": "string"}},
                },
            },
            {
                "name": "sql_execute_readonly",
                "description": (
                    "Execute a guarded read-only SELECT/CTE SQL query with automatic row limit "
                    "clamping and role-based PII redaction."
                ),
                "inputSchema": {
                    "type": "object",
                    "required": ["query"],
                    "properties": {"query": {"type": "string"}},
                },
            },
            {
                "name": "kb_search",
                "description": "Hybrid lexical + cosine vector search across enterprise policies & SOPs.",
                "inputSchema": {
                    "type": "object",
                    "required": ["query"],
                    "properties": {
                        "query": {"type": "string"},
                        "top_k": {"type": "integer", "default": 3},
                        "category": {"type": "string"},
                    },
                },
            },
            {
                "name": "kb_get_document",
                "description": "Retrieve a specific enterprise knowledge document by doc_id.",
                "inputSchema": {
                    "type": "object",
                    "required": ["doc_id"],
                    "properties": {"doc_id": {"type": "string"}},
                },
            },
        ]

    def handle_jsonrpc(
        self,
        request: dict[str, Any],
        caller_id: str = "anonymous",
        role: str = "analyst",
    ) -> dict[str, Any]:
        req_id = request.get("id")
        method = request.get("method", "")
        params = request.get("params") or {}

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "serverInfo": {"name": "mcp-enterprise-data-suite", "version": "1.0.0"},
                    "capabilities": {"tools": {}},
                },
            }

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": self.list_tools()}}

        if method == "tools/call":
            tool_name = str(params.get("name", ""))
            args = params.get("arguments") or {}
            try:
                data = self._dispatch_tool(tool_name, args, caller_id=caller_id, role=role)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "isError": False,
                        "structuredContent": data,
                    },
                }
            except (AuthorizationError, RateLimitExceededError) as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32001, "message": str(exc)},
                }
            except (SQLGuardrailError, ValueError, KeyError) as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": str(exc)},
                }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: '{method}'"},
        }

    def _dispatch_tool(
        self,
        tool_name: str,
        args: dict[str, Any],
        caller_id: str,
        role: str,
    ) -> dict[str, Any]:
        if tool_name == "sql_list_tables":
            return self.sql_server.list_tables(caller_id=caller_id, role=role)
        if tool_name == "sql_describe_table":
            return self.sql_server.describe_table(
                table_name=str(args.get("table_name", "")),
                caller_id=caller_id,
                role=role,
            )
        if tool_name == "sql_execute_readonly":
            return self.sql_server.execute_readonly_sql(
                query=str(args.get("query", "")),
                caller_id=caller_id,
                role=role,
            )
        if tool_name == "kb_search":
            return self.kb_server.search_knowledge_base(
                query=str(args.get("query", "")),
                caller_id=caller_id,
                role=role,
                top_k=int(args.get("top_k", 3)),
                category=args.get("category"),
            )
        if tool_name == "kb_get_document":
            return self.kb_server.get_document_by_id(
                doc_id=str(args.get("doc_id", "")),
                caller_id=caller_id,
                role=role,
            )
        raise ValueError(f"Unknown MCP tool: '{tool_name}'")
