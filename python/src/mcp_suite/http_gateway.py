"""FastAPI HTTP transport gateway exposing the Enterprise MCP JSON-RPC router & audit log."""

from __future__ import annotations

from dataclasses import asdict
from typing import Annotated, Any

from fastapi import FastAPI, Header

from mcp_suite.protocol import EnterpriseMCPRouter

app = FastAPI(
    title="MCP Enterprise Data Suite Gateway",
    version="1.0.0",
    description="Guarded MCP JSON-RPC 2.0 server for read-only SQL analytics and hybrid vector KB.",
)
router_instance = EnterpriseMCPRouter()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "server": "mcp-enterprise-data-suite"}


@app.post("/mcp")
def mcp_endpoint(
    payload: dict[str, Any],
    x_caller_id: Annotated[str, Header()] = "langgraph-agent",
    x_caller_role: Annotated[str, Header()] = "analyst",
) -> dict[str, Any]:
    return router_instance.handle_jsonrpc(payload, caller_id=x_caller_id, role=x_caller_role)


@app.get("/audit")
def get_audit_log() -> dict[str, Any]:
    events = [asdict(ev) for ev in router_instance.governance.audit_log]
    return {"count": len(events), "events": events}
