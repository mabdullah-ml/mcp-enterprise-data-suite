import assert from "node:assert/strict";
import test from "node:test";
import { EnterpriseOpsMCPServer } from "./api_bridge_server.ts";

test("ops_list_incidents filters open incidents cleanly", () => {
  const mcp = new EnterpriseOpsMCPServer();
  const res = mcp.handleJsonRpc(
    {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "ops_list_incidents", arguments: { status: "open" } },
    },
    "agent-ops",
    "analyst"
  );
  const content = (res.result as { structuredContent: { count: number; items: { incident_id: string }[] } })
    .structuredContent;
  assert.equal(content.count, 1);
  assert.equal(content.items[0].incident_id, "INC-503");
});

test("ops_create_change_ticket enforces RBAC and requires HITL approval", () => {
  const mcp = new EnterpriseOpsMCPServer();
  const denied = mcp.handleJsonRpc(
    {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "ops_create_change_ticket",
        arguments: { title: "Scale embedding workers", service: "bedrock-embedding-sync" },
      },
    },
    "analyst-bot",
    "analyst"
  );
  assert.equal(denied.error?.code, -32001);

  const allowed = mcp.handleJsonRpc(
    {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "ops_create_change_ticket",
        arguments: { title: "Scale embedding workers", service: "bedrock-embedding-sync" },
      },
    },
    "sre-agent",
    "engineer"
  );
  const ticket = (
    allowed.result as { structuredContent: { ticket_id: string; requires_hitl_approval: boolean } }
  ).structuredContent;
  assert.equal(ticket.ticket_id, "CHG-101");
  assert.equal(ticket.requires_hitl_approval, true);
});
