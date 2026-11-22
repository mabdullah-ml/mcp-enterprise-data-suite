export type CallerRole = "analyst" | "engineer" | "admin";

export interface IncidentRecord {
  incident_id: string;
  service: string;
  severity: "SEV1" | "SEV2" | "SEV3";
  status: "open" | "mitigated" | "resolved";
  summary: string;
}

export interface ChangeTicket {
  ticket_id: string;
  title: string;
  service: string;
  requires_hitl_approval: boolean;
  created_by: string;
  status: "pending_approval" | "approved";
}

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id: number | string;
  method: string;
  params?: {
    name?: string;
    arguments?: Record<string, unknown>;
  };
}

export interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: number | string;
  result?: unknown;
  error?: { code: number; message: string };
}

const ROLE_SCOPES: Record<CallerRole, Set<string>> = {
  analyst: new Set(["ops:ticket_read"]),
  engineer: new Set(["ops:ticket_read", "ops:ticket_create"]),
  admin: new Set(["ops:ticket_read", "ops:ticket_create"]),
};

export class EnterpriseOpsMCPServer {
  private readonly incidents: IncidentRecord[];
  private readonly tickets: ChangeTicket[] = [];
  private ticketCounter = 100;

  constructor() {
    this.incidents = [
      {
        incident_id: "INC-501",
        service: "rag-retrieval-api",
        severity: "SEV2",
        status: "resolved",
        summary: "OpenSearch hybrid query latency spike resolved via shard rebalance.",
      },
      {
        incident_id: "INC-503",
        service: "bedrock-embedding-sync",
        severity: "SEV2",
        status: "open",
        summary: "Batch embedding queue backlog under investigation in ap-northeast-1.",
      },
    ];
  }

  public listTools() {
    return [
      {
        name: "ops_list_incidents",
        description: "List active and recent production AI platform incidents.",
        inputSchema: {
          type: "object",
          properties: { status: { type: "string" } },
        },
      },
      {
        name: "ops_create_change_ticket",
        description:
          "Create a governed production change ticket (enforces engineer/admin RBAC and HITL approval flag).",
        inputSchema: {
          type: "object",
          required: ["title", "service"],
          properties: {
            title: { type: "string" },
            service: { type: "string" },
          },
        },
      },
    ];
  }

  public handleJsonRpc(
    req: JsonRpcRequest,
    callerId = "agent",
    role: CallerRole = "analyst"
  ): JsonRpcResponse {
    if (req.method === "initialize") {
      return {
        jsonrpc: "2.0",
        id: req.id,
        result: {
          protocolVersion: "2024-11-05",
          serverInfo: { name: "mcp-ops-bridge-server", version: "1.0.0" },
          capabilities: { tools: {} },
        },
      };
    }

    if (req.method === "tools/list") {
      return { jsonrpc: "2.0", id: req.id, result: { tools: this.listTools() } };
    }

    if (req.method === "tools/call") {
      const toolName = req.params?.name ?? "";
      const args = req.params?.arguments ?? {};

      if (toolName === "ops_list_incidents") {
        if (!ROLE_SCOPES[role]?.has("ops:ticket_read")) {
          return {
            jsonrpc: "2.0",
            id: req.id,
            error: { code: -32001, message: `Role '${role}' lacks scope 'ops:ticket_read'.` },
          };
        }
        const statusFilter = typeof args.status === "string" ? args.status : undefined;
        const filtered = statusFilter
          ? this.incidents.filter((i) => i.status === statusFilter)
          : this.incidents;
        return {
          jsonrpc: "2.0",
          id: req.id,
          result: { isError: false, structuredContent: { count: filtered.length, items: filtered } },
        };
      }

      if (toolName === "ops_create_change_ticket") {
        if (!ROLE_SCOPES[role]?.has("ops:ticket_create")) {
          return {
            jsonrpc: "2.0",
            id: req.id,
            error: { code: -32001, message: `Role '${role}' lacks scope 'ops:ticket_create'.` },
          };
        }
        const title = String(args.title ?? "").trim();
        const service = String(args.service ?? "").trim();
        if (title.length < 5 || service.length < 2) {
          return {
            jsonrpc: "2.0",
            id: req.id,
            error: { code: -32602, message: "Both 'title' (>=5 chars) and 'service' are required." },
          };
        }
        this.ticketCounter += 1;
        const ticket: ChangeTicket = {
          ticket_id: `CHG-${this.ticketCounter}`,
          title,
          service,
          requires_hitl_approval: true,
          created_by: callerId,
          status: "pending_approval",
        };
        this.tickets.push(ticket);
        return {
          jsonrpc: "2.0",
          id: req.id,
          result: { isError: false, structuredContent: ticket },
        };
      }

      return {
        jsonrpc: "2.0",
        id: req.id,
        error: { code: -32602, message: `Unknown tool: '${toolName}'` },
      };
    }

    return {
      jsonrpc: "2.0",
      id: req.id,
      error: { code: -32601, message: `Method not found: '${req.method}'` },
    };
  }
}
