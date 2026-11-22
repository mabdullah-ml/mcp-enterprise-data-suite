import http from "node:http";
import {
  EnterpriseOpsMCPServer,
  type CallerRole,
  type JsonRpcRequest,
} from "./api_bridge_server.ts";

const server = new EnterpriseOpsMCPServer();
const port = Number(process.env.PORT ?? 8081);

const httpServer = http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok", server: "mcp-ops-bridge-server" }));
    return;
  }

  if (req.method === "POST" && req.url === "/mcp") {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      try {
        const rpc = JSON.parse(body) as JsonRpcRequest;
        const callerId = String(req.headers["x-caller-id"] ?? "agent");
        const roleHeader = String(req.headers["x-caller-role"] ?? "analyst") as CallerRole;
        const response = server.handleJsonRpc(rpc, callerId, roleHeader);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(response));
      } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid JSON-RPC payload" }));
      }
    });
    return;
  }

  res.writeHead(404);
  res.end();
});

httpServer.listen(port, () => {
  console.log(`mcp-ops-bridge-server listening on http://0.0.0.0:${port}`);
});
