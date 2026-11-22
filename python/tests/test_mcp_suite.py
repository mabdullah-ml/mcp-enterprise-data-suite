"""Comprehensive tests for SQL guardrails, PII redaction, RBAC, hybrid KB, and MCP JSON-RPC."""

from __future__ import annotations

import unittest

from mcp_suite.protocol import EnterpriseMCPRouter
from mcp_suite.security.governance import GovernanceController
from mcp_suite.security.sql_guard import SQLGuardrailError, validate_and_clamp_sql


class TestEnterpriseMCPSuite(unittest.TestCase):
    def setUp(self) -> None:
        self.governance = GovernanceController(max_calls_per_minute=20)
        self.router = EnterpriseMCPRouter(governance=self.governance, db_path=":memory:")

    def tearDown(self) -> None:
        self.router.close()

    def test_sql_guardrail_blocks_ddl_dml_and_multistatement(self) -> None:
        dangerous_queries = [
            "DROP TABLE customers",
            "DELETE FROM customers WHERE customer_id = 'CUST-101'",
            "SELECT * FROM customers; DROP TABLE customers;",
            "SELECT * FROM customers /* bypass */ UNION UPDATE customers SET tier='X'",
            "PRAGMA table_info(customers)",
        ]
        for sql in dangerous_queries:
            with self.assertRaises(SQLGuardrailError, msg=f"Failed to block: {sql}"):
                validate_and_clamp_sql(sql)

    def test_sql_guardrail_clamps_excessive_limit_and_allows_cte(self) -> None:
        clamped = validate_and_clamp_sql("SELECT * FROM customers LIMIT 99999", max_rows=50)
        self.assertIn("LIMIT 50", clamped)

        cte = validate_and_clamp_sql(
            "WITH top_c AS (SELECT company_name FROM customers) SELECT * FROM top_c",
            max_rows=25,
        )
        self.assertTrue(cte.endswith("LIMIT 25"))

    def test_mcp_sql_tool_redacts_pii_for_analyst_and_allows_for_admin(self) -> None:
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "sql_execute_readonly",
                "arguments": {"query": "SELECT company_name, contact_email FROM customers"},
            },
        }
        analyst_res = self.router.handle_jsonrpc(req, caller_id="agent-1", role="analyst")
        content = analyst_res["result"]["structuredContent"]
        self.assertTrue(content["pii_redacted"])
        self.assertEqual(content["rows"][0]["contact_email"], "[REDACTED_EMAIL]")

        admin_res = self.router.handle_jsonrpc(req, caller_id="admin-1", role="admin")
        admin_content = admin_res["result"]["structuredContent"]
        self.assertFalse(admin_content["pii_redacted"])
        self.assertIn("@", admin_content["rows"][0]["contact_email"])

    def test_hybrid_vector_kb_search_ranks_relevant_documents_first(self) -> None:
        req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "kb_search",
                "arguments": {"query": "AWS Bedrock OpenSearch RAGAS faithfulness", "top_k": 2},
            },
        }
        res = self.router.handle_jsonrpc(req, caller_id="agent-2", role="analyst")
        hits = res["result"]["structuredContent"]["results"]
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(hits[0]["doc_id"], "KB-RAG-02")
        self.assertEqual(hits[0]["owner_contact"], "[REDACTED_EMAIL]")

    def test_mcp_protocol_initialize_list_and_rate_limiting(self) -> None:
        init_res = self.router.handle_jsonrpc({"jsonrpc": "2.0", "id": 10, "method": "initialize"})
        self.assertEqual(init_res["result"]["serverInfo"]["name"], "mcp-enterprise-data-suite")

        tools_res = self.router.handle_jsonrpc({"jsonrpc": "2.0", "id": 11, "method": "tools/list"})
        tool_names = [t["name"] for t in tools_res["result"]["tools"]]
        self.assertIn("sql_execute_readonly", tool_names)
        self.assertIn("kb_search", tool_names)

        tight_router = EnterpriseMCPRouter(
            governance=GovernanceController(max_calls_per_minute=2), db_path=":memory:"
        )
        try:
            call = {
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {"name": "sql_list_tables", "arguments": {}},
            }
            self.assertIn("result", tight_router.handle_jsonrpc(call, caller_id="bot", role="analyst"))
            self.assertIn("result", tight_router.handle_jsonrpc(call, caller_id="bot", role="analyst"))
            blocked = tight_router.handle_jsonrpc(call, caller_id="bot", role="analyst")
            self.assertEqual(blocked["error"]["code"], -32001)
        finally:
            tight_router.close()


if __name__ == "__main__":
    unittest.main()
