"""Read-only SQL Analytics MCP Server with SQL guardrails and automatic PII redaction."""

from __future__ import annotations

import sqlite3
from typing import Any

from mcp_suite.security.governance import GovernanceController
from mcp_suite.security.pii_redactor import redact_payload
from mcp_suite.security.sql_guard import validate_and_clamp_sql

DEMO_SEED_SQL = """
CREATE TABLE IF NOT EXISTS customers (
    customer_id TEXT PRIMARY KEY,
    company_name TEXT NOT NULL,
    tier TEXT NOT NULL,
    contact_email TEXT NOT NULL,
    region TEXT NOT NULL,
    annual_contract_usd REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sla_incidents (
    incident_id TEXT PRIMARY KEY,
    service_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    latency_p99_ms INTEGER NOT NULL,
    resolved INTEGER NOT NULL
);

INSERT OR IGNORE INTO customers VALUES
    ('CUST-101', 'Kanto Precision Manufacturing', 'Enterprise', 'ops-lead@kanto-mfg.example', 'JP-East', 185000.0),
    ('CUST-102', 'Pacific Logistics Cloud', 'Enterprise', 'cto@pacific-log.example', 'APAC', 240000.0),
    ('CUST-103', 'Sakura BioPharma Labs', 'Strategic', 'compliance@sakura-bio.example', 'JP-East', 320000.0);

INSERT OR IGNORE INTO sla_incidents VALUES
    ('INC-501', 'rag-retrieval-api', 'SEV2', 920, 1),
    ('INC-502', 'hitl-worker-cloudrun', 'SEV3', 410, 1),
    ('INC-503', 'bedrock-embedding-sync', 'SEV2', 1480, 0);
"""


class SQLAnalyticsMCPServer:
    """Provides guarded read-only SQL inspection and querying over enterprise tables."""

    def __init__(
        self,
        governance: GovernanceController,
        db_path: str = ":memory:",
        max_rows: int = 200,
    ) -> None:
        self.governance = governance
        self.max_rows = max_rows
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(DEMO_SEED_SQL)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def list_tables(self, caller_id: str, role: str) -> dict[str, Any]:
        self.governance.authorize(caller_id, role, "sql.list_tables", "sql:read")
        rows = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        return {"tables": [r["name"] for r in rows]}

    def describe_table(self, table_name: str, caller_id: str, role: str) -> dict[str, Any]:
        self.governance.authorize(caller_id, role, "sql.describe_table", "sql:read")
        allowed_tables = self.list_tables(caller_id, role)["tables"]
        if table_name not in allowed_tables:
            raise ValueError(f"Unknown table '{table_name}'. Allowed: {allowed_tables}")
        cols = self._conn.execute(f'PRAGMA table_info("{table_name}")').fetchall()
        return {
            "table": table_name,
            "columns": [{"name": c["name"], "type": c["type"]} for c in cols],
        }

    def execute_readonly_sql(self, query: str, caller_id: str, role: str) -> dict[str, Any]:
        should_redact = self.governance.authorize(
            caller_id, role, "sql.execute_readonly_sql", "sql:read"
        )
        safe_sql = validate_and_clamp_sql(query, max_rows=self.max_rows)
        rows = [dict(r) for r in self._conn.execute(safe_sql).fetchall()]
        if should_redact:
            rows = redact_payload(rows)
        return {
            "executed_sql": safe_sql,
            "row_count": len(rows),
            "pii_redacted": should_redact,
            "rows": rows,
        }
