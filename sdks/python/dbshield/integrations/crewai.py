"""
CrewAI Database Tool Guardrail Integration
"""

from __future__ import annotations

import sqlite3
from typing import Any, Optional
from ..guard import DBShieldGuard, DBShieldSecurityViolation
from ..pii import PiiRedactor


class DBShieldDatabaseTool:
    """
    CrewAI tool providing database access to autonomous agents while
    intercepting tautologies, destructive DDL, and redacting customer PII.
    """

    name: str = "Database Security Query Tool"
    description: str = "Safely query databases without risk of table drops or accidental bulk data deletion."

    def __init__(
        self,
        database_url: str = "sqlite:///app.db",
        safety_tier: str = "BALANCED",
        guard: Optional[DBShieldGuard] = None,
        redactor: Optional[PiiRedactor] = None,
    ):
        self.database_url = database_url
        self.guard = guard or DBShieldGuard(safety_tier=safety_tier)
        self.redactor = redactor or PiiRedactor()

    def run(self, query: str) -> str:
        """Executes a query through DBShield guardrails."""
        eval_result = self.guard.validate_query(query)
        if not eval_result.allowed:
            reason = eval_result.violations[0].message if eval_result.violations else "Blocked by DBShield"
            return f"❌ [DBShield Blocked]: {reason}"

        # If SQLite path
        if self.database_url.startswith("sqlite:///"):
            path = self.database_url.replace("sqlite:///", "")
            conn = sqlite3.connect(path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            try:
                cursor.execute(query)
                if query.strip().upper().startswith("SELECT"):
                    rows = [dict(r) for r in cursor.fetchmany(50)]
                    clean_rows = self.redactor.redact_rows(rows)
                    return str(clean_rows)
                else:
                    conn.commit()
                    return f"✓ Query executed successfully. Rows affected: {cursor.rowcount}"
            except Exception as e:
                return f"Execution error: {e}"
            finally:
                conn.close()

        return "✓ Query validated by DBShield AST safety gate."
