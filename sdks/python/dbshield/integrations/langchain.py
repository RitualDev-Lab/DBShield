"""
LangChain SQLDatabase & Agent Tool Guardrail Integration
"""

from __future__ import annotations

from typing import Any, Optional
from ..guard import DBShieldGuard, DBShieldSecurityViolation
from ..pii import PiiRedactor


class DBShieldSQLDatabase:
    """
    Wraps LangChain's SQLDatabase utility with pre-execution AST safety gates
    and post-execution PII dynamic redaction.
    """

    def __init__(
        self,
        sql_database: Any,
        safety_tier: str = "BALANCED",
        guard: Optional[DBShieldGuard] = None,
        redactor: Optional[PiiRedactor] = None,
    ):
        self._db = sql_database
        self.guard = guard or DBShieldGuard(safety_tier=safety_tier)
        self.redactor = redactor or PiiRedactor()

    def run(self, command: str, *args, **kwargs) -> Any:
        """Validates query safety and masks PII before returning data to LLM."""
        eval_result = self.guard.validate_query(command)
        if not eval_result.allowed:
            reason = eval_result.violations[0].message if eval_result.violations else "Prohibited by DBShield"
            raise DBShieldSecurityViolation(f"[DBShield Block] {reason}", eval_result.violations)

        raw_result = self._db.run(command, *args, **kwargs)

        if isinstance(raw_result, str):
            return self.redactor.redact_text(raw_result)
        if isinstance(raw_result, list):
            if raw_result and isinstance(raw_result[0], dict):
                return self.redactor.redact_rows(raw_result)
            return raw_result
        return raw_result

    def __getattr__(self, name: str):
        return getattr(self._db, name)


class DBShieldQueryTool:
    """LangChain BaseTool compatible safe SQL execution tool."""

    name = "dbshield_sql_db_query"
    description = "Execute a SQL query against the database with safety guardrails against drops, unconstrained mutations, and PII leaks."

    def __init__(self, db: DBShieldSQLDatabase):
        self.db = db

    def _run(self, query: str) -> str:
        try:
            res = self.db.run(query)
            return str(res)
        except DBShieldSecurityViolation as e:
            return f"Error: Database mutation blocked by DBShield safety guardrail: {e}"

    def run(self, query: str) -> str:
        return self._run(query)
