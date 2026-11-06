"""
LlamaIndex NLSQLTableQueryEngine Transform Guardrail
"""

from __future__ import annotations

from typing import Any, Optional
from ..guard import DBShieldGuard, DBShieldSecurityViolation
from ..pii import PiiRedactor


class DBShieldLlamaIndexTransform:
    """
    Transforms LlamaIndex natural language generated SQL statements,
    validating safety before execution and sanitizing returned response text.
    """

    def __init__(
        self,
        safety_tier: str = "BALANCED",
        guard: Optional[DBShieldGuard] = None,
        redactor: Optional[PiiRedactor] = None,
    ):
        self.guard = guard or DBShieldGuard(safety_tier=safety_tier)
        self.redactor = redactor or PiiRedactor()

    def filter_query(self, sql_query: str) -> str:
        """Inspects generated SQL; raises exception if dangerous."""
        eval_result = self.guard.validate_query(sql_query)
        if not eval_result.allowed:
            reason = eval_result.violations[0].message if eval_result.violations else "Prohibited by DBShield"
            raise DBShieldSecurityViolation(f"[DBShield Block] {reason}", eval_result.violations)
        return sql_query

    def sanitize_response(self, response_text: str) -> str:
        """Sanitizes PII in final LLM response text."""
        return self.redactor.redact_text(response_text)
