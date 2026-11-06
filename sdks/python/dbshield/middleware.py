"""
DBShield Middleware & Database Driver Interceptors (SQLAlchemy & DB-API 2.0)
"""

from __future__ import annotations

from typing import Any, Optional
from .guard import DBShieldGuard, DBShieldSecurityViolation


def attach_dbshield(
    engine_or_connection: Any,
    guard: Optional[DBShieldGuard] = None,
    safety_tier: str = "BALANCED",
) -> None:
    """
    Attaches DBShield SQL AST guardrails to a SQLAlchemy Engine or Connection.
    Every query executed by an AI agent or application through this engine is
    automatically intercepted before hitting the database socket.
    """
    active_guard = guard or DBShieldGuard(safety_tier=safety_tier)

    try:
        from sqlalchemy import event

        def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
            eval_result = active_guard.validate_query(statement)
            if not eval_result.allowed:
                reason = eval_result.violations[0].message if eval_result.violations else "Blocked by DBShield guardrail"
                raise DBShieldSecurityViolation(
                    f"[DBShield Block] {reason} (Statement: {statement[:100]}...)",
                    eval_result.violations,
                )

        event.listen(engine_or_connection, "before_cursor_execute", before_cursor_execute)
    except ImportError:
        raise ImportError(
            "SQLAlchemy is required to use attach_dbshield on an engine. Install it with: pip install sqlalchemy"
        )


class DBShieldCursorWrapper:
    """Wraps a standard Python DB-API 2.0 cursor to enforce query safety."""

    def __init__(self, cursor: Any, guard: DBShieldGuard):
        self._cursor = cursor
        self._guard = guard

    def execute(self, operation: str, parameters: Any = None):
        res = self._guard.validate_query(operation)
        if not res.allowed:
            reason = res.violations[0].message if res.violations else "Blocked by DBShield"
            raise DBShieldSecurityViolation(f"[DBShield Block] {reason}", res.violations)
        return self._cursor.execute(operation, parameters) if parameters is not None else self._cursor.execute(operation)

    def executemany(self, operation: str, seq_of_parameters: Any):
        res = self._guard.validate_query(operation)
        if not res.allowed:
            reason = res.violations[0].message if res.violations else "Blocked by DBShield"
            raise DBShieldSecurityViolation(f"[DBShield Block] {reason}", res.violations)
        return self._cursor.executemany(operation, seq_of_parameters)

    def __getattr__(self, name: str):
        return getattr(self._cursor, name)


class DBShieldConnectionWrapper:
    """Wraps a DB-API 2.0 connection (e.g. sqlite3.Connection, psycopg2)."""

    def __init__(self, conn: Any, guard: Optional[DBShieldGuard] = None, safety_tier: str = "BALANCED"):
        self._conn = conn
        self._guard = guard or DBShieldGuard(safety_tier=safety_tier)

    def cursor(self, *args, **kwargs):
        real_cursor = self._conn.cursor(*args, **kwargs)
        return DBShieldCursorWrapper(real_cursor, self._guard)

    def execute(self, *args, **kwargs):
        cursor = self.cursor()
        return cursor.execute(*args, **kwargs)

    def __getattr__(self, name: str):
        return getattr(self._conn, name)
