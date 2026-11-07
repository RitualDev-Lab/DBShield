"""
DBShield Python SDK
Database Guardrail, SQL AST Firewall & Sandboxing Wire Proxy for AI Coding Agents
"""

from .guard import (
    DBShieldGuard,
    DBShieldSecurityViolation,
    EvaluationResult,
    Violation,
)
from .pii import PiiRedactor
from .sandbox import TwoPhaseSandboxEngine
from .client import DBShieldClient
from .middleware import attach_dbshield, DBShieldConnectionWrapper
from .integrations.langchain import DBShieldSQLDatabase, DBShieldQueryTool
from .integrations.crewai import DBShieldDatabaseTool
from .integrations.llamaindex import DBShieldLlamaIndexTransform

__version__ = "0.2.1"

__all__ = [
    "DBShieldGuard",
    "DBShieldSecurityViolation",
    "EvaluationResult",
    "Violation",
    "PiiRedactor",
    "TwoPhaseSandboxEngine",
    "DBShieldClient",
    "attach_dbshield",
    "DBShieldConnectionWrapper",
    "DBShieldSQLDatabase",
    "DBShieldQueryTool",
    "DBShieldDatabaseTool",
    "DBShieldLlamaIndexTransform",
]
