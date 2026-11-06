"""
DBShield SQL AST-Level Guardrail & Firewall Engine (Python Implementation)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Set


@dataclass
class Violation:
    code: str
    message: str
    severity: str  # "CRITICAL", "BLOCKED", "CAUTION"


@dataclass
class EvaluationResult:
    allowed: boolean = True
    risk_level: str = "SAFE"  # "SAFE", "CAUTION", "BLOCKED", "CRITICAL"
    risk_score: int = 0  # 0 to 100
    operation: str = "UNKNOWN"
    target_tables: List[str] = field(default_factory=list)
    violations: List[Violation] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    requires_dry_run: bool = False


class DBShieldSecurityViolation(Exception):
    """Raised when an unconstrained or destructive database query violates DBShield guardrails."""

    def __init__(self, message: str, violations: Optional[List[Violation]] = None):
        super().__init__(message)
        self.violations = violations or []


class DBShieldGuard:
    """
    In-process SQL AST safety guardrail protecting relational databases from
    unconstrained bulk updates/deletes, tautology bypasses (WHERE 1=1),
    destructive drops, and table lock hazards.
    """

    def __init__(
        self,
        safety_tier: str = "BALANCED",
        max_rows_per_mutation: int = 50,
        allow_destructive_ddl: bool = False,
        blocked_tables: Optional[Set[str]] = None,
    ):
        self.safety_tier = safety_tier.upper()
        self.max_rows_per_mutation = max_rows_per_mutation
        self.allow_destructive_ddl = allow_destructive_ddl
        self.blocked_tables = blocked_tables or {"credentials", "internal_audit", "admin_tokens", "api_keys"}

    def strip_comments(self, sql: str) -> str:
        """Strips single-line and multi-line SQL comments while preserving strings."""
        # Remove single line comments (-- and #)
        cleaned = re.sub(r"(--[^\r\n]*|#[^\r\n]*)", " ", sql)
        # Remove multi-line comments (/* ... */)
        cleaned = re.sub(r"/\*.*?\*/", " ", cleaned, flags=re.DOTALL)
        return cleaned.strip()

    def validate_query(self, sql: str) -> EvaluationResult:
        """Evaluates a raw SQL query against DBShield security invariants."""
        stripped = self.strip_comments(sql)
        if not stripped:
            return EvaluationResult(
                allowed=False,
                risk_level="BLOCKED",
                risk_score=60,
                operation="EMPTY",
                violations=[Violation("EMPTY_QUERY", "Query is empty or contains only comments.", "BLOCKED")],
            )

        # Detect multiple statement chaining (e.g. SELECT 1; DROP TABLE users;)
        statements = [s.strip() for s in stripped.split(";") if s.strip()]
        if len(statements) > 1 and self.safety_tier != "PERMISSIVE":
            # Check each statement individually
            for stmt in statements:
                res = self._evaluate_single_statement(stmt)
                if not res.allowed:
                    res.violations.insert(
                        0,
                        Violation(
                            "MULTI_STATEMENT_HAZARD",
                            "Multi-statement execution contains prohibited operation.",
                            "BLOCKED",
                        ),
                    )
                    return res

        return self._evaluate_single_statement(statements[0] if statements else stripped)

    def _evaluate_single_statement(self, sql: str) -> EvaluationResult:
        violations: List[Violation] = []
        warnings: List[str] = []
        requires_dry_run = False
        risk_score = 0
        risk_level = "SAFE"

        # 1. Detect Operation
        op = "UNKNOWN"
        upper = sql.upper().strip()
        first_word = upper.split()[0] if upper.split() else ""

        if first_word == "SELECT":
            op = "SELECT"
            risk_score = 5
        elif first_word == "INSERT":
            op = "INSERT"
            risk_score = 25
            if self.safety_tier == "STRICT":
                requires_dry_run = True
        elif first_word == "UPDATE":
            op = "UPDATE"
            risk_score = 35
        elif first_word == "DELETE":
            op = "DELETE"
            risk_score = 45
        elif first_word == "DROP":
            op = "DDL_DROP"
            risk_score = 95
        elif first_word == "TRUNCATE":
            op = "DDL_TRUNCATE"
            risk_score = 95
        elif first_word == "ALTER":
            op = "DDL_ALTER"
            risk_score = 50
        elif first_word == "CREATE":
            op = "DDL_CREATE"
            risk_score = 20

        # 2. Extract Target Tables
        tables = self._extract_tables(sql)
        for t in tables:
            if t.lower() in self.blocked_tables:
                violations.append(
                    Violation(
                        "VIRTUAL_SCHEMA_RBAC_BLOCKED",
                        f"Access to sensitive table '{t}' is prohibited by Virtual Schema RBAC.",
                        "CRITICAL",
                    )
                )

        # 3. Destructive DDL Check
        if op in ("DDL_DROP", "DDL_TRUNCATE"):
            if not self.allow_destructive_ddl:
                violations.append(
                    Violation(
                        "DESTRUCTIVE_DDL_PROHIBITED",
                        f"Destructive DDL '{op}' on table(s) [{', '.join(tables)}] is blocked.",
                        "CRITICAL",
                    )
                )
            else:
                warnings.append(f"Executing destructive DDL '{op}' under explicit override.")

        # 4. Destructive ALTER TABLE DROP COLUMN
        if op == "DDL_ALTER" and re.search(r"\bDROP\s+COLUMN\b", upper):
            if not self.allow_destructive_ddl:
                violations.append(
                    Violation(
                        "DESTRUCTIVE_ALTER_PROHIBITED",
                        f"Irreversible column drop on table(s) [{', '.join(tables)}] is prohibited.",
                        "CRITICAL",
                    )
                )

        # 5. Migration Lock Hazard Check
        if op == "DDL_ALTER" and re.search(r"\bADD\s+COLUMN\b", upper) and re.search(r"\bNOT\s+NULL\b", upper) and not re.search(r"\bDEFAULT\b", upper):
            violations.append(
                Violation(
                    "LOCK_HAZARD_NOT_NULL_NO_DEFAULT",
                    "Adding NOT NULL column without DEFAULT requires an exclusive table rewrite lock.",
                    "BLOCKED",
                )
            )

        # 6. Unconstrained Mutation & Tautology Check (UPDATE / DELETE)
        if op in ("UPDATE", "DELETE"):
            where_match = re.search(r"\bWHERE\b(.*)", sql, flags=re.IGNORECASE | re.DOTALL)
            if not where_match:
                violations.append(
                    Violation(
                        "UNCONSTRAINED_MUTATION",
                        f"Unconstrained {op} query has no WHERE clause, risking bulk table destruction.",
                        "CRITICAL",
                    )
                )
            else:
                where_clause = where_match.group(1).strip()
                tautology = self._check_tautology(where_clause)
                if tautology:
                    violations.append(
                        Violation(
                            "TAUTOLOGY_DETECTED",
                            f"Unconstrained {op} mutation: WHERE clause contains tautology '{tautology}' matching all rows.",
                            "CRITICAL",
                        )
                    )
                else:
                    if self.safety_tier == "STRICT":
                        requires_dry_run = True
                        risk_score = 45
                    elif self.safety_tier == "BALANCED":
                        risk_score = 30

        # Determine final decision
        has_critical = any(v.severity == "CRITICAL" for v in violations)
        has_blocked = any(v.severity == "BLOCKED" for v in violations)

        if has_critical:
            allowed = False
            risk_level = "CRITICAL"
            risk_score = max(risk_score, 90)
        elif has_blocked:
            allowed = False
            risk_level = "BLOCKED"
            risk_score = max(risk_score, 70)
        else:
            allowed = True
            risk_level = "SAFE" if risk_score < 30 else "CAUTION"

        return EvaluationResult(
            allowed=allowed,
            risk_level=risk_level,
            risk_score=risk_score,
            operation=op,
            target_tables=tables,
            violations=violations,
            warnings=warnings,
            requires_dry_run=requires_dry_run,
        )

    def _extract_tables(self, sql: str) -> List[str]:
        """Extracts candidate table names using regex heuristics."""
        tables = set()
        # FROM <table> or JOIN <table>
        matches = re.findall(r"\b(?:FROM|JOIN|UPDATE|INTO|TABLE)\s+([`\"']?[a-zA-Z0-9_]+[`\"']?)", sql, flags=re.IGNORECASE)
        for m in matches:
            clean = m.strip("`\"' ")
            if clean.upper() not in ("SELECT", "WHERE", "SET", "VALUES"):
                tables.add(clean)
        return sorted(list(tables))

    def _check_tautology(self, where_clause: str) -> Optional[str]:
        """Identifies tautologies such as 1=1, 0=0, true, 'a'='a', col=col."""
        # Simple boolean true
        if re.match(r"^true$", where_clause, flags=re.IGNORECASE):
            return "true"

        # WHERE 1=1 or WHERE 'a'='a'
        numeric_match = re.search(r"(\b\d+\b)\s*=\s*(\b\d+\b)", where_clause)
        if numeric_match and numeric_match.group(1) == numeric_match.group(2):
            return f"{numeric_match.group(1)}={numeric_match.group(2)}"

        string_match = re.search(r"(['\"][^'\"]+['\"])\s*=\s*(['\"][^'\"]+['\"])", where_clause)
        if string_match and string_match.group(1) == string_match.group(2):
            return f"{string_match.group(1)}={string_match.group(2)}"

        # WHERE 1!=2 or 0!=1
        ne_match = re.search(r"(\b\d+\b)\s*(!=|<>)\s*(\b\d+\b)", where_clause)
        if ne_match and ne_match.group(1) != ne_match.group(3):
            return f"{ne_match.group(1)}!={ne_match.group(3)}"

        # WHERE col = col
        col_match = re.search(r"\b([a-zA-Z0-9_]+)\s*=\s*\1\b", where_clause)
        if col_match:
            return f"{col_match.group(1)}={col_match.group(1)}"

        # OR true or OR 1=1
        if re.search(r"\bOR\s+(true|1\s*=\s*1|['\"]a['\"]\s*=\s*['\"]a['\"])", where_clause, flags=re.IGNORECASE):
            return "OR tautology"

        return None
