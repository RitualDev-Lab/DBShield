"""
Unit & Integration Tests for DBShield Python SDK
"""

import sqlite3
import pytest
from dbshield import (
    DBShieldGuard,
    DBShieldSecurityViolation,
    PiiRedactor,
    TwoPhaseSandboxEngine,
    DBShieldClient,
    DBShieldConnectionWrapper,
)


def test_guard_allows_safe_select():
    guard = DBShieldGuard(safety_tier="BALANCED")
    res = guard.validate_query("SELECT id, name, email FROM users WHERE id = 42;")
    assert res.allowed is True
    assert res.operation == "SELECT"
    assert "users" in res.target_tables


def test_guard_blocks_destructive_ddl():
    guard = DBShieldGuard(allow_destructive_ddl=False)
    res_drop = guard.validate_query("DROP TABLE users;")
    assert res_drop.allowed is False
    assert any(v.code == "DESTRUCTIVE_DDL_PROHIBITED" for v in res_drop.violations)

    res_trunc = guard.validate_query("TRUNCATE TABLE accounts;")
    assert res_trunc.allowed is False


def test_guard_blocks_unconstrained_mutations():
    guard = DBShieldGuard()
    # No WHERE clause
    res_del = guard.validate_query("DELETE FROM orders;")
    assert res_del.allowed is False
    assert any(v.code == "UNCONSTRAINED_MUTATION" for v in res_del.violations)

    res_upd = guard.validate_query("UPDATE users SET status = 'inactive';")
    assert res_upd.allowed is False


def test_guard_blocks_tautology_bypasses():
    guard = DBShieldGuard()
    # WHERE 1=1
    res1 = guard.validate_query("DELETE FROM users WHERE 1=1;")
    assert res1.allowed is False
    assert any(v.code == "TAUTOLOGY_DETECTED" for v in res1.violations)

    # WHERE 'a'='a'
    res2 = guard.validate_query("UPDATE orders SET price = 0 WHERE 'a' = 'a';")
    assert res2.allowed is False

    # WHERE true
    res3 = guard.validate_query("DELETE FROM accounts WHERE true;")
    assert res3.allowed is False

    # WHERE col = col
    res4 = guard.validate_query("DELETE FROM sessions WHERE id = id;")
    assert res4.allowed is False


def test_guard_blocks_migration_lock_hazards():
    guard = DBShieldGuard()
    res = guard.validate_query("ALTER TABLE orders ADD COLUMN amount_cents INT NOT NULL;")
    assert res.allowed is False
    assert any(v.code == "LOCK_HAZARD_NOT_NULL_NO_DEFAULT" for v in res.violations)


def test_guard_blocks_virtual_schema_sensitive_tables():
    guard = DBShieldGuard(blocked_tables={"credentials", "api_keys"})
    res = guard.validate_query("SELECT * FROM credentials;")
    assert res.allowed is False
    assert any(v.code == "VIRTUAL_SCHEMA_RBAC_BLOCKED" for v in res.violations)


def test_pii_redactor():
    redactor = PiiRedactor(salt="test-salt")

    # SSN
    text = "User SSN is 123-45-6789 and email is user@domain.com."
    redacted = redactor.redact_text(text)
    assert "123-45-6789" not in redacted
    assert "[REDACTED:SSN:" in redacted
    assert "user@domain.com" not in redacted
    assert "u***r@d****n.com" in redacted

    # Secret key
    secret_text = "API token is sk-proj-123456789012345678901234567890"
    redacted_sec = redactor.redact_text(secret_text)
    assert "sk-proj-" not in redacted_sec
    assert "[REDACTED:SECRET:" in redacted_sec

    # Tabular rows
    rows = [
        {"id": 10, "password_hash": "$2b$12$e8Y72", "email": "admin@example.org"},
    ]
    cleaned = redactor.redact_rows(rows)
    assert "[REDACTED:CREDENTIAL:" in cleaned[0]["password_hash"]


def test_two_phase_sandbox_tokens():
    engine = TwoPhaseSandboxEngine(secret_key="my-super-secret-key")
    query = "UPDATE users SET active = 1 WHERE id = 5;"

    token = engine.issue_commit_token(query=query, affected_rows=1, ttl_seconds=60)
    assert token.startswith("2pc_tok_")

    # Valid verification
    assert engine.verify_commit_token(token, query) is True

    # Replay attack prevention
    assert engine.verify_commit_token(token, query) is False

    # Tampered query
    token2 = engine.issue_commit_token(query=query, affected_rows=1, ttl_seconds=60)
    assert engine.verify_commit_token(token2, "DELETE FROM users;") is False


def test_connection_wrapper_intercepts_sqlite():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE products (id INT, name TEXT);")
    conn.execute("INSERT INTO products VALUES (1, 'Widget');")
    conn.commit()

    safe_conn = DBShieldConnectionWrapper(conn)

    # Safe SELECT works
    cursor = safe_conn.cursor()
    cursor.execute("SELECT * FROM products WHERE id = 1;")
    rows = cursor.fetchall()
    assert len(rows) == 1

    # Unconstrained DELETE raises DBShieldSecurityViolation
    with pytest.raises(DBShieldSecurityViolation):
        cursor.execute("DELETE FROM products WHERE 1=1;")

    conn.close()


def test_client_proxy_url_translation():
    upstream = "postgres://admin:secret123@aurora-cluster.internal:5432/production_db"
    proxy_url = DBShieldClient.get_proxy_connection_url(upstream, proxy_host="127.0.0.1", proxy_port=5433)
    assert proxy_url == "postgres://admin:secret123@127.0.0.1:5433/production_db"
