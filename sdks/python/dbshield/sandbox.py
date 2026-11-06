"""
Two-Phase Distributed Dry-Run & Shadow Database Simulator (Python Implementation)
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Optional, Tuple


class TwoPhaseSandboxEngine:
    """
    Coordinates isolated transaction rollback dry-runs (BEGIN ... ROLLBACK)
    and mints tamper-evident HMAC-SHA256 commit tokens.
    """

    def __init__(self, secret_key: str = "dbshield-enterprise-2pc-key"):
        self.secret_key = secret_key.encode("utf-8")
        self.used_tokens = set()

    def issue_commit_token(self, query: str, affected_rows: int, ttl_seconds: int = 300) -> str:
        """Issues a cryptographic two-phase commit token with bound affected rows and expiration."""
        expires_at = int(time.time()) + ttl_seconds
        payload = f"{query.strip()}|{affected_rows}|{expires_at}"
        sig = hmac.new(self.secret_key, payload.encode("utf-8"), hashlib.sha256).hexdigest()[:16]
        return f"2pc_tok_{expires_at}_{affected_rows}_{sig}"

    def verify_commit_token(self, token: str, query: str) -> bool:
        """Verifies integrity, query binding, and expiration of a two-phase commit token."""
        if token in self.used_tokens:
            return False  # Replay attack prevention

        parts = token.split("_")
        if len(parts) != 5 or parts[0] != "2pc" or parts[1] != "tok":
            return False

        try:
            expires_at = int(parts[2])
            affected_rows = int(parts[3])
            sig = parts[4]
        except ValueError:
            return False

        if time.time() > expires_at:
            return False  # Expired token

        expected_payload = f"{query.strip()}|{affected_rows}|{expires_at}"
        expected_sig = hmac.new(self.secret_key, expected_payload.encode("utf-8"), hashlib.sha256).hexdigest()[:16]

        if hmac.compare_digest(sig, expected_sig):
            self.used_tokens.add(token)
            return True
        return False

    def simulate_sqlite_mutation(self, conn, query: str) -> Tuple[int, str]:
        """
        Executes a mutation in an isolated transaction rollback block on a sqlite3 connection.
        Returns (affected_rows, commit_token).
        """
        cursor = conn.cursor()
        try:
            cursor.execute("BEGIN;")
            cursor.execute(query)
            affected_rows = cursor.rowcount
            cursor.execute("ROLLBACK;")
            token = self.issue_commit_token(query, affected_rows)
            return affected_rows, token
        except Exception:
            try:
                cursor.execute("ROLLBACK;")
            except Exception:
                pass
            raise
