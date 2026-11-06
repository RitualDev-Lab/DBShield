"""
Dynamic Zero-Leak PII & Credential Masking Engine (Python Implementation)
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Union


class PiiRedactor:
    """
    Scans and sanitizes outgoing tabular data cells and SQL logs, replacing
    sensitive personal data (SSNs, credit cards, emails) and high-entropy credentials
    with deterministic surrogate tokens before streaming to LLM inference contexts.
    """

    SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    PHONE_PATTERN = re.compile(r"\b(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b")
    CC_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
    SECRET_PATTERN = re.compile(r"\b(?:sk-[a-zA-Z0-9_\-]{20,}|ghp_[a-zA-Z0-9]{30,}|AKIA[0-9A-Z]{16}|ey[A-Za-z0-9_\-]{20,}\.ey[A-Za-z0-9_\-]{20,})\b")

    def __init__(self, salt: str = "dbshield-salt"):
        self.salt = salt

    def _hash_token(self, val: str) -> str:
        h = hashlib.sha256(f"{self.salt}:{val}".encode("utf-8")).hexdigest()
        return h[:6]

    def _luhn_check(self, card_number: str) -> bool:
        """Validates credit card checksum using the Luhn formula."""
        digits = [int(c) for c in card_number if c.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        checksum = 0
        reverse_digits = digits[::-1]
        for i, digit in enumerate(reverse_digits):
            if i % 2 == 1:
                doubled = digit * 2
                checksum += doubled - 9 if doubled > 9 else doubled
            else:
                checksum += digit
        return checksum % 10 == 0

    def redact_text(self, text: str) -> str:
        """Redacts sensitive values within a plaintext string."""
        if not text:
            return text

        # 1. Mask Secrets (API Keys, Bearer Tokens)
        def replace_secret(m):
            val = m.group(0)
            return f"[REDACTED:SECRET:{self._hash_token(val)}]"

        text = self.SECRET_PATTERN.sub(replace_secret, text)

        # 2. Mask SSN
        def replace_ssn(m):
            val = m.group(0)
            return f"[REDACTED:SSN:{self._hash_token(val)}]"

        text = self.SSN_PATTERN.sub(replace_ssn, text)

        # 3. Mask Credit Cards (Only if valid Luhn)
        def replace_cc(m):
            val = m.group(0)
            clean = re.sub(r"\D", "", val)
            if self._luhn_check(clean):
                return f"[REDACTED:CC:{self._hash_token(clean)}]"
            return val

        text = self.CC_PATTERN.sub(replace_cc, text)

        # 4. Mask Email
        def replace_email(m):
            val = m.group(0)
            parts = val.split("@")
            user = parts[0]
            domain = parts[1]
            masked_user = user[0] + "***" + (user[-1] if len(user) > 1 else "")
            dom_parts = domain.split(".")
            masked_dom = dom_parts[0][0] + "****" + dom_parts[0][-1] + "." + ".".join(dom_parts[1:])
            return f"{masked_user}@{masked_dom}"

        text = self.EMAIL_PATTERN.sub(replace_email, text)

        return text

    def redact_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Redacts dictionary record key-value pairs."""
        redacted = {}
        for k, v in record.items():
            k_lower = k.lower()
            if isinstance(v, str):
                if any(sec in k_lower for sec in ("password", "token", "secret", "hash", "jwt", "key")):
                    redacted[k] = f"[REDACTED:CREDENTIAL:{self._hash_token(v)}]"
                elif any(sec in k_lower for sec in ("ssn", "social_security")):
                    redacted[k] = f"[REDACTED:SSN:{self._hash_token(v)}]"
                else:
                    redacted[k] = self.redact_text(v)
            else:
                redacted[k] = v
        return redacted

    def redact_rows(self, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Redacts an entire tabular row set."""
        return [self.redact_record(r) for r in rows]
