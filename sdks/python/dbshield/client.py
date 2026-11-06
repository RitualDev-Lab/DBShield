"""
DBShield Client & Wire Proxy Helper
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional


class DBShieldClient:
    """
    Client interface communicating with local or remote DBShield gateways,
    fetching live approval requests, and querying audit ledgers.
    """

    def __init__(self, base_url: str = "http://127.0.0.1:3100", api_key: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def _request(self, endpoint: str, method: str = "GET", data: Optional[Dict[str, Any]] = None) -> Any:
        url = f"{self.base_url}{endpoint}"
        headers = {"User-Agent": "DBShield-Python-SDK/0.2.0"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        body = None
        if data is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(data).encode("utf-8")

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw = resp.read().decode("utf-8")
            return json.loads(raw) if raw else None

    def get_status(self) -> Dict[str, Any]:
        """Inspects live gateway status, dialect, and security tier."""
        try:
            return self._request("/api/v1/status") or {}
        except Exception:
            return {
                "status": "OFFLINE",
                "version": "0.2.0",
                "proxyPort": 5433,
                "safetyTier": "BALANCED",
            }

    def get_approvals(self) -> List[Dict[str, Any]]:
        """Fetches pending two-phase mutation approvals."""
        try:
            res = self._request("/api/v1/approvals")
            return res.get("approvals", []) if isinstance(res, dict) else []
        except Exception:
            return []

    def approve_mutation(self, approval_id: str) -> bool:
        """Approves a pending agent mutation."""
        try:
            res = self._request(f"/api/v1/approvals/{approval_id}/approve", method="POST")
            return bool(res and res.get("success"))
        except Exception:
            return False

    def reject_mutation(self, approval_id: str) -> bool:
        """Rejects a pending agent mutation."""
        try:
            res = self._request(f"/api/v1/approvals/{approval_id}/reject", method="POST")
            return bool(res and res.get("success"))
        except Exception:
            return False

    @staticmethod
    def get_proxy_connection_url(
        upstream_url: str, proxy_host: str = "127.0.0.1", proxy_port: int = 5433
    ) -> str:
        """
        Translates a production PostgreSQL connection string into a DBShield
        transparent wire proxy URL.
        Example:
          postgres://user:pass@db.internal:5432/app
          -> postgres://user:pass@127.0.0.1:5433/app
        """
        parsed = urllib.parse.urlparse(upstream_url)
        netloc_parts = []
        if parsed.username:
            userinfo = parsed.username
            if parsed.password:
                userinfo += f":{parsed.password}"
            netloc_parts.append(f"{userinfo}@")
        netloc_parts.append(f"{proxy_host}:{proxy_port}")
        return urllib.parse.urlunparse(
            (parsed.scheme, "".join(netloc_parts), parsed.path, parsed.params, parsed.query, parsed.fragment)
        )
