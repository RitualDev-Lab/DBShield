# 03 — DBShield Configuration & CLI Reference

## Safety Tiers
- **`STRICT`**: Blocks unconstrained `DELETE`/`UPDATE`, destructive DDL (`DROP`/`TRUNCATE`), unindexed sequential scans, and requires explicit intent on sensitive columns.
- **`BALANCED`**: Allows safe reads and bounded mutations with dry-run simulation and PII masking enabled.
- **`PERMISSIVE`**: Audit logging and PII masking active with advisory warnings.

## Core CLI Commands

| Command | Description |
| :--- | :--- |
| `dbshield proxy` | Start transparent Postgres/MySQL wire-protocol guardrail proxy. |
| `dbshield mcp` | Start DBShield MCP stdio server for IDE agents. |
| `dbshield audit <dir>` | Scan repository SQL files/migrations for unsafe DDL or lock hazards. |
| `dbshield configure` | Auto-patch Claude Desktop, Cursor, or Antigravity MCP config. |
| `dbshield top` | Live terminal telemetry dashboard for intercepted queries. |
