---
name: dbshield
title: DBShield
tagline: Safe database proxy with dry-run SQL, rollback simulation & PII masking for AI agents
description: Safety-first database guardrail and wire-protocol proxy MCP server for autonomous AI coding agents. Intercepts SQL mutations, simulates dry-run transaction impacts, explains unindexed query plans, masks sensitive PII columns, and prevents unauthorized drops or table truncations.
category: Developer Tools
use_cases:
  - Database Guardrails
  - AI Agent SQL Safety
  - Dry-Run Query Simulation
  - PII Masking & Data Privacy
  - Query Plan Analysis & Performance
getting_started:
  - "Safely execute query with dry-run check: db_query sql: SELECT * FROM users LIMIT 10"
  - "Simulate mutation impact: db_dry_run sql: UPDATE orders SET status = 'completed' WHERE id = 1"
  - "Explain SQL query execution plan: db_explain_query sql: SELECT * FROM items WHERE category = 'books'"
  - "Tool: db_query: Guarded SQL execution with AST validation, cost gate, row cap, and automatic PII redaction"
  - "Tool: db_dry_run: Lock-free shadow transaction simulation returning exact affected-row counts"
tags:
  - database
  - postgres
  - mysql
  - sqlite
  - sql
  - security
  - guardrails
  - mcp
  - ai-agents
  - cursor
documentation_url: https://ritualdev.in/dbshield
repository: https://github.com/RitualDev-Lab/DBShield
homepage: https://ritualdev.in/dbshield
npm: "@ritualdev-lab/dbshield"
transport: stdio
command: npx
args: ["-y", "@ritualdev-lab/dbshield", "mcp"]
pricing:
  type: freemium
  license: MIT
environment_variables:
  - name: DBSHIELD_DB_URL
    required: false
    docs_url: https://ritualdev.in/dbshield
    description: Connection URL or local file path for target Postgres, MySQL, or SQLite database.
  - name: DBSHIELD_DIALECT
    required: false
    docs_url: https://ritualdev.in/dbshield
    description: Target database dialect (postgres, mysql, sqlite). Defaults to sqlite.
  - name: DBSHIELD_ENFORCE_DRY_RUN
    required: false
    docs_url: https://ritualdev.in/dbshield
    description: Set to 'true' to block any destructive SQL mutations without explicit pre-image approval.
---

# DBShield MCP Server

**DBShield** is a database guardrail and wire proxy MCP server designed specifically for autonomous AI coding agents (Claude Desktop, Cursor, Windsurf).

## Setup Requirements

| Variable Name | Required | Docs URL | Description |
|---|---|---|---|
| `DBSHIELD_DB_URL` | No | `https://ritualdev.in/dbshield` | Connection URL or file path for target Postgres, MySQL, or SQLite database. |
| `DBSHIELD_DIALECT` | No | `https://ritualdev.in/dbshield` | Target dialect (`postgres`, `mysql`, `sqlite`). Defaults to `sqlite`. |
| `DBSHIELD_ENFORCE_DRY_RUN` | No | `https://ritualdev.in/dbshield` | Enforces shadow transaction dry-runs before committing mutations. |

## Quick Installation

```json
{
  "mcpServers": {
    "dbshield": {
      "command": "npx",
      "args": ["-y", "@ritualdev-lab/dbshield", "mcp"],
      "env": {
        "DBSHIELD_DIALECT": "postgres",
        "DBSHIELD_DB_URL": "postgresql://user:password@localhost:5432/mydb"
      }
    }
  }
}
```

## Exposed Tools

1. `db_query`: Guarded SQL execution with AST validation, cost gate, row cap, and automatic PII redaction.
2. `db_dry_run`: Lock-free shadow transaction simulation returning exact affected-row counts and single-use commit tokens.
3. `db_explain_query`: Query plan analyzer flagging unindexed sequential scans and proposing index DDL.
4. `db_check_semantic_intent`: Verifies agent stated intent against targeted sensitive columns.
5. `db_audit_log`: Queries the tamper-evident, PII-redacted HMAC audit ledger.
