---
name: db-shield
description: Safety-first Database Guardrail & Sandboxing MCP Server for AI Coding Agents. Protects relational databases from destructive mutations, drops, locks, and PII leaks.
version: 0.2.0
author: RitualDev Lab
license: MIT
---

# 🛡️ DBShield AI Skill

This skill equips autonomous AI coding agents (Antigravity, Claude Code, Cursor, Windsurf, Codex) with safety-first database guardrails, two-phase dry-run execution, virtual schema masking, and real-time PII sanitization.

## Directives for AI Agents

When interacting with databases, generating SQL, or executing migrations:

1. **Always Use Two-Phase Mutation (`db_dry_run` before `db_commit`)**:
   - NEVER execute unconstrained `UPDATE`, `DELETE`, or DDL statements directly against production or staging databases.
   - First invoke `db_dry_run` to inspect simulated row impacts and obtain a cryptographic commit token:
     ```json
     {
       "tool": "db_dry_run",
       "arguments": {
         "query": "UPDATE users SET status = 'active' WHERE id = 42"
       }
     }
     ```
   - Only execute `db_commit` using the verified `commit_token` returned by `db_dry_run`.

2. **Never Write Tautological Queries**:
   - Avoid `WHERE 1=1`, `WHERE 'a'='a'`, or self-referential conditions (`WHERE id = id`).
   - DBShield's AST Tautology Trap intercepts and blocks these queries as critical violations.

3. **Validate Migrations Before Applying**:
   - Always validate DDL scripts with `db_validate_migration` to check for unindexed foreign keys, table locks, and zero-downtime safety plans.

4. **Adhere to Virtual Schema Masking**:
   - Internal tables (`credentials`, `api_keys`, `admin_sessions`) and restricted columns are automatically masked from agent introspection. Do not attempt to query system catalogs (`information_schema`, `pg_catalog`) to bypass masking.

## 🚀 CLI Commands & Quickstart

```bash
# Launch MCP Server on stdio (for Claude Desktop / Cursor / Antigravity)
npx @ritualdev-lab/dbshield start

# Launch PostgreSQL wire proxy on port 5433
npx @ritualdev-lab/dbshield proxy --port 5433

# Launch live query approval dashboard
npx @ritualdev-lab/dbshield dashboard --port 3100

# Generate SOC 2 compliance audit report
npx @ritualdev-lab/dbshield report --compliance soc2 --audit-pdf audit.pdf

# Auto-configure Claude Desktop
npx @ritualdev-lab/dbshield install-claude

# Auto-configure Cursor IDE
npx @ritualdev-lab/dbshield install-cursor
```

## 🛸 Antigravity & MCP Configuration

Add DBShield to your agent configuration (`mcp.json` or `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "dbshield": {
      "command": "npx",
      "args": ["-y", "@ritualdev-lab/dbshield", "start"],
      "env": {
        "DBSHIELD_DIALECT": "sqlite",
        "DBSHIELD_STORAGE": "./dev.db",
        "DBSHIELD_TIER": "BALANCED"
      }
    }
  }
}
```
