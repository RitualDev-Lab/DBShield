<div align="center">

# 🛡️ DBShield

**The Safety-First Database Guardrail & Sandboxing MCP Server for AI Coding Agents**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![MCP Protocol](https://img.shields.io/badge/MCP-Protocol%201.0-8A2BE2.svg)](https://modelcontextprotocol.io/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8%2B-blue)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D20.0-green.svg)](https://nodejs.org/)
[![Biome](https://img.shields.io/badge/Code%20Style-Biome-60a5fa.svg)](https://biomejs.dev)

*Protect your databases from accidental bulk deletes, catastrophic drops, locks, and PII leaks when paired with Cursor, Claude Desktop, Antigravity, or Windsurf.*

</div>

---

## ⚡ The Problem: AI Agents Writing Raw SQL

When autonomous AI coding agents interact directly with databases:
1. **Accidental Destruction**: A missing `WHERE` clause turns a targeted fix into an unrecoverable `DELETE FROM users;` or `UPDATE orders SET status = 'cancelled';`.
2. **Catastrophic DDL**: Agents dropping staging or production tables (`DROP TABLE`, `TRUNCATE`) instead of running non-destructive migrations.
3. **PII & Credential Leaks**: Customer emails, passwords, SSNs, and API keys are streamed in plaintext directly into model contexts and chat transcripts.
4. **Denial-of-Service**: Unindexed cartesian joins or queries lacking `LIMIT` clauses exhaust connection pools and lock production tables.

**DBShield sits between your AI Agent and your Database as an intelligent, zero-overhead safety firewall.**

---

## 🚀 Key Capabilities

- 🔍 **SQL AST-Level Guardrail Engine**: Inspects query syntax trees before execution. Intercepts dangerous mutations, tautologies (`WHERE 1=1`), and unconstrained deletes.
- 🧪 **Dry-Run Auto-Rollback Sandboxing**: Executes writes in an isolated transaction block (`BEGIN ... ROLLBACK`). Previews exact row impacts without altering the real database state.
- 🔒 **Dynamic Zero-Leak PII Masking**: Automatically detects sensitive fields (passwords, emails, phone numbers, tokens) and masks them before streaming back to LLM context.
- 📐 **Safe Schema Introspection**: Exposes rich table definitions, foreign keys, and indexes without exposing data rows.
- 🎛️ **Granular Safety Tiers**: Choose between `STRICT` (read-only / 1-row limits), `BALANCED` (production guardrails), or `PERMISSIVE` (custom rules).
- 🔌 **Universal MCP Protocol**: Drop-in compatible with Claude Desktop, Cursor, Antigravity, Windsurf, and custom Agent frameworks.

---

## 📦 Quickstart

### 1. Claude Desktop Setup
Add DBShield to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "dbshield": {
      "command": "npx",
      "args": ["-y", "@ritualdev-lab/dbshield", "start"],
      "env": {
        "DBSHIELD_DIALECT": "sqlite",
        "DBSHIELD_STORAGE_PATH": "./dev.db",
        "DBSHIELD_SAFETY_TIER": "BALANCED"
      }
    }
  }
}
```

### 2. Cursor IDE Setup
Add DBShield to your `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "dbshield": {
      "command": "npx",
      "args": ["-y", "@ritualdev-lab/dbshield", "start"]
    }
  }
}
```

### 3. Terminal CLI
```bash
# Check status and inspect connected database
npx @ritualdev-lab/dbshield status

# Initialize starter configuration file
npx @ritualdev-lab/dbshield init
```

---

## ⚙️ Configuration (`dbshield.config.json`)

```json
{
  "$schema": "https://raw.githubusercontent.com/RitualDev-Lab/DBShield/main/schema.json",
  "dialect": "sqlite",
  "storagePath": "./dev.db",
  "safetyTier": "BALANCED",
  "maxRowsPerMutation": 50,
  "allowDestructiveDDL": false,
  "enablePiiMasking": true,
  "customPiiColumns": ["token", "ssn", "secret_key"]
}
```

### Safety Tiers

| Tier | Mutation Limit | Destructive DDL | Dry-Run Required | PII Masking | Best For |
|---|---|---|---|---|---|
| `STRICT` | Max 1 row | ❌ Blocked | ✅ Always Required | 🔒 Enforced | Production, Staging |
| `BALANCED` | Max 50 rows | ❌ Blocked | ✅ On Bulk Writes | 🔒 Enforced | Local Dev, Team Collaboration |
| `PERMISSIVE`| Max 500 rows | ⚠️ Warned | Optional | Optional | Sandbox Benchmarks |

---

## 🛠️ MCP Tools Reference

| Tool | Description |
|---|---|
| `db_status` | Inspect gateway connectivity, active safety tier, and database statistics. |
| `db_describe_schema` | Safe introspection of tables, columns, constraints, and relations. |
| `db_query` | Safe read query execution with automatic PII redaction and row limits. *(Phase 2-4)* |
| `db_dry_run` | Test mutation inside an auto-rollback transaction with row delta preview. *(Phase 3)* |
| `db_commit` | Execute verified mutation accompanied by authorization token. *(Phase 3)* |

---

## 🗺️ Project Roadmap

- [x] **Phase 1: Architecture, Core Engine & Repository Scaffolding**
  - Node.js 22 + TypeScript + Biome configuration
  - Universal `DatabaseAdapter` interface & zero-config SQLite driver
  - `@modelcontextprotocol/sdk` Stdio server setup
  - Configuration manager & CLI entrypoint
- [x] **Phase 2: SQL AST Parser & Mutation Guardrail Engine**
  - AST-level query inspection with `node-sql-parser`
  - Destructive DDL blocker (`DROP TABLE`, `TRUNCATE`, `ALTER TABLE DROP COLUMN`)
  - Blind mutation protection (unconstrained `DELETE` / `UPDATE` without `WHERE`)
  - Boolean & constant tautology bypass detection (`1=1`, `WHERE true`, `OR 1=1`)
  - Multi-statement injection defense & safety tier scoring (`STRICT`, `BALANCED`, `PERMISSIVE`)
  - First-class `db_query` MCP tool with automated guardrail interception
- [x] **Phase 3: Dry-Run Sandbox & Auto-Rollback Transaction Engine**
  - Atomic transaction rollback sandbox (`BEGIN ... ROLLBACK`) with zero database mutation side-effects
  - Row-level blast radius estimation and `maxRowsPerMutation` threshold enforcement
  - Cryptographically signed HMAC-SHA256 two-phase commit tokens (`CommitTokenManager`)
  - Query hash tamper-proofing, short-lived TTLs, and replay attack prevention
  - First-class `db_dry_run` and `db_commit` MCP tools
- [ ] **Phase 4: Real-Time Dynamic PII Masking & Data Redaction**
- [ ] **Phase 5: Full MCP Tool Suite & Cursor/Claude Auto-Configurator**
- [ ] **Phase 6: Comprehensive Testing, CI/CD & npm Release**

---

## 📄 License
MIT © [RitualDev Lab](https://github.com/RitualDev-Lab)
