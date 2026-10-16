<div align="center">

# 🛡️ DBShield

**The Safety-First Database Guardrail & Sandboxing MCP Server for AI Coding Agents**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![MCP Protocol](https://img.shields.io/badge/MCP-Protocol%201.0-8A2BE2.svg)](https://modelcontextprotocol.io/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8%2B-blue)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-%3E%3D22.0-green.svg)](https://nodejs.org/)
[![CI](https://github.com/RitualDev-Lab/DBShield/actions/workflows/ci.yml/badge.svg)](https://github.com/RitualDev-Lab/DBShield/actions/workflows/ci.yml)
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
### 1. Claude Desktop Setup (1-Click)
Run the auto-installer to configure your local Claude Desktop:

```bash
npx @ritualdev-lab/dbshield install-claude
```

Or manually add to `claude_desktop_config.json`:
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

### 2. Cursor IDE Setup (1-Click)
Run inside your workspace to create or update `.cursor/mcp.json`:

```bash
npx @ritualdev-lab/dbshield install-cursor
```

### 3. Terminal CLI & Status
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
| `db_query` | Safe read query execution with automatic PII redaction and row limits. |
| `db_dry_run` | Test mutation inside an auto-rollback transaction with row delta preview. |
| `db_commit` | Execute verified mutation accompanied by authorization token. |
| `db_explain_query` | Analyze query execution plans, detect unindexed full-table scans, and receive index hints. |
| `db_audit_log` | Retrieve compliance query audit trail, blocked operations, and risk scores. |

---

## 🛡️ Matrix of Supported SQL & Enforced Guarantees

DBShield enforces rigorous runtime guarantees across the SQL lifecycle. Guarantees are verified transactionally, ensuring mutations never exceed approved scope even if database state drifts:

| SQL Operation | Classification Mechanism | Static AST Guardrail | Execution Boundary & Rollback | Data Masking & Privacy |
|---|---|---|---|---|
| **SELECT** | Prepared-statement column reflection (`stmt.columns()`) | Detects missing `LIMIT` in STRICT tier; warns if limit exceeds server cap | Streaming iterator (`stmt.iterate()`) caps memory; truncates at `maxRowsPerRead` | Zero-leak dynamic PII masking on result rows |
| **WITH ... (CTE)** | Prepared-statement column reflection & recursive AST analysis | Recursively extracts underlying mutated tables & verifies read safety | Streaming iterator (`stmt.iterate()`) with hard read ceiling | Zero-leak dynamic PII masking on result rows |
| **UPDATE (Targeted)** | AST evaluation & tautology checker (`evaluateWhereClause`) | Blocks unconstrained updates, `WHERE 1=1`, `WHERE true`, tautological `OR` | Atomic transaction; rolls back if affected rows exceed `maxMutationRows` | Literal masking in logs & database errors |
| **DELETE (Targeted)** | AST evaluation & tautology checker (`evaluateWhereClause`) | Blocks unconstrained deletes, `WHERE 1=1`, tautological `OR` | Atomic transaction; rolls back if affected rows exceed `maxMutationRows` | Literal masking in logs & database errors |
| **INSERT** | AST evaluation & dialect parser | Pre-flight dry run simulation required under STRICT tier | Atomic transaction; rolls back if inserted rows exceed `maxMutationRows` | Redacts sensitive literals in `(cols) VALUES (vals)` |
| **DROP TABLE / TRUNCATE** | AST statement opcode inspection | **CRITICAL BLOCK**: Intercepted before database touch unless explicitly overridden | Direct execution blocked | Audit log records blocked attempt with high risk score |
| **ALTER TABLE DROP COLUMN** | AST expression visitor (`expr.action`) | **BLOCKED**: Intercepted before database touch to prevent schema data loss | Direct execution blocked | Audit log records blocked attempt |
| **EXPLAIN / PRAGMA** | Prepared-statement column reflection | Safe read-only inspection | Read capped at `maxRowsPerRead` | Sanitized output |

### Enforced Guarantees Breakdown

1. **Parameter-Bound Commit Invariance (B1)**:
   - Commit authorization tokens are cryptographically signed (HMAC-SHA256) binding the exact normalized SQL query text, typed parameters (`params`), database identity (`storagePath`), safety tier, and simulated affected row count.
   - Any query tampering, bound parameter alteration, or cross-database replay attempt is instantly rejected (`PARAMS_MISMATCH`, `QUERY_TAMPERED`).
2. **Hard Mutation Ceilings & Transactional Rollbacks (B2)**:
   - Exceeding `maxRowsPerMutation` is a hard safety limit across **all safety tiers** (`STRICT`, `BALANCED`, `PERMISSIVE`), immediately refusing dry-run authorization (`EXCESSIVE_BLAST_RADIUS`).
   - Mutations executed directly or committed through `db_commit` run inside an atomic transaction block: if actual row modifications exceed the authorized ceiling, DBShield immediately executes `ROLLBACK;` and aborts.
3. **Simulation Delta Drift Prevention (B2)**:
   - Protects against concurrent modifications between dry run and commit: if underlying database rows change such that actual affected rows differ from simulated rows (`simulatedAffectedRows != actualChanges`), DBShield rolls back the transaction with `[SIMULATION_DELTA_DRIFT]`.
4. **Audit Log & Error Message Sanitization (B3)**:
   - Raw SQL strings have sensitive literals (passwords, tokens, API keys, emails, phone numbers, SSNs, credit cards) masked before being written to disk or the in-memory circular buffer.
   - Database engine errors (e.g., SQLite constraint failures) are sanitized prior to returning to the agent or storing in audit records.
   - `db_audit_log` returns strictly sanitized compliance records.
5. **Memory-Safe Streaming Read Row Capping (B4)**:
   - SQLite row reads are streamed lazily using Node.js `stmt.iterate()`.
   - Results are capped at `maxRowsPerRead` without buffering the full dataset into Node.js heap memory, returning agent-friendly pagination metadata (`totalReturned`, `isTruncated`, `maxAllowedRows`, `hasMore`, `warning`).
6. **Robust Statement Classification & CTE Support (B5)**:
   - Replaced naive string prefix checks with SQLite prepared-statement column metadata (`stmt.columns() > 0`) and recursive AST extraction.
   - Complex CTEs (`WITH active AS (...) SELECT ...`) and leading single-line (`--`) or multi-line (`/* */`) comments are correctly classified and executed without error.

---

## 🔒 Production Deployment & Least-Privilege Guide

For production and shared environments, DBShield should be paired with database-level least privilege:

### 1. SQLite Filesystem Hardening
- **File Permissions**: Restrict database file permissions so only the DBShield process UID has access:
  ```bash
  chmod 600 /var/data/production.db
  chown dbshield:dbshield /var/data/production.db
  ```
- **Read-Only Connections**: For read-only agent workloads, mount SQLite with read-only flags or initialize with SQLite read-only mode:
  ```json
  {
    "storagePath": "file:/var/data/production.db?mode=ro",
    "safetyTier": "STRICT"
  }
  ```

### 2. Relational Database Least Privilege (PostgreSQL / MySQL)
- Create a dedicated database role for DBShield with minimal necessary grants:
  ```sql
  -- Create isolated role
  CREATE ROLE agent_user WITH LOGIN PASSWORD 'strong_random_password';
  
  -- Grant only targeted DML on application tables (NO DROP, TRUNCATE, or ALTER)
  GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO agent_user;
  REVOKE ALL ON SCHEMA public FROM PUBLIC;
  ```

### 3. Policy Enforcement vs Human Approval
- **Deterministic Policy Enforcement**: DBShield's dry-run authorization token guarantees that a query adheres to automated safety policies (blast radius thresholds, tautology checks, parameter binding).
- **Human Approval Hand-Off**: In sensitive production workflows, `db_dry_run` outputs can be piped to an external human-in-the-loop review system (Slack, Teams, or ticketing webhook) before the token is submitted to `db_commit`.

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
- [x] **Phase 4: Real-Time Dynamic PII Masking & Data Redaction**
  - Heuristic column detection for passwords, secrets, tokens, API keys, emails, phones, SSNs, credit cards
  - High-performance regex inspection for inline PII embedded in generic text columns
  - Format-preserving deterministic masking (`a***@ritualdev.in`, `+***-***-5309`, `****-****-****-4444`)
  - Zero-leak secret replacement (`[REDACTED_SECRET]`, `[REDACTED_TOKEN]`)
  - Automated compliance audit report headers injected into MCP `db_query` responses
  - Custom column overrides via `config.customPiiColumns`
- [x] **Phase 5: Full MCP Tool Suite & Cursor/Claude Auto-Configurator**
  - `db_explain_query` query plan analysis with sequential scan & missing index alerts
  - `db_audit_log` in-memory circular audit buffer with status & risk score filtering
  - Interactive 1-click CLI configurators (`dbshield install-claude`, `dbshield install-cursor`)
  - Cross-platform configuration file detection & graceful merging
- [x] **Phase 6: Automated Testing, CI/CD, Documentation & Packaging**
  - Comprehensive unit & integration testing suite (42 tests passing across all engines)
  - GitHub Actions multi-platform CI matrix testing on Node.js 22 & 24 across Ubuntu and Windows
  - Automated Release & npm publish workflow on tag push
  - Zero-native-dependency bundle verification and production distribution via `pnpm pack`

---

## 📄 License
MIT © [RitualDev Lab](https://github.com/RitualDev-Lab)
