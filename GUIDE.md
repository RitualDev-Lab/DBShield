# 📖 DBShield Complete Run & Integration Guide

> **Safety-First Database Guardrail & Sandboxing MCP Server for Autonomous AI Coding Agents**  
> *Official documentation for local developers, DevOps engineers, and autonomous AI agents.*

---

## 📑 Table of Contents

1. [Introduction & Architecture](#1-introduction--architecture)
2. [Prerequisites & System Requirements](#2-prerequisites--system-requirements)
3. [Instant 30-Second Quickstart (Zero Install)](#3-instant-30-second-quickstart-zero-install)
4. [CLI Command Reference (With Examples)](#4-cli-command-reference-with-examples)
   - [MCP Stdio Server (`dbshield start`)](#41-mcp-stdio-server)
   - [PostgreSQL Protocol 3.0 Wire Proxy (`dbshield proxy`)](#42-postgresql-wire-proxy)
   - [Interactive Terminal Process Monitor (`dbshield top`)](#43-interactive-terminal-monitor)
   - [Migration & Schema Lock Hazard Audit (`dbshield audit`)](#44-migration--schema-audit)
   - [Live Query Approval Dashboard (`dbshield dashboard`)](#45-live-approval-dashboard)
   - [Regulatory Compliance Audit Report (`dbshield report`)](#46-regulatory-compliance-audit-report)
   - [Database Gateway Status (`dbshield status`)](#47-database-gateway-status)
   - [IDE One-Click Auto-Configuration](#48-ide-one-click-auto-configuration)
5. [AI Coding Agent Integration (Cursor, Claude, Windsurf, Antigravity)](#5-ai-coding-agent-integration)
6. [Wire-Protocol Proxy & Production Deployment](#6-wire-protocol-proxy--production-deployment)
   - [Docker Compose](#61-docker-compose)
   - [Kubernetes Helm Chart](#62-kubernetes-helm-chart)
   - [AWS Aurora / RDS, GCP Cloud SQL & Azure PostgreSQL](#63-cloud-database-gateways)
7. [Two-Phase Distributed Dry-Run Engine](#7-two-phase-distributed-dry-run-engine)
8. [ChatOps Approval Integration (Slack & Microsoft Teams)](#8-chatops-approval-integration)
9. [Programmatic TypeScript / Node.js SDK](#9-programmatic-typescript--nodejs-sdk)
10. [Troubleshooting & FAQ](#10-troubleshooting--faq)

---

## 1. Introduction & Architecture

Modern AI coding agents (**Claude Code**, **Cursor**, **Windsurf**, **Google Antigravity**) have autonomous capabilities to inspect codebases and query live databases. Without deterministic guardrails, agents can:
1. Accidental bulk mutations: A missing `WHERE` clause turns a targeted fix into an unrecoverable `DELETE FROM users;` or `UPDATE orders SET status = 'cancelled';`.
2. Catastrophic DDL: Dropping staging or production tables (`DROP TABLE`, `TRUNCATE`) instead of running non-destructive migrations.
3. PII & credential leaks: Streaming passwords, emails, SSNs, and API keys directly into LLM prompts and model training logs.
4. Denial-of-service locks: Unindexed queries exhausting connection pools and locking production tables.

**DBShield** sits between AI Agents and Databases as an intelligent, zero-overhead safety firewall:
- **Zero Cloud Exfiltration**: 100% air-gapped, zero external telemetry, keeping all database records locally on your machine or inside your VPC.
- **SQL AST Analysis**: Inspects query syntax trees before transmission, intercepting tautologies (`WHERE 1=1`), unconstrained updates, and schema drops in $< 0.42\text{ ms}$.
- **Two-Phase Shadow Rollback**: Executes mutations in an isolated transaction rollback block (`BEGIN ... ROLLBACK`) to preview affected rows before committing.
- **Dynamic PII Masking**: Real-time wire-level redaction of customer emails, SSNs, and API tokens.

---

## 2. Prerequisites & System Requirements

- **Node.js**: v20.0.0 or higher (`node -v`)
- **Package Manager**: npm, pnpm, yarn, or bun
- **Operating Systems**: macOS, Linux, Windows (PowerShell & WSL)
- **Supported Databases**: PostgreSQL (v12-v17+), SQLite (v3+), MySQL (v8+)

---

## 3. Instant 30-Second Quickstart (Zero Install)

You can run DBShield immediately with `npx` without installing any global packages:

```bash
# 1. Initialize configuration in your repository
npx @ritualdev-lab/dbshield init

# 2. Configure your local Claude Desktop or Cursor IDE in 1 click
npx @ritualdev-lab/dbshield install-cursor
npx @ritualdev-lab/dbshield install-claude

# 3. Launch the wire-protocol proxy on localhost:5433
npx @ritualdev-lab/dbshield proxy --port 5433 --upstream-host 127.0.0.1 --upstream-port 5432
```

---

## 4. CLI Command Reference (With Examples)

### 4.1. MCP Stdio Server
Launches the Model Context Protocol (MCP) server communicating over `stdio`:
```bash
npx @ritualdev-lab/dbshield start
```

### 4.2. PostgreSQL Wire Proxy
Runs a transparent TCP wire proxy intercepting raw PostgreSQL Protocol 3.0 packets:
```bash
npx @ritualdev-lab/dbshield proxy --port 5433 --upstream-host 127.0.0.1 --upstream-port 5432
```
Now point any ORM, application, or agent directly to:
```env
DATABASE_URL="postgres://postgres:postgres@127.0.0.1:5433/production_db"
```

### 4.3. Interactive Terminal Monitor
Launches an interactive live ANSI terminal monitor displaying active agent database sessions, intercepted queries, and shadow DB instances:
```bash
npx @ritualdev-lab/dbshield top
```

### 4.4. Migration & Schema Audit
Statically scans migration files, Prisma schemas, and SQL scripts for table lock hazards, unindexed foreign keys, and destructive drops:
```bash
npx @ritualdev-lab/dbshield audit ./migrations
```

### 4.5. Live Approval Dashboard
Launches a zero-dependency local web dashboard streaming real-time agent queries with 1-click Approve/Reject buttons:
```bash
npx @ritualdev-lab/dbshield dashboard --port 3100
```
Open [http://localhost:3100](http://localhost:3100) in your browser.

### 4.6. Regulatory Compliance Audit Report
Generates verifiable compliance documentation for SOC 2 Type II, ISO 27001, and India DPDP Act 2023:
```bash
npx @ritualdev-lab/dbshield report --compliance soc2 --format html -o ./audit-report.html
npx @ritualdev-lab/dbshield report --compliance iso27001 --audit-pdf ./audit-report.pdf
```

### 4.7. Database Gateway Status
Inspects the database connection, configured safety tiers, and schema table counts:
```bash
npx @ritualdev-lab/dbshield status
```

### 4.8. IDE One-Click Auto-Configuration
Automatically patches the MCP configuration files for your IDEs:
```bash
npx @ritualdev-lab/dbshield install-cursor       # Patches .cursor/mcp.json
npx @ritualdev-lab/dbshield install-claude       # Patches claude_desktop_config.json
npx @ritualdev-lab/dbshield install-antigravity  # Patches .antigravity/mcp.json
```

---

## 5. AI Coding Agent Integration

### Cursor IDE (`.cursor/mcp.json`)
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

### Claude Desktop (`claude_desktop_config.json`)
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

### Google Antigravity (`.antigravity/mcp.json`)
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

---

## 6. Wire-Protocol Proxy & Production Deployment

### 6.1. Docker Compose
```yaml
version: '3.8'
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: app
      POSTGRES_USER: user
      POSTGRES_PASSWORD: password
    ports:
      - "5432:5432"

  dbshield:
    image: ghcr.io/ritualdev-lab/dbshield:latest
    ports:
      - "5433:5433"
      - "3100:3100"
      - "9090:9090"
    environment:
      DBSHIELD_UPSTREAM_HOST: postgres
      DBSHIELD_UPSTREAM_PORT: 5432
      DBSHIELD_LISTEN_PORT: 5433
      DBSHIELD_SAFETY_TIER: BALANCED
    depends_on:
      - postgres
```

---

## 7. Two-Phase Distributed Dry-Run Engine

1. **Phase 1 (Simulation)**: When an agent issues a mutation, DBShield executes:
   ```sql
   BEGIN;
   UPDATE users SET status = 'inactive' WHERE last_login < NOW() - INTERVAL '1 year';
   -- Inspect affected rows: 142 records
   ROLLBACK;
   ```
2. **Commit Token Generation**: A cryptographic token `2pc_tok_...` is generated and returned to the agent along with the affected row count and preview diff.
3. **Phase 2 (Commit)**: The agent (or human approver) provides the `commitToken` to finalize the mutation within the TTL window (default 300s).

---

## 8. ChatOps Approval Integration

DBShield can route mutation requests exceeding risk thresholds to Slack or Microsoft Teams:

```json
{
  "approval": {
    "slackWebhookUrl": "https://hooks.slack.com/services/T000/B000/XXXX",
    "teamsWebhookUrl": "https://company.webhook.office.com/webhookb2/XXXX",
    "autoApproveUnderRows": 5
  }
}
```

---

## 9. Programmatic TypeScript / Node.js SDK

```typescript
import { SqlGuardEngine } from "@ritualdev-lab/dbshield";

const guard = new SqlGuardEngine({
  safetyTier: "BALANCED",
  maxRowsPerMutation: 50,
  allowDestructiveDDL: false
});

const result = guard.validateQuery("DELETE FROM users WHERE 1=1;");
if (!result.isAllowed) {
  console.error("Mutation blocked:", result.reason);
}
```

---

## 10. Troubleshooting & FAQ

**Q: Does DBShield add query latency?**  
A: No. In-process AST inspection and zero-copy wire parsing add less than $0.42\text{ ms}$ overhead.

**Q: Does DBShield send query contents or schema metadata to any cloud server?**  
A: No. DBShield is 100% air-gapped and local-first with zero telemetry.
