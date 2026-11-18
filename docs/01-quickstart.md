# 01 — DBShield Quickstart

**DBShield (`@ritualdev-lab/dbshield`)** is a safety-first SQL guardrail, wire-protocol proxy, PII redactor, and lock-free dry-run sandbox for AI coding agents querying PostgreSQL, MySQL, SQLite, and Redis.

## 1. Install & Run via MCP
```bash
npx -y @ritualdev-lab/dbshield --help
```

## 2. Configure Claude Desktop / Cursor / Antigravity
```bash
npx -y @ritualdev-lab/dbshield configure --client cursor
```

## 3. Launch the Wire-Protocol SQL Proxy
```bash
npx -y @ritualdev-lab/dbshield proxy --target postgres://readonly@localhost:5432/app --tier STRICT
```

## Next Steps
- [02 — Architecture](02-architecture.md)
- [03 — Configuration & CLI Reference](03-configuration-and-cli.md)
- [04 — Integrations & MCP Server](04-integrations-and-mcp.md)
- [05 — Enterprise VPC & Security](05-enterprise-vpc-and-security.md)
