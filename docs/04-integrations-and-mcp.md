# 04 — Integrations & MCP Server

## MCP Tools Exposed by DBShield
- `db_query`: Guarded SQL execution with AST validation, cost gate, row cap, and automatic PII redaction.
- `db_dry_run`: Lock-free shadow transaction simulation returning exact affected-row counts and single-use commit tokens.
- `db_explain_query`: Query plan analyzer flagging unindexed sequential scans and proposing index DDL.
- `db_check_semantic_intent`: Verifies agent stated intent against targeted sensitive columns.
- `db_audit_log`: Queries the tamper-evident, PII-redacted HMAC audit ledger.

## ChatOps Integration (Slack & Microsoft Teams)
Configure `DBSHIELD_CHATOPS_SECRET`, `SLACK_WEBHOOK_URL`, or `TEAMS_WEBHOOK_URL` to route `CRITICAL` mutations through `PreImageChecksumCoordinator` with 1-click HMAC-signed Approve/Reject cards.
