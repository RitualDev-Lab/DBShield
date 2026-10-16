import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { SqliteAdapter } from "../src/adapters/sqlite.js";
import { AuditLogger } from "../src/audit/index.js";
import { installClaude, installCursor } from "../src/configurator/index.js";
import { QueryExplainer } from "../src/explain/index.js";
import { createMcpServer } from "../src/server/index.js";

test("QueryExplainer - Detects Sequential Scans on Unindexed Tables", async () => {
  const adapter = new SqliteAdapter(":memory:");
  await adapter.connect();

  await adapter.query(`
    CREATE TABLE customers (
      id INTEGER PRIMARY KEY,
      email TEXT NOT NULL,
      status TEXT
    );
  `);

  const explainer = new QueryExplainer(adapter);
  const report = await explainer.explainQuery("SELECT * FROM customers WHERE email = 'a@b.com';");

  assert.equal(report.isIndexed, false);
  assert.ok(report.bottlenecks.some((b) => b.includes("Full table sequential scan")));
  assert.ok(report.suggestions.some((s) => s.includes("Create an index")));

  await adapter.disconnect();
});

test("QueryExplainer - Verifies Indexed Optimization", async () => {
  const adapter = new SqliteAdapter(":memory:");
  await adapter.connect();

  await adapter.query(`
    CREATE TABLE orders (
      id INTEGER PRIMARY KEY,
      order_number TEXT NOT NULL
    );
  `);
  await adapter.query("CREATE INDEX idx_orders_number ON orders(order_number);");

  const explainer = new QueryExplainer(adapter);
  const report = await explainer.explainQuery(
    "SELECT * FROM orders WHERE order_number = 'ORD-100';",
  );

  assert.equal(report.isIndexed, true);
  assert.ok(report.suggestions.some((s) => s.includes("utilizes existing index structures")));

  await adapter.disconnect();
});

test("AuditLogger - Records Events and Filters by Status and Risk", async () => {
  const logger = new AuditLogger();

  await logger.log({
    auditId: "aud_1",
    timestamp: new Date().toISOString(),
    sql: "SELECT * FROM users;",
    operation: "SELECT",
    status: "SUCCESS",
    riskLevel: "SAFE",
    riskScore: 5,
  });

  await logger.log({
    auditId: "aud_2",
    timestamp: new Date().toISOString(),
    sql: "DROP TABLE users;",
    operation: "DDL_DROP",
    status: "BLOCKED",
    riskLevel: "CRITICAL",
    riskScore: 95,
    violations: ["DESTRUCTIVE_DDL_BLOCKED"],
  });

  const allEntries = logger.getEntries({ limit: 10 });
  assert.equal(allEntries.length, 2);

  // Filter by BLOCKED status
  const blockedOnly = logger.getEntries({ status: "BLOCKED" });
  assert.equal(blockedOnly.length, 1);
  assert.equal(blockedOnly[0].auditId, "aud_2");

  // Filter by minRiskScore >= 50
  const highRisk = logger.getEntries({ minRiskScore: 50 });
  assert.equal(highRisk.length, 1);
  assert.equal(highRisk[0].riskScore, 95);
});

test("Configurator - Claude Desktop Configuration Patching", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dbshield-claude-test-"));
  const tempConfigPath = path.join(tempDir, "claude_desktop_config.json");

  // Seed existing unrelated server config
  const existingConfig = {
    mcpServers: {
      github: {
        command: "npx",
        args: ["-y", "@modelcontextprotocol/server-github"],
      },
    },
  };
  await fs.writeFile(tempConfigPath, JSON.stringify(existingConfig, null, 2), "utf8");

  // Patch with DBShield
  const result = await installClaude(tempConfigPath);
  assert.equal(result.success, true);
  assert.equal(result.configPath, tempConfigPath);

  // Verify file content preserves existing server and adds dbshield
  const updatedRaw = await fs.readFile(tempConfigPath, "utf8");
  const parsed = JSON.parse(updatedRaw);

  assert.ok(parsed.mcpServers.github, "Existing server config must be preserved");
  assert.ok(parsed.mcpServers.dbshield, "DBShield server config must be added");
  assert.deepEqual(parsed.mcpServers.dbshield.args, ["-y", "@ritualdev-lab/dbshield", "start"]);

  await fs.rm(tempDir, { recursive: true, force: true });
});

test("Configurator - Cursor Configuration Patching", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dbshield-cursor-test-"));

  const result = await installCursor(tempDir);
  assert.equal(result.success, true);

  const cursorConfigPath = path.join(tempDir, ".cursor", "mcp.json");
  const raw = await fs.readFile(cursorConfigPath, "utf8");
  const parsed = JSON.parse(raw);

  assert.ok(parsed.mcpServers.dbshield);
  assert.equal(parsed.mcpServers.dbshield.command, "npx");

  await fs.rm(tempDir, { recursive: true, force: true });
});

test("MCP Server - db_explain_query and db_audit_log Tools Integration", async () => {
  const instance = await createMcpServer({
    storagePath: ":memory:",
    safetyTier: "BALANCED",
  });

  await instance.adapter.query("CREATE TABLE products (id INTEGER PRIMARY KEY, sku TEXT);");

  // Explain query through explainer instance
  const explain = await instance.explainer.explainQuery(
    "SELECT * FROM products WHERE sku = 'ABC';",
  );
  assert.ok(explain.bottlenecks.length > 0, "Unindexed query should flag bottlenecks");

  // Execute query to populate audit log
  await instance.adapter.query("INSERT INTO products VALUES (1, 'ABC');");
  await instance.auditLogger.log({
    auditId: "test_audit_id",
    timestamp: new Date().toISOString(),
    sql: "SELECT * FROM products;",
    operation: "SELECT",
    status: "SUCCESS",
    riskLevel: "SAFE",
    riskScore: 5,
  });

  const logs = instance.auditLogger.getEntries({ limit: 5 });
  assert.ok(logs.length >= 1);
  assert.equal(logs[0].sql, "SELECT * FROM products;");

  await instance.stop();
});
