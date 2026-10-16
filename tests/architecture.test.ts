import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import test from "node:test";
import { SqliteAdapter } from "../src/adapters/sqlite.js";
import { DEFAULT_CONFIG, loadConfig } from "../src/config/index.js";
import { createMcpServer } from "../src/server/index.js";

test("DBShield Config Loader - Default Values & Safety Tiers", async () => {
  const config = await loadConfig();
  assert.equal(config.dialect, "sqlite");
  assert.equal(config.safetyTier, "BALANCED");
  assert.equal(config.maxRowsPerMutation, 50);
  assert.equal(config.allowDestructiveDDL, false);
  assert.equal(config.enablePiiMasking, true);
});

test("SqliteAdapter - Execution and Schema Introspection", async () => {
  const adapter = new SqliteAdapter(":memory:");
  await adapter.connect();

  // Create table
  await adapter.query(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      role TEXT DEFAULT 'developer'
    );
  `);

  // Insert row
  const insertRes = await adapter.query(
    "INSERT INTO users (email, role) VALUES ('test@ritualdev.in', 'lead');",
  );
  assert.equal(insertRes.rowCount, 1, "Should report 1 row inserted");

  // Select row
  const selectRes = await adapter.query("SELECT * FROM users;");
  assert.equal(selectRes.rowCount, 1);
  assert.equal(selectRes.rows[0].email, "test@ritualdev.in");
  assert.equal(selectRes.rows[0].role, "lead");
  assert.ok(selectRes.executionTimeMs >= 0);
  assert.ok(selectRes.auditId);

  // Schema introspection
  const schema = await adapter.getTableSchema("users");
  assert.ok(schema, "Schema should be found");
  assert.equal(schema.tableName, "users");
  assert.equal(schema.columns.length, 3);
  assert.equal(schema.columns[0].name, "id");
  assert.equal(schema.columns[0].primaryKey, true);
  assert.equal(schema.columns[1].name, "email");
  assert.equal(schema.columns[1].nullable, false);

  await adapter.disconnect();
});

test("SqliteAdapter - Dry-Run Auto-Rollback Transaction Guarantee", async () => {
  const adapter = new SqliteAdapter(":memory:");
  await adapter.connect();

  await adapter.query(`
    CREATE TABLE accounts (
      id INTEGER PRIMARY KEY,
      balance INTEGER
    );
  `);

  await adapter.query("INSERT INTO accounts (id, balance) VALUES (1, 100), (2, 200);");

  // Execute dry-run mutation
  const dryRunRes = await adapter.executeDryRun("UPDATE accounts SET balance = balance + 500;");
  assert.equal(dryRunRes.safe, true);
  assert.equal(dryRunRes.simulatedAffectedRows, 2, "Dry-run should report 2 rows affected");
  assert.equal(dryRunRes.rollbackVerified, true, "Rollback must be verified");

  // Verify accounts balance was NOT modified in the database
  const checkRes = await adapter.query("SELECT balance FROM accounts WHERE id = 1;");
  assert.equal(
    checkRes.rows[0].balance,
    100,
    "Balance must remain 100 after dry-run transaction rollback",
  );

  await adapter.disconnect();
});

test("MCP Server - Factory & Lifecycle Initialization", async () => {
  const instance = await createMcpServer({
    dialect: "sqlite",
    storagePath: ":memory:",
    safetyTier: "STRICT",
  });

  assert.ok(instance.server, "MCP Server instance must exist");
  assert.equal(instance.config.safetyTier, "STRICT");

  await instance.stop();
});

test("DBShield CLI - Help and Version Flags", () => {
  const versionOutput = execSync("npx tsx src/cli.ts --version", { encoding: "utf8" });
  assert.ok(versionOutput.includes("dbshield v0.1.0"));

  const helpOutput = execSync("npx tsx src/cli.ts --help", { encoding: "utf8" });
  assert.ok(helpOutput.includes("DBShield - Database Guardrail & Sandboxing MCP Server"));
  assert.ok(helpOutput.includes("claude_desktop_config.json"));
  assert.ok(helpOutput.includes(".cursor/mcp.json"));
});
