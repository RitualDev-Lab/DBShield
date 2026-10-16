import assert from "node:assert/strict";
import test from "node:test";
import { SqliteAdapter } from "../src/adapters/sqlite.js";
import { SqlGuardEngine } from "../src/guard/engine.js";
import { SandboxEngine } from "../src/sandbox/engine.js";
import { CommitTokenManager } from "../src/sandbox/tokens.js";
import { createMcpServer } from "../src/server/index.js";
import type { DBShieldConfig } from "../src/types/index.js";

const BASE_CONFIG: DBShieldConfig = {
  dialect: "sqlite",
  safetyTier: "BALANCED",
  maxRowsPerMutation: 50,
  allowDestructiveDDL: false,
  enablePiiMasking: true,
  customPiiColumns: [],
};

test("CommitTokenManager - Issue and Verify Valid Token", () => {
  const manager = new CommitTokenManager("test-secret-key-123", 60);
  const sql = "UPDATE users SET role = 'admin' WHERE id = 1;";
  const tokenInfo = manager.issueToken(sql, 1, ["users"]);

  assert.ok(tokenInfo.token.startsWith("dbs_"));
  assert.equal(tokenInfo.expiresInSeconds, 60);

  const verification = manager.verifyAndConsume(tokenInfo.token, sql);
  assert.equal(verification.valid, true);
  assert.equal(verification.payload?.affectedRows, 1);
  assert.deepEqual(verification.payload?.targetTables, ["users"]);
});

test("CommitTokenManager - Replay Protection (Single-Use)", () => {
  const manager = new CommitTokenManager("test-secret-key-123", 60);
  const sql = "UPDATE users SET role = 'admin' WHERE id = 1;";
  const tokenInfo = manager.issueToken(sql, 1, ["users"]);

  // First consumption: success
  const first = manager.verifyAndConsume(tokenInfo.token, sql);
  assert.equal(first.valid, true);

  // Second consumption attempt: blocked
  const second = manager.verifyAndConsume(tokenInfo.token, sql);
  assert.equal(second.valid, false);
  assert.equal(second.error, "TOKEN_ALREADY_USED");
});

test("CommitTokenManager - Query Tamper Protection", () => {
  const manager = new CommitTokenManager("test-secret-key-123", 60);
  const authorizedSql = "UPDATE users SET role = 'moderator' WHERE id = 5;";
  const maliciousSql = "UPDATE users SET role = 'superuser' WHERE id = 5;";

  const tokenInfo = manager.issueToken(authorizedSql, 1, ["users"]);

  const result = manager.verifyAndConsume(tokenInfo.token, maliciousSql);
  assert.equal(result.valid, false);
  assert.equal(result.error, "QUERY_TAMPERED");
});

test("CommitTokenManager - Expiration Protection", async () => {
  // 1-second TTL
  const manager = new CommitTokenManager("test-secret-key-123", 0.05);
  const sql = "UPDATE users SET role = 'admin' WHERE id = 1;";
  const tokenInfo = manager.issueToken(sql, 1, ["users"]);

  await new Promise((r) => setTimeout(r, 70));

  const result = manager.verifyAndConsume(tokenInfo.token, sql);
  assert.equal(result.valid, false);
  assert.equal(result.error, "TOKEN_EXPIRED");
});

test("SandboxEngine - Dry-Run Simulation & Transaction Rollback", async () => {
  const adapter = new SqliteAdapter(":memory:");
  await adapter.connect();

  await adapter.query(`
    CREATE TABLE balances (
      id INTEGER PRIMARY KEY,
      amount INTEGER NOT NULL
    );
  `);
  await adapter.query("INSERT INTO balances VALUES (1, 100), (2, 200), (3, 300);");

  const guard = new SqlGuardEngine(BASE_CONFIG);
  const sandbox = new SandboxEngine(adapter, guard, BASE_CONFIG);

  const dryRunSql = "UPDATE balances SET amount = amount + 500 WHERE id IN (1, 2);";
  const dryRunRes = await sandbox.dryRun(dryRunSql);

  assert.equal(dryRunRes.safe, true);
  assert.equal(dryRunRes.simulatedAffectedRows, 2);
  assert.equal(dryRunRes.rollbackVerified, true);
  assert.ok(dryRunRes.commitToken);
  assert.ok(dryRunRes.expiresAt);

  // Verify database balance was NOT altered
  const check = await adapter.query("SELECT amount FROM balances WHERE id = 1;");
  assert.equal(
    check.rows[0].amount,
    100,
    "Database balance must remain 100 after dry-run simulation",
  );

  await adapter.disconnect();
});

test("SandboxEngine - Two-Phase Commit Workflow", async () => {
  const adapter = new SqliteAdapter(":memory:");
  await adapter.connect();

  await adapter.query("CREATE TABLE accounts (id INTEGER PRIMARY KEY, status TEXT);");
  await adapter.query("INSERT INTO accounts VALUES (1, 'pending');");

  const guard = new SqlGuardEngine(BASE_CONFIG);
  const sandbox = new SandboxEngine(adapter, guard, BASE_CONFIG);

  const mutationSql = "UPDATE accounts SET status = 'active' WHERE id = 1;";

  // Phase 1: Dry run
  const dryRunRes = await sandbox.dryRun(mutationSql);
  assert.equal(dryRunRes.safe, true);
  assert.ok(dryRunRes.commitToken);

  // Phase 2: Commit
  const commitRes = await sandbox.commit(dryRunRes.commitToken, mutationSql);
  assert.equal(commitRes.rowCount, 1);

  // Verify status is now 'active'
  const verify = await adapter.query("SELECT status FROM accounts WHERE id = 1;");
  assert.equal(verify.rows[0].status, "active", "Database status must be updated after commit");

  // Replay attempt must fail
  await assert.rejects(
    async () => await sandbox.commit(dryRunRes.commitToken, mutationSql),
    /already been consumed/,
  );

  await adapter.disconnect();
});

test("SandboxEngine - Blast Radius Enforcement in STRICT Tier", async () => {
  const adapter = new SqliteAdapter(":memory:");
  await adapter.connect();

  await adapter.query("CREATE TABLE logs (id INTEGER PRIMARY KEY, msg TEXT);");
  await adapter.query("INSERT INTO logs VALUES (1, 'a'), (2, 'b'), (3, 'c'), (4, 'd'), (5, 'e');");

  const strictConfig: DBShieldConfig = {
    ...BASE_CONFIG,
    safetyTier: "STRICT",
    maxRowsPerMutation: 2, // Max 2 rows allowed
  };

  const guard = new SqlGuardEngine(strictConfig);
  const sandbox = new SandboxEngine(adapter, guard, strictConfig);

  const bulkSql = "DELETE FROM logs WHERE id > 0;";
  const dryRunRes = await sandbox.dryRun(bulkSql);

  assert.equal(dryRunRes.safe, false, "Must be flagged unsafe due to excessive blast radius");
  assert.equal(dryRunRes.simulatedAffectedRows, 5);
  assert.ok(dryRunRes.warnings.some((w) => w.includes("EXCESSIVE_BLAST_RADIUS")));
  assert.equal(dryRunRes.commitToken, undefined, "No commit token should be issued when unsafe");

  await adapter.disconnect();
});

test("MCP Server - db_dry_run and db_commit Tools Integration", async () => {
  const instance = await createMcpServer({
    storagePath: ":memory:",
    safetyTier: "BALANCED",
  });

  await instance.adapter.query("CREATE TABLE inventory (id INTEGER, qty INTEGER);");
  await instance.adapter.query("INSERT INTO inventory VALUES (1, 10);");

  // Step 1: Simulate mutation via sandbox engine
  const updateSql = "UPDATE inventory SET qty = 25 WHERE id = 1;";
  const dryRun = await instance.sandboxEngine.dryRun(updateSql);
  assert.equal(dryRun.safe, true);
  assert.ok(dryRun.commitToken);

  // Step 2: Commit via sandbox engine
  const commit = await instance.sandboxEngine.commit(dryRun.commitToken, updateSql);
  assert.equal(commit.rowCount, 1);

  // Step 3: Verify updated row
  const check = await instance.adapter.query("SELECT qty FROM inventory WHERE id = 1;");
  assert.equal(check.rows[0].qty, 25);

  await instance.stop();
});
