import assert from "node:assert";
import test from "node:test";
import { InMemoryRedisAdapter } from "../src/adapters/redis.js";
import { SqliteAdapter } from "../src/adapters/sqlite.js";
import { DistributedSandboxEngine } from "../src/sandbox/distributed.js";
import { DistributedCommitTokenManager } from "../src/sandbox/distributed-tokens.js";
import type { DBShieldConfig, DistributedStoreOperation } from "../src/types/index.js";

test("InMemoryRedisAdapter - Shadow simulation dry-run and atomic rollback", async () => {
  const redis = new InMemoryRedisAdapter();
  await redis.connect();

  redis.set("user:1:role", "member");

  // Dry-run set operation
  const dryRes = await redis.executeDryRun("SET", "user:1:role", "admin");
  assert.strictEqual(dryRes.safe, true);
  assert.strictEqual(dryRes.simulatedAffectedKeys, 1);
  assert.strictEqual(dryRes.rollbackVerified, true);

  // Value in live storage must NOT have changed
  assert.strictEqual(redis.get("user:1:role"), "member");

  // Real commit
  const commitRes = await redis.executeCommit("SET", "user:1:role", "admin");
  assert.strictEqual(commitRes.success, true);
  assert.strictEqual(redis.get("user:1:role"), "admin");

  await redis.disconnect();
});

test("DistributedCommitTokenManager - Issue, verify, tamper protection, and replay prevention", () => {
  const tokenManager = new DistributedCommitTokenManager(undefined, 60);

  const ops: DistributedStoreOperation[] = [
    {
      storeId: "postgres-main",
      storeType: "postgres",
      action: "SQL",
      queryOrKey: "UPDATE users SET role = 'admin' WHERE id = 1;",
    },
    {
      storeId: "redis-session",
      storeType: "redis",
      action: "KV_SET",
      queryOrKey: "session:1:role",
      paramsOrValue: "admin",
    },
  ];

  // Issue token
  const tokenInfo = tokenManager.issueToken(ops, 2);
  assert.ok(tokenInfo.token.startsWith("dbs_dist_"));

  // Tamper with second operation query
  const tamperedOps = JSON.parse(JSON.stringify(ops));
  tamperedOps[1].queryOrKey = "session:2:role"; // altered key

  const tamperCheck = tokenManager.verifyAndConsume(tokenInfo.token, tamperedOps);
  assert.strictEqual(tamperCheck.valid, false);
  assert.strictEqual(tamperCheck.error, "OPERATIONS_TAMPERED");

  // Valid verification & consumption
  const validCheck = tokenManager.verifyAndConsume(tokenInfo.token, ops);
  assert.strictEqual(validCheck.valid, true);
  assert.strictEqual(validCheck.payload?.totalAffectedEntities, 2);

  // Replay protection - token cannot be reused
  const replayCheck = tokenManager.verifyAndConsume(tokenInfo.token, ops);
  assert.strictEqual(replayCheck.valid, false);
  assert.strictEqual(replayCheck.error, "TOKEN_ALREADY_USED");
});

test("DistributedSandboxEngine - Multi-Store Dry-Run & Two-Phase Commit across SQLite + Redis", async () => {
  const config: DBShieldConfig = {
    dialect: "sqlite",
    safetyTier: "BALANCED",
    maxRowsPerMutation: 50,
    maxRowsPerRead: 500,
    allowDestructiveDDL: false,
    enablePiiMasking: true,
    enableCostGate: false,
    enableMigrationGate: false,
    enableSemanticGuard: false,
    maxEstimatedCost: 50000,
    maxEstimatedRows: 100000,
    statementTimeoutMs: 5000,
    enforceConcurrentIndexCreation: false,
    disallowBreakingRenames: true,
    requireIntentForSensitiveColumns: false,
  };

  const sqlite = new SqliteAdapter(":memory:");
  await sqlite.connect();
  await sqlite.query("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT);");
  await sqlite.query("INSERT INTO users (name, email) VALUES ('Alice', 'alice@example.com');");

  const redis = new InMemoryRedisAdapter();
  await redis.connect();
  redis.set("user:1:cached_email", "old@example.com");

  const engine = new DistributedSandboxEngine(config);
  engine.registerStore("sqlite-primary", sqlite);
  engine.registerStore("redis-cache", redis);

  const operations: DistributedStoreOperation[] = [
    {
      storeId: "sqlite-primary",
      storeType: "sqlite",
      action: "SQL",
      queryOrKey: "UPDATE users SET email = 'alice.new@example.com' WHERE id = 1;",
    },
    {
      storeId: "redis-cache",
      storeType: "redis",
      action: "KV_SET",
      queryOrKey: "user:1:cached_email",
      paramsOrValue: "alice.new@example.com",
    },
  ];

  // 1. Coordinated Dry Run
  const dryRunRes = await engine.dryRun(operations);
  assert.strictEqual(dryRunRes.safe, true);
  assert.strictEqual(dryRunRes.totalAffectedEntities, 2);
  assert.ok(dryRunRes.distributedCommitToken);
  assert.strictEqual(dryRunRes.storeResults["sqlite-primary"].safe, true);
  assert.strictEqual(dryRunRes.storeResults["sqlite-primary"].affectedRows, 1);
  assert.strictEqual(dryRunRes.storeResults["redis-cache"].safe, true);
  assert.strictEqual(dryRunRes.storeResults["redis-cache"].affectedKeys, 1);

  // Verify rollback across both stores
  const checkSqlite = await sqlite.query("SELECT email FROM users WHERE id = 1;");
  assert.strictEqual(checkSqlite.rows[0].email, "alice@example.com");
  assert.strictEqual(redis.get("user:1:cached_email"), "old@example.com");

  // 2. Coordinated Two-Phase Commit
  const commitRes = await engine.commit(dryRunRes.distributedCommitToken!, operations);
  assert.strictEqual(commitRes.committed, true);
  assert.ok(commitRes.distributedAuditId);
  assert.strictEqual(commitRes.storeResults["sqlite-primary"].success, true);
  assert.strictEqual(commitRes.storeResults["sqlite-primary"].affectedRows, 1);
  assert.strictEqual(commitRes.storeResults["redis-cache"].success, true);
  assert.strictEqual(commitRes.storeResults["redis-cache"].affectedKeys, 1);

  // Verify state committed to both stores
  const finalSqlite = await sqlite.query("SELECT email FROM users WHERE id = 1;");
  assert.strictEqual(finalSqlite.rows[0].email, "alice.new@example.com");
  assert.strictEqual(redis.get("user:1:cached_email"), "alice.new@example.com");

  await sqlite.disconnect();
  await redis.disconnect();
});
