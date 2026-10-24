import assert from "node:assert/strict";
import { test } from "node:test";
import type pg from "pg";
import { PostgresAdapter, SqliteAdapter } from "../src/adapters/index.js";
import { DEFAULT_CONFIG } from "../src/config/index.js";
import { CostGateEngine } from "../src/cost/index.js";
import { QueryExplainer } from "../src/explain/index.js";
import { createMcpServer } from "../src/server/index.js";
import type { DBShieldConfig } from "../src/types/index.js";

// Helper for PostgreSQL mock pool
function createMockPostgresPool(explainPlanRows: Array<{ "QUERY PLAN": string }>) {
  const executedQueries: { sql: string; params?: unknown[] }[] = [];

  const pool = {
    async query(sql: string, params?: unknown[]) {
      executedQueries.push({ sql, params });
      if (sql.startsWith("EXPLAIN")) {
        return {
          rows: explainPlanRows,
          rowCount: explainPlanRows.length,
          fields: [{ name: "QUERY PLAN" }],
        };
      }
      return { rows: [{ id: 1 }], rowCount: 1, fields: [{ name: "id" }] };
    },
    async connect() {
      return {
        async query(sql: string, params?: unknown[]) {
          executedQueries.push({ sql, params });
          return { rows: [], rowCount: 1, fields: [] };
        },
        release() {},
      };
    },
    async end() {},
  };

  return { pool, executedQueries };
}

test("CostGateEngine - Blocks queries exceeding maxEstimatedCost in PostgreSQL", async () => {
  const { pool } = createMockPostgresPool([
    {
      "QUERY PLAN": "Seq Scan on large_orders  (cost=0.00..84500.00 rows=150000 width=32)",
    },
  ]);

  const adapter = new PostgresAdapter("postgres://localhost:5432/test");
  adapter.setPool(pool as unknown as pg.Pool);

  const config: DBShieldConfig = {
    ...DEFAULT_CONFIG,
    dialect: "postgres",
    safetyTier: "BALANCED",
    maxEstimatedCost: 50000,
  };

  const costGate = new CostGateEngine(config, adapter);
  const evaluation = await costGate.evaluate("SELECT * FROM large_orders;");

  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.blocked, true);
  assert.equal(evaluation.code, "EXCESSIVE_QUERY_COST");
  assert.equal(evaluation.riskLevel, "BLOCKED");
  assert.equal(evaluation.estimatedCost, 84500);
  assert.ok(
    evaluation.bottlenecks.some((b) => b.includes("Estimated planner execution cost of 84500")),
  );
  assert.ok(evaluation.suggestions.some((s) => s.includes("Add indexing")));
});

test("CostGateEngine - Blocks queries exceeding maxEstimatedRows in PostgreSQL", async () => {
  const { pool } = createMockPostgresPool([
    {
      "QUERY PLAN":
        "Index Scan using idx_status on orders  (cost=0.00..1200.00 rows=250000 width=32)",
    },
  ]);

  const adapter = new PostgresAdapter("postgres://localhost:5432/test");
  adapter.setPool(pool as unknown as pg.Pool);

  const config: DBShieldConfig = {
    ...DEFAULT_CONFIG,
    dialect: "postgres",
    safetyTier: "BALANCED",
    maxEstimatedCost: 50000,
    maxEstimatedRows: 100000,
  };

  const costGate = new CostGateEngine(config, adapter);
  const evaluation = await costGate.evaluate("SELECT * FROM orders WHERE status = 'pending';");

  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.blocked, true);
  assert.equal(evaluation.code, "EXCESSIVE_QUERY_COST");
  assert.equal(evaluation.estimatedRows, 250000);
  assert.ok(
    evaluation.bottlenecks.some((b) =>
      b.includes("Estimated rows scanned (250000) exceeds safety ceiling"),
    ),
  );
});

test("CostGateEngine - Warns on queries exceeding soft warnEstimatedCost without blocking", async () => {
  const { pool } = createMockPostgresPool([
    {
      "QUERY PLAN": "Seq Scan on users  (cost=0.00..15000.00 rows=1000 width=64)",
    },
  ]);

  const adapter = new PostgresAdapter("postgres://localhost:5432/test");
  adapter.setPool(pool as unknown as pg.Pool);

  const config: DBShieldConfig = {
    ...DEFAULT_CONFIG,
    dialect: "postgres",
    safetyTier: "BALANCED",
    maxEstimatedCost: 50000,
    warnEstimatedCost: 10000,
    blockUnindexedSeqScan: false,
  };

  const costGate = new CostGateEngine(config, adapter);
  const evaluation = await costGate.evaluate("SELECT * FROM users WHERE active = true;");

  assert.equal(evaluation.allowed, true);
  assert.equal(evaluation.blocked, false);
  assert.equal(evaluation.riskLevel, "CAUTION");
  assert.ok(evaluation.warnings.some((w) => w.includes("exceeds soft warning threshold (10000)")));
});

test("CostGateEngine - Blocks unindexed sequential scan in STRICT tier", async () => {
  const { pool } = createMockPostgresPool([
    {
      "QUERY PLAN": "Seq Scan on audit_logs  (cost=0.00..500.00 rows=50 width=32)",
    },
  ]);

  const adapter = new PostgresAdapter("postgres://localhost:5432/test");
  adapter.setPool(pool as unknown as pg.Pool);

  const config: DBShieldConfig = {
    ...DEFAULT_CONFIG,
    dialect: "postgres",
    safetyTier: "STRICT",
    blockUnindexedSeqScan: true,
  };

  const costGate = new CostGateEngine(config, adapter);
  const evaluation = await costGate.evaluate("SELECT * FROM audit_logs;");

  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.blocked, true);
  assert.equal(evaluation.code, "UNINDEXED_SCAN_DISALLOWED");
  assert.ok(
    evaluation.bottlenecks.some((b) =>
      b.includes("Sequential scan on an unindexed table is strictly prohibited"),
    ),
  );
});

test("CostGateEngine - Blocks unbounded scan without LIMIT in STRICT tier (SQLite)", async () => {
  const sqliteAdapter = new SqliteAdapter(":memory:");
  await sqliteAdapter.connect();
  await sqliteAdapter.query("CREATE TABLE documents (id INTEGER PRIMARY KEY, content TEXT);");

  const config: DBShieldConfig = {
    ...DEFAULT_CONFIG,
    dialect: "sqlite",
    safetyTier: "STRICT",
    blockUnindexedSeqScan: false,
  };

  const costGate = new CostGateEngine(config, sqliteAdapter);
  const evaluation = await costGate.evaluate(
    "SELECT content FROM documents WHERE content LIKE '%test%';",
  );

  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.blocked, true);
  assert.equal(evaluation.code, "UNBOUNDED_SCAN_DISALLOWED");
  assert.ok(evaluation.suggestions.some((s) => s.includes("Add a LIMIT clause")));

  await sqliteAdapter.disconnect();
});

test("CostGateEngine - Allows indexed query with low cost without warnings", async () => {
  const sqliteAdapter = new SqliteAdapter(":memory:");
  await sqliteAdapter.connect();
  await sqliteAdapter.query("CREATE TABLE accounts (id INTEGER PRIMARY KEY, email TEXT UNIQUE);");

  const config: DBShieldConfig = {
    ...DEFAULT_CONFIG,
    dialect: "sqlite",
    safetyTier: "BALANCED",
  };

  const costGate = new CostGateEngine(config, sqliteAdapter);
  const evaluation = await costGate.evaluate(
    "SELECT * FROM accounts WHERE email = 'test@example.com';",
  );

  assert.equal(evaluation.allowed, true);
  assert.equal(evaluation.blocked, false);
  assert.equal(evaluation.riskLevel, "SAFE");
  assert.equal(evaluation.warnings.length, 0);

  await sqliteAdapter.disconnect();
});

test("Runaway Query Killer - Statement timeout terminates slow queries in SqliteAdapter with [QUERY_TIMEOUT_EXCEEDED]", async () => {
  // Use a very short timeout of 20ms and an iterative recursive table that generates large rows
  const sqliteAdapter = new SqliteAdapter(":memory:", 5000, 50, 20);
  await sqliteAdapter.connect();

  await assert.rejects(async () => {
    // Generate a long loop in SQLite that takes > 20ms
    await sqliteAdapter.query(
      `WITH RECURSIVE cnt(x) AS (
        SELECT 1
        UNION ALL
        SELECT x+1 FROM cnt WHERE x < 2000000
      )
      SELECT x, hex(randomblob(1000)) FROM cnt;`,
      [],
      { timeoutMs: 20 },
    );
  }, /\[QUERY_TIMEOUT_EXCEEDED\] Query execution exceeded the hard limit of 20ms and was terminated to protect database stability/);

  await sqliteAdapter.disconnect();
});

test("Runaway Query Killer - Statement timeout terminates slow queries in PostgresAdapter with [QUERY_TIMEOUT_EXCEEDED]", async () => {
  const hangingPool = {
    async query() {
      // Simulate slow execution that hangs longer than timeout
      return new Promise<never>((resolve) => {
        setTimeout(resolve, 500);
      });
    },
    async connect() {
      return {
        async query() {
          return new Promise<never>((resolve) => {
            setTimeout(resolve, 500);
          });
        },
        release() {},
      };
    },
    async end() {},
  };

  const postgresAdapter = new PostgresAdapter("postgres://localhost:5432/test", 500, 50, 30);
  postgresAdapter.setPool(hangingPool as unknown as pg.Pool);

  await assert.rejects(async () => {
    await postgresAdapter.query("SELECT * FROM huge_analytics_events;", [], { timeoutMs: 30 });
  }, /\[QUERY_TIMEOUT_EXCEEDED\] Query execution exceeded the hard limit of 30ms and was terminated to protect database stability/);
});

test("MCP Server db_query - Intercepts unindexed sequential scans in STRICT tier", async () => {
  const serverInstance = await createMcpServer({
    storagePath: ":memory:",
    safetyTier: "STRICT",
    blockUnindexedSeqScan: true,
  });

  // Create an unindexed table in SQLite
  await serverInstance.adapter.query("CREATE TABLE raw_logs (id INTEGER, message TEXT);");

  // Evaluate query through server's costGateEngine
  const evaluation = await serverInstance.costGateEngine.evaluate("SELECT * FROM raw_logs;");
  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.code, "UNINDEXED_SCAN_DISALLOWED");
  assert.equal(evaluation.blocked, true);

  await serverInstance.stop();
});

test("MCP Server db_status - Reflects active cost gate configuration", async () => {
  const serverInstance = await createMcpServer({
    storagePath: ":memory:",
    safetyTier: "BALANCED",
    enableCostGate: true,
    maxEstimatedCost: 50000,
    maxEstimatedRows: 100000,
    statementTimeoutMs: 4500,
  });

  assert.equal(serverInstance.config.enableCostGate, true);
  assert.equal(serverInstance.config.maxEstimatedCost, 50000);
  assert.equal(serverInstance.config.maxEstimatedRows, 100000);
  assert.equal(serverInstance.config.statementTimeoutMs, 4500);

  await serverInstance.stop();
});
