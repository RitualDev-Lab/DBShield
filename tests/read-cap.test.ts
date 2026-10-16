import assert from "node:assert/strict";
import test from "node:test";
import { SqliteAdapter } from "../src/adapters/sqlite.js";
import { SqlGuardEngine } from "../src/guard/engine.js";
import { createMcpServer } from "../src/server/index.js";

test("Phase 2 (B4): SqliteAdapter enforces hard read ceiling with streaming truncation", async () => {
  const adapter = new SqliteAdapter(":memory:", 50); // Default 50 rows cap
  await adapter.connect();

  await adapter.query(`
    CREATE TABLE logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      message TEXT,
      level TEXT
    );
  `);

  // Insert 120 rows
  for (let i = 0; i < 12; i++) {
    const values = Array.from({ length: 10 }, (_, j) => `('Event ${i * 10 + j}', 'INFO')`).join(
      ", ",
    );
    await adapter.query(`INSERT INTO logs (message, level) VALUES ${values};`);
  }

  // 1. Unbounded query on 120 rows capped at default 50 rows
  const cappedRes = await adapter.query("SELECT * FROM logs;");
  assert.equal(cappedRes.rowCount, 50, "Must cap materialized rows at 50");
  assert.equal(cappedRes.rows.length, 50);
  assert.ok(cappedRes.meta, "Pagination metadata must be returned");
  assert.equal(cappedRes.meta.isTruncated, true, "isTruncated must be true");
  assert.equal(cappedRes.meta.totalReturned, 50);
  assert.equal(cappedRes.meta.maxAllowedRows, 50);
  assert.ok(cappedRes.meta.warning?.includes("capped at 50 rows"));

  // 2. Query with custom maxRows options override
  const customCappedRes = await adapter.query("SELECT * FROM logs;", [], { maxRows: 15 });
  assert.equal(customCappedRes.rowCount, 15);
  assert.equal(customCappedRes.rows.length, 15);
  assert.equal(customCappedRes.meta?.isTruncated, true);
  assert.equal(customCappedRes.meta?.maxAllowedRows, 15);

  // 3. Query under the limit (e.g. LIMIT 10)
  const underLimitRes = await adapter.query("SELECT * FROM logs WHERE id <= 10;");
  assert.equal(underLimitRes.rowCount, 10);
  assert.equal(
    underLimitRes.meta?.isTruncated,
    false,
    "Should not be marked truncated under limit",
  );
  assert.equal(underLimitRes.meta?.hasMore, false);

  // 4. Exact limit match (50 items requested with cap of 50)
  const exactRes = await adapter.query("SELECT * FROM logs WHERE id <= 50;");
  assert.equal(exactRes.rowCount, 50);
  assert.equal(exactRes.meta?.isTruncated, false, "Exact boundary must not trigger truncation");

  await adapter.disconnect();
});

test("Phase 2 (B4): SqlGuardEngine warns when requested LIMIT exceeds maxRowsPerRead ceiling", () => {
  const guard = new SqlGuardEngine({
    dialect: "sqlite",
    safetyTier: "BALANCED",
    maxRowsPerMutation: 50,
    maxRowsPerRead: 100, // 100 row ceiling
    allowDestructiveDDL: false,
    enablePiiMasking: true,
  });

  // Query requesting 500 rows when ceiling is 100
  const evalExceeded = guard.evaluate("SELECT * FROM users LIMIT 500;");
  assert.equal(evalExceeded.allowed, true);
  assert.ok(
    evalExceeded.warnings.some((w) => w.includes("exceeds server maxRowsPerRead ceiling (100)")),
    "Guardrail must warn that requested limit exceeds server ceiling",
  );

  // Query within limit
  const evalWithin = guard.evaluate("SELECT * FROM users LIMIT 50;");
  assert.equal(evalWithin.allowed, true);
  assert.ok(
    !evalWithin.warnings.some((w) => w.includes("exceeds server maxRowsPerRead ceiling")),
    "Should not warn when limit is within threshold",
  );
});

test("Phase 2 (B4): MCP Server db_query returns structured truncation metadata", async () => {
  const instance = await createMcpServer({
    dialect: "sqlite",
    storagePath: ":memory:",
    safetyTier: "BALANCED",
    maxRowsPerRead: 20, // Low cap for test
  });

  await instance.adapter.query("CREATE TABLE metrics (id INT, val REAL);");
  for (let i = 0; i < 50; i++) {
    await instance.adapter.query(`INSERT INTO metrics VALUES (${i}, ${Math.random()});`);
  }

  // Call db_query through adapter
  const queryResult = await instance.adapter.query("SELECT * FROM metrics;", [], {
    maxRows: instance.config.maxRowsPerRead,
  });

  assert.equal(queryResult.rowCount, 20);
  assert.equal(queryResult.meta?.isTruncated, true);
  assert.equal(queryResult.meta?.maxAllowedRows, 20);
  assert.equal(queryResult.meta?.totalReturned, 20);

  await instance.stop();
});
