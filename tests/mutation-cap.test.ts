import assert from "node:assert/strict";
import test from "node:test";
import { SqliteAdapter } from "../src/adapters/sqlite.js";
import { SqlGuardEngine } from "../src/guard/engine.js";
import { SandboxEngine } from "../src/sandbox/engine.js";
import type { DBShieldConfig } from "../src/types/index.js";

const BASE_CONFIG: DBShieldConfig = {
  dialect: "sqlite",
  storagePath: ":memory:",
  safetyTier: "BALANCED",
  maxRowsPerMutation: 5,
  warnRowsPerMutation: 2,
  maxRowsPerRead: 100,
  allowDestructiveDDL: false,
  enablePiiMasking: false,
  logAudit: false,
};

test("SqliteAdapter - Direct mutation exceeding maxMutationRows rolls back transactionally", async () => {
  const adapter = new SqliteAdapter(":memory:", 100, 50);
  await adapter.connect();

  await adapter.query(`
    CREATE TABLE accounts (
      id INTEGER PRIMARY KEY,
      balance INTEGER,
      status TEXT
    );
  `);

  await adapter.query(
    "INSERT INTO accounts (id, balance, status) VALUES (1, 100, 'pending'), (2, 200, 'pending'), (3, 300, 'pending'), (4, 400, 'pending'), (5, 500, 'pending');",
  );

  // Attempt to update 5 rows directly with limit set to 3
  await assert.rejects(
    async () => {
      await adapter.query("UPDATE accounts SET status = 'active' WHERE balance > 0;", [], {
        maxMutationRows: 3,
      });
    },
    (err: Error) => {
      assert.ok(err.message.includes("[MUTATION_LIMIT_EXCEEDED]"));
      assert.ok(err.message.includes("exceeding the hard safety limit of 3 rows"));
      return true;
    },
  );

  // Verify all 5 rows remain untouched ('pending') due to transaction rollback
  const check = await adapter.query("SELECT status FROM accounts WHERE status = 'pending';");
  assert.equal(check.rowCount, 5, "All rows must remain pending after rollback");

  // Mutation within limit (2 rows) succeeds
  const okRes = await adapter.query(
    "UPDATE accounts SET status = 'active' WHERE id IN (1, 2);",
    [],
    { maxMutationRows: 3 },
  );
  assert.equal(okRes.rowCount, 2);

  const activeCheck = await adapter.query("SELECT status FROM accounts WHERE status = 'active';");
  assert.equal(activeCheck.rowCount, 2);

  await adapter.disconnect();
});

test("SandboxEngine - Blast radius hard ceiling blocks across all tiers (BALANCED and PERMISSIVE)", async () => {
  const adapter = new SqliteAdapter(":memory:");
  await adapter.connect();

  await adapter.query("CREATE TABLE tasks (id INTEGER PRIMARY KEY, state TEXT);");
  await adapter.query(
    "INSERT INTO tasks VALUES (1, 'todo'), (2, 'todo'), (3, 'todo'), (4, 'todo'), (5, 'todo');",
  );

  // BALANCED tier with maxRowsPerMutation = 3
  const balancedConfig: DBShieldConfig = {
    ...BASE_CONFIG,
    safetyTier: "BALANCED",
    maxRowsPerMutation: 3,
  };

  const guard = new SqlGuardEngine(balancedConfig);
  const sandbox = new SandboxEngine(adapter, guard, balancedConfig);

  const dryRunRes = await sandbox.dryRun("UPDATE tasks SET state = 'done' WHERE id > 0;");
  assert.equal(
    dryRunRes.safe,
    false,
    "Must be unsafe when exceeding hard ceiling in BALANCED tier",
  );
  assert.equal(dryRunRes.simulatedAffectedRows, 5);
  assert.equal(dryRunRes.commitToken, undefined, "Commit token must not be issued");
  assert.ok(dryRunRes.warnings.some((w) => w.includes("EXCESSIVE_BLAST_RADIUS")));

  // PERMISSIVE tier with maxRowsPerMutation = 3 must also block
  const permissiveConfig: DBShieldConfig = {
    ...BASE_CONFIG,
    safetyTier: "PERMISSIVE",
    maxRowsPerMutation: 3,
  };
  const permissiveGuard = new SqlGuardEngine(permissiveConfig);
  const permissiveSandbox = new SandboxEngine(adapter, permissiveGuard, permissiveConfig);

  const permRes = await permissiveSandbox.dryRun("UPDATE tasks SET state = 'done' WHERE id > 0;");
  assert.equal(
    permRes.safe,
    false,
    "Must be unsafe when exceeding hard ceiling even in PERMISSIVE tier",
  );
  assert.equal(permRes.commitToken, undefined);

  await adapter.disconnect();
});

test("SandboxEngine - Soft warning threshold issues warning and allows token if within hard ceiling", async () => {
  const adapter = new SqliteAdapter(":memory:");
  await adapter.connect();

  await adapter.query("CREATE TABLE items (id INTEGER PRIMARY KEY, qty INTEGER);");
  await adapter.query("INSERT INTO items VALUES (1, 10), (2, 20), (3, 30);");

  // warnRowsPerMutation = 2, maxRowsPerMutation = 5
  const config: DBShieldConfig = {
    ...BASE_CONFIG,
    maxRowsPerMutation: 5,
    warnRowsPerMutation: 2,
  };

  const guard = new SqlGuardEngine(config);
  const sandbox = new SandboxEngine(adapter, guard, config);

  // Updating 3 rows: > warnRowsPerMutation (2), but <= maxRowsPerMutation (5)
  const dryRunRes = await sandbox.dryRun("UPDATE items SET qty = 100 WHERE id IN (1, 2, 3);");
  assert.equal(dryRunRes.safe, true, "Must be safe when within hard ceiling");
  assert.equal(dryRunRes.simulatedAffectedRows, 3);
  assert.ok(dryRunRes.commitToken, "Must issue commit token");
  assert.ok(
    dryRunRes.warnings.some((w) => w.includes("BLAST_RADIUS_WARNING")),
    "Must include soft warning threshold message",
  );

  await adapter.disconnect();
});

test("SandboxEngine - Simulation delta drift detection rolls back commit when underlying data changes", async () => {
  const adapter = new SqliteAdapter(":memory:");
  await adapter.connect();

  await adapter.query("CREATE TABLE customers (id INTEGER PRIMARY KEY, tier TEXT);");
  await adapter.query("INSERT INTO customers VALUES (1, 'standard'), (2, 'standard');");

  const guard = new SqlGuardEngine(BASE_CONFIG);
  const sandbox = new SandboxEngine(adapter, guard, BASE_CONFIG);

  const mutationSql = "UPDATE customers SET tier = 'vip' WHERE tier = 'standard';";

  // Dry run simulates 2 affected rows
  const dryRunRes = await sandbox.dryRun(mutationSql);
  assert.equal(dryRunRes.safe, true);
  assert.equal(dryRunRes.simulatedAffectedRows, 2);
  const token = dryRunRes.commitToken!;

  // Concurrent modification: another user/agent inserts a 3rd standard customer
  await adapter.query("INSERT INTO customers VALUES (3, 'standard');");

  // Attempt to commit with token issued for 2 rows
  await assert.rejects(
    async () => {
      await sandbox.commit(token, mutationSql);
    },
    (err: Error) => {
      assert.ok(err.message.includes("[SIMULATION_DELTA_DRIFT]"));
      assert.ok(
        err.message.includes(
          "Simulated affected rows was 2, but actual commit would affect 3 rows",
        ),
      );
      return true;
    },
  );

  // Verify none of the customers were changed to 'vip' because transaction was rolled back
  const check = await adapter.query("SELECT tier FROM customers WHERE tier = 'vip';");
  assert.equal(check.rowCount, 0, "No customer should be vip after drift rollback");

  await adapter.disconnect();
});
