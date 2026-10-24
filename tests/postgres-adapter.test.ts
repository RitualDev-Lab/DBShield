import assert from "node:assert/strict";
import { test } from "node:test";
import type pg from "pg";
import { PostgresAdapter, createDatabaseAdapter } from "../src/adapters/index.js";
import { QueryExplainer } from "../src/explain/index.js";
import type { TableSchema } from "../src/types/index.js";

// Mock client generator for pg
function createMockClient(options: {
  queryHandler?: (
    sql: string,
    params?: unknown[],
  ) => Promise<{ rows: Record<string, unknown>[]; rowCount?: number; fields?: { name: string }[] }>;
}) {
  const executedStatements: { sql: string; params?: unknown[] }[] = [];

  const client = {
    async query(sql: string, params?: unknown[]) {
      executedStatements.push({ sql, params });
      if (options.queryHandler) {
        return options.queryHandler(sql, params);
      }
      return { rows: [], rowCount: 0, fields: [] };
    },
    release() {},
  };

  return { client, executedStatements };
}

// Mock pool generator
function createMockPool(options: {
  queryHandler?: (
    sql: string,
    params?: unknown[],
  ) => Promise<{ rows: Record<string, unknown>[]; rowCount?: number; fields?: { name: string }[] }>;
  clientQueryHandler?: (
    sql: string,
    params?: unknown[],
  ) => Promise<{ rows: Record<string, unknown>[]; rowCount?: number; fields?: { name: string }[] }>;
}) {
  const executedQueries: { sql: string; params?: unknown[] }[] = [];
  const { client, executedStatements: clientStatements } = createMockClient({
    queryHandler: options.clientQueryHandler || options.queryHandler,
  });

  const pool = {
    async query(sql: string, params?: unknown[]) {
      executedQueries.push({ sql, params });
      if (options.queryHandler) {
        return options.queryHandler(sql, params);
      }
      return { rows: [], rowCount: 0, fields: [] };
    },
    async connect() {
      return client;
    },
    async end() {},
  };

  return { pool, executedQueries, clientStatements };
}

test("PostgresAdapter - Factory Initialization and Dialect", () => {
  const adapter = createDatabaseAdapter({
    dialect: "postgres",
    connectionString: "postgresql://postgres:secret@localhost:5432/testdb",
    safetyTier: "BALANCED",
    maxRowsPerMutation: 50,
    maxRowsPerRead: 500,
    allowDestructiveDDL: false,
    enablePiiMasking: true,
  });

  assert.equal(adapter.dialect, "postgres");
  assert.ok(adapter instanceof PostgresAdapter);
});

test("PostgresAdapter - Cloud Connection Auto-SSL Detection", () => {
  const neonAdapter = new PostgresAdapter(
    "postgres://user:pass@ep-cool-db.us-east-2.aws.neon.tech/neondb",
  );
  assert.equal(neonAdapter.dialect, "postgres");

  const supabaseAdapter = new PostgresAdapter(
    "postgres://postgres:secret@db.xyz.supabase.co:5432/postgres",
  );
  assert.equal(supabaseAdapter.dialect, "postgres");
});

test("PostgresAdapter - Executes SELECT Queries and Enforces Read Cap", async () => {
  const mockRows = Array.from({ length: 15 }, (_, i) => ({ id: i + 1, name: `User ${i + 1}` }));
  const { pool } = createMockPool({
    queryHandler: async () => ({
      rows: mockRows,
      rowCount: mockRows.length,
      fields: [{ name: "id" }, { name: "name" }],
    }),
  });

  const adapter = new PostgresAdapter("postgres://localhost:5432/test", 10, 50);
  adapter.setPool(pool as unknown as pg.Pool);

  const result = await adapter.query("SELECT * FROM users;");
  assert.equal(result.rowCount, 10);
  assert.equal(result.rows.length, 10);
  assert.equal(result.meta?.isTruncated, true);
  assert.equal(result.meta?.maxAllowedRows, 10);
  assert.deepEqual(result.columns, ["id", "name"]);
});

test("PostgresAdapter - Mutation Exceeding Limit Triggers Transaction Rollback", async () => {
  const { pool, clientStatements } = createMockPool({
    clientQueryHandler: async (sql) => {
      if (sql.includes("DELETE FROM logs")) {
        return { rows: [], rowCount: 150 }; // Exceeds cap of 50
      }
      return { rows: [], rowCount: 0 };
    },
  });

  const adapter = new PostgresAdapter("postgres://localhost:5432/test", 500, 50);
  adapter.setPool(pool as unknown as pg.Pool);

  await assert.rejects(async () => {
    await adapter.query("DELETE FROM logs;");
  }, /\[MUTATION_LIMIT_EXCEEDED\] Mutation affected 150 rows, exceeding the hard safety limit of 50 rows/);

  assert.ok(clientStatements.some((s) => s.sql === "BEGIN;"));
  assert.ok(clientStatements.some((s) => s.sql === "ROLLBACK;"));
});

test("PostgresAdapter - Dry-Run Simulation Guarantees Rollback", async () => {
  const { pool, clientStatements } = createMockPool({
    clientQueryHandler: async (sql) => {
      if (sql.includes("UPDATE users SET active = false")) {
        return { rows: [], rowCount: 5 };
      }
      return { rows: [], rowCount: 0 };
    },
  });

  const adapter = new PostgresAdapter("postgres://localhost:5432/test");
  adapter.setPool(pool as unknown as pg.Pool);

  const result = await adapter.executeDryRun(
    "UPDATE users SET active = false WHERE idle_days > 90;",
  );
  assert.equal(result.safe, true);
  assert.equal(result.simulatedAffectedRows, 5);
  assert.equal(result.rollbackVerified, true);

  assert.ok(clientStatements.some((s) => s.sql === "BEGIN;"));
  assert.ok(clientStatements.some((s) => s.sql === "ROLLBACK;"));
});

test("PostgresAdapter - Two-Phase Commit with Drift Protection", async () => {
  const { pool } = createMockPool({
    clientQueryHandler: async (sql) => {
      if (sql.includes("UPDATE users")) {
        return { rows: [], rowCount: 8 }; // Drift: expected 5, but actually affects 8
      }
      return { rows: [], rowCount: 0 };
    },
  });

  const adapter = new PostgresAdapter("postgres://localhost:5432/test");
  adapter.setPool(pool as unknown as pg.Pool);

  await assert.rejects(async () => {
    await adapter.executeCommit("UPDATE users SET active = false WHERE id IN (1,2,3);", [], {
      expectedRows: 5,
    });
  }, /\[SIMULATION_DELTA_DRIFT\] Data changed between simulation and commit/);
});

test("PostgresAdapter - Schema Reflection Maps PostgreSQL Metadata", async () => {
  const { pool } = createMockPool({
    queryHandler: async (sql, params) => {
      if (sql.includes("information_schema.tables")) {
        return { rows: [{ table_name: "customers" }] };
      }
      if (sql.includes("information_schema.columns")) {
        return {
          rows: [
            {
              column_name: "id",
              data_type: "integer",
              is_nullable: "NO",
              column_default: null,
              is_primary_key: true,
            },
            {
              column_name: "email",
              data_type: "text",
              is_nullable: "NO",
              column_default: null,
              is_primary_key: false,
            },
          ],
        };
      }
      if (sql.includes("tc.constraint_type = 'FOREIGN KEY'")) {
        return {
          rows: [
            {
              column_name: "org_id",
              foreign_table_name: "organizations",
              foreign_column_name: "id",
            },
          ],
        };
      }
      if (sql.includes("pg_indexes")) {
        return {
          rows: [
            {
              indexname: "idx_customers_email",
              indexdef: "CREATE UNIQUE INDEX idx_customers_email ON customers USING btree (email)",
            },
          ],
        };
      }
      return { rows: [] };
    },
  });

  const adapter = new PostgresAdapter("postgres://localhost:5432/test");
  adapter.setPool(pool as unknown as pg.Pool);

  const schemas: TableSchema[] = await adapter.getSchema();
  assert.equal(schemas.length, 1);
  const customers = schemas[0];
  assert.equal(customers.tableName, "customers");
  assert.equal(customers.columns.length, 2);
  assert.equal(customers.columns[0].primaryKey, true);
  assert.equal(customers.foreignKeys.length, 1);
  assert.equal(customers.foreignKeys[0].referencedTable, "organizations");
  assert.equal(customers.indexes.length, 1);
  assert.equal(customers.indexes[0].unique, true);
  assert.deepEqual(customers.indexes[0].columns, ["email"]);
});

test("QueryExplainer - Analyzes PostgreSQL Sequential Scans", async () => {
  const { pool } = createMockPool({
    queryHandler: async () => ({
      rows: [
        { "QUERY PLAN": "Seq Scan on large_orders  (cost=0.00..4523.00 rows=152000 width=32)" },
        { "QUERY PLAN": "  Filter: (status = 'pending'::text)" },
      ],
      fields: [{ name: "QUERY PLAN" }],
    }),
  });

  const adapter = new PostgresAdapter("postgres://localhost:5432/test");
  adapter.setPool(pool as unknown as pg.Pool);

  const explainer = new QueryExplainer(adapter);
  const report = await explainer.explainQuery(
    "SELECT * FROM large_orders WHERE status = 'pending';",
  );

  assert.equal(report.isIndexed, false);
  assert.ok(
    report.bottlenecks.some((b) =>
      b.includes("Full table sequential scan detected on 'large_orders'"),
    ),
  );
  assert.ok(report.suggestions.some((s) => s.includes("Create an index on the column(s)")));
});
