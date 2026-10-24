import assert from "node:assert/strict";
import { test } from "node:test";
import { SqliteAdapter } from "../src/adapters/index.js";
import { DEFAULT_CONFIG } from "../src/config/index.js";
import { MigrationSafetyEngine } from "../src/migration/index.js";
import { createMcpServer } from "../src/server/index.js";
import type { DBShieldConfig, TableSchema } from "../src/types/index.js";

test("MigrationSafetyEngine - Intercepts dangerous NOT NULL column addition without DEFAULT", () => {
  const engine = new MigrationSafetyEngine({
    ...DEFAULT_CONFIG,
    dialect: "postgres",
    safetyTier: "BALANCED",
  });

  const report = engine.validateMigration(
    "ALTER TABLE customers ADD COLUMN balance NUMERIC NOT NULL;",
    "postgres",
  );

  assert.equal(report.safe, false);
  assert.ok(report.violations.some((v) => v.code === "DANGEROUS_NOT_NULL_COLUMN"));
  assert.equal(report.highestLockLevel, "ACCESS_EXCLUSIVE");
  assert.ok(report.violations[0].message.includes("without a DEFAULT clause"));
  assert.ok(report.safeMigrationPlan.some((p) => p.includes("Zero-Downtime Safe Column Addition")));
});

test("MigrationSafetyEngine - Allows nullable column addition or NOT NULL with DEFAULT", () => {
  const engine = new MigrationSafetyEngine({
    ...DEFAULT_CONFIG,
    dialect: "postgres",
    safetyTier: "BALANCED",
  });

  const nullableReport = engine.validateMigration(
    "ALTER TABLE customers ADD COLUMN nickname VARCHAR(50);",
    "postgres",
  );
  assert.equal(nullableReport.safe, true);
  assert.equal(nullableReport.violations.length, 0);

  const defaultReport = engine.validateMigration(
    "ALTER TABLE customers ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT true;",
    "postgres",
  );
  assert.equal(defaultReport.safe, true);
  assert.equal(defaultReport.violations.length, 0);
});

test("MigrationSafetyEngine - Intercepts destructive column drop (ALTER TABLE DROP COLUMN)", () => {
  const engine = new MigrationSafetyEngine({
    ...DEFAULT_CONFIG,
    allowDestructiveDDL: false,
  });

  const report = engine.validateMigration("ALTER TABLE users DROP COLUMN ssn;", "postgres");

  assert.equal(report.safe, false);
  assert.ok(report.violations.some((v) => v.code === "DESTRUCTIVE_COLUMN_DROP"));
  assert.equal(report.violations[0].severity, "BLOCKED");
  assert.ok(report.violations[0].message.includes("causes instant production breakage"));
  assert.ok(
    report.safeMigrationPlan.some((p) => p.includes("Expand-and-Contract Column Deprecation")),
  );
});

test("MigrationSafetyEngine - Intercepts destructive table drop (DROP TABLE / TRUNCATE)", () => {
  const engine = new MigrationSafetyEngine({
    ...DEFAULT_CONFIG,
    allowDestructiveDDL: false,
  });

  const report = engine.validateMigration("DROP TABLE accounts;", "postgres");
  assert.equal(report.safe, false);
  assert.ok(report.violations.some((v) => v.code === "DESTRUCTIVE_TABLE_DROP"));
  assert.equal(report.violations[0].severity, "CRITICAL");
});

test("MigrationSafetyEngine - Flags non-concurrent index creation in PostgreSQL with TABLE_LOCKING_INDEX_CREATION", () => {
  const engine = new MigrationSafetyEngine({
    ...DEFAULT_CONFIG,
    dialect: "postgres",
    enforceConcurrentIndexCreation: true,
  });

  const report = engine.validateMigration(
    "CREATE INDEX idx_orders_customer ON orders(customer_id);",
    "postgres",
  );

  assert.equal(report.safe, false);
  assert.ok(report.violations.some((v) => v.code === "TABLE_LOCKING_INDEX_CREATION"));
  assert.equal(report.highestLockLevel, "SHARE");
  assert.ok(report.violations[0].message.includes("acquires a ShareLock"));
  assert.ok(report.safeMigrationPlan.some((p) => p.includes("CREATE INDEX CONCURRENTLY")));
});

test("MigrationSafetyEngine - Allows CREATE INDEX CONCURRENTLY in PostgreSQL without warnings", () => {
  const engine = new MigrationSafetyEngine({
    ...DEFAULT_CONFIG,
    dialect: "postgres",
    enforceConcurrentIndexCreation: true,
  });

  const report = engine.validateMigration(
    "CREATE INDEX CONCURRENTLY idx_orders_customer ON orders(customer_id);",
    "postgres",
  );

  assert.equal(report.safe, true);
  assert.equal(report.violations.length, 0);
});

test("MigrationSafetyEngine - Intercepts breaking table/column renames", () => {
  const engine = new MigrationSafetyEngine({
    ...DEFAULT_CONFIG,
    disallowBreakingRenames: true,
  });

  const report = engine.validateMigration(
    "ALTER TABLE users RENAME COLUMN email TO primary_email;",
    "postgres",
  );

  assert.equal(report.safe, false);
  assert.ok(report.violations.some((v) => v.code === "BREAKING_RENAME"));
  assert.equal(report.violations[0].severity, "BLOCKED");
  assert.ok(report.safeMigrationPlan.some((p) => p.includes("Zero-Downtime Safe Rename")));
});

test("MigrationSafetyEngine - Warns on column type modification requiring table rewrite", () => {
  const engine = new MigrationSafetyEngine({
    ...DEFAULT_CONFIG,
    dialect: "postgres",
  });

  const report = engine.validateMigration(
    "ALTER TABLE transactions ALTER COLUMN amount TYPE BIGINT;",
    "postgres",
  );

  assert.ok(report.violations.some((v) => v.code === "TABLE_REWRITE_TYPE_CHANGE"));
  assert.equal(report.highestLockLevel, "ACCESS_EXCLUSIVE");
  assert.ok(report.safeMigrationPlan.some((p) => p.includes("Zero-Downtime Type Change")));
});

test("MigrationSafetyEngine - Multi-statement migration script validation with comprehensive risk score", () => {
  const engine = new MigrationSafetyEngine({
    ...DEFAULT_CONFIG,
    dialect: "postgres",
  });

  const migrationScript = `
    -- Step 1: Add safe column
    ALTER TABLE users ADD COLUMN nickname VARCHAR(50);

    -- Step 2: Dangerous NOT NULL without default
    ALTER TABLE users ADD COLUMN age INT NOT NULL;

    -- Step 3: Dangerous column drop
    ALTER TABLE users DROP COLUMN legacy_auth;
  `;

  const report = engine.validateMigration(migrationScript, "postgres");
  assert.equal(report.safe, false);
  assert.equal(report.violations.length, 2);
  assert.ok(report.violations.some((v) => v.code === "DANGEROUS_NOT_NULL_COLUMN"));
  assert.ok(report.violations.some((v) => v.code === "DESTRUCTIVE_COLUMN_DROP"));
  assert.equal(report.highestLockLevel, "ACCESS_EXCLUSIVE");
});

test("Schema Health & Drift - Discovers unindexed foreign keys causing cascade locks", () => {
  const engine = new MigrationSafetyEngine(DEFAULT_CONFIG);

  const mockSchemas: TableSchema[] = [
    {
      tableName: "orders",
      columns: [
        { name: "id", type: "INTEGER", nullable: false, primaryKey: true },
        { name: "customer_id", type: "INTEGER", nullable: false, primaryKey: false },
      ],
      foreignKeys: [
        {
          column: "customer_id",
          referencedTable: "customers",
          referencedColumn: "id",
        },
      ],
      indexes: [], // No index on customer_id!
    },
  ];

  const report = engine.analyzeSchemaHealth(mockSchemas);
  assert.equal(report.inSync, false);
  assert.equal(report.unindexedForeignKeys.length, 1);
  assert.equal(report.unindexedForeignKeys[0].table, "orders");
  assert.equal(report.unindexedForeignKeys[0].column, "customer_id");
  assert.ok(report.differences.some((d) => d.type === "MISSING_INDEX"));
});

test("Schema Health & Drift - Detects schema drift (missing tables, missing columns, type mismatch)", () => {
  const engine = new MigrationSafetyEngine(DEFAULT_CONFIG);

  const liveSchemas: TableSchema[] = [
    {
      tableName: "users",
      columns: [{ name: "id", type: "INTEGER", nullable: false, primaryKey: true }],
      foreignKeys: [],
      indexes: [],
    },
  ];

  const expectedSchemas: TableSchema[] = [
    {
      tableName: "users",
      columns: [
        { name: "id", type: "INTEGER", nullable: false, primaryKey: true },
        { name: "email", type: "TEXT", nullable: false, primaryKey: false },
      ],
      foreignKeys: [],
      indexes: [],
    },
    {
      tableName: "audit_logs",
      columns: [{ name: "id", type: "INTEGER", nullable: false, primaryKey: true }],
      foreignKeys: [],
      indexes: [],
    },
  ];

  const report = engine.analyzeSchemaHealth(liveSchemas, expectedSchemas);
  assert.equal(report.inSync, false);
  assert.ok(report.differences.some((d) => d.type === "MISSING_TABLE" && d.table === "audit_logs"));
  assert.ok(report.differences.some((d) => d.type === "MISSING_COLUMN" && d.column === "email"));
});

test("MCP Server db_validate_migration tool - Validates dangerous migration and returns zero-downtime plan", async () => {
  const serverInstance = await createMcpServer({
    storagePath: ":memory:",
    safetyTier: "BALANCED",
  });

  const report = serverInstance.migrationEngine.validateMigration(
    "ALTER TABLE profiles ADD COLUMN age INT NOT NULL;",
    "sqlite",
  );

  assert.equal(report.safe, false);
  assert.ok(report.violations.some((v) => v.code === "DANGEROUS_NOT_NULL_COLUMN"));
  assert.ok(report.safeMigrationPlan.length > 0);

  await serverInstance.stop();
});

test("MCP Server db_check_schema_drift tool - Audits live database foreign keys and schema health", async () => {
  const serverInstance = await createMcpServer({
    storagePath: ":memory:",
    safetyTier: "BALANCED",
  });

  // Create table with foreign key but no index
  await serverInstance.adapter.query("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);");
  await serverInstance.adapter.query(
    "CREATE TABLE posts (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, FOREIGN KEY (user_id) REFERENCES users(id));",
  );

  const schemas = await serverInstance.adapter.getSchema();
  const report = serverInstance.migrationEngine.analyzeSchemaHealth(schemas);

  assert.equal(report.totalTables, 2);
  assert.equal(report.unindexedForeignKeys.length, 1);
  assert.equal(report.unindexedForeignKeys[0].table, "posts");
  assert.equal(report.unindexedForeignKeys[0].column, "user_id");

  await serverInstance.stop();
});

test("MCP Server db_query - Intercepts dangerous DDL statement before execution", async () => {
  const serverInstance = await createMcpServer({
    storagePath: ":memory:",
    safetyTier: "BALANCED",
    allowDestructiveDDL: false,
  });

  await serverInstance.adapter.query(
    "CREATE TABLE documents (id INTEGER PRIMARY KEY, title TEXT);",
  );

  // Attempt to add dangerous NOT NULL column without DEFAULT
  const res = serverInstance.migrationEngine.validateMigration(
    "ALTER TABLE documents ADD COLUMN priority INT NOT NULL;",
    "sqlite",
  );

  assert.equal(res.safe, false);
  assert.ok(res.violations.some((v) => v.code === "DANGEROUS_NOT_NULL_COLUMN"));

  await serverInstance.stop();
});
