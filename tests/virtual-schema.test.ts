import assert from "node:assert";
import test from "node:test";
import { SqliteAdapter } from "../src/adapters/sqlite.js";
import { SqlGuardEngine } from "../src/guard/engine.js";
import { VirtualSchemaManager } from "../src/guard/virtual-schema.js";
import type { DBShieldConfig, TableSchema } from "../src/types/index.js";

test("Virtual Schema Masking - Table hiding and glob matching", () => {
  const vsm = new VirtualSchemaManager({
    enabled: true,
    hiddenTables: ["credentials", "internal_audit", "admin_*", "secret_*"],
    defaultRole: "agent",
  });

  assert.strictEqual(vsm.isTableHidden("credentials"), true);
  assert.strictEqual(vsm.isTableHidden("internal_audit"), true);
  assert.strictEqual(vsm.isTableHidden("admin_keys"), true);
  assert.strictEqual(vsm.isTableHidden("admin_roles"), true);
  assert.strictEqual(vsm.isTableHidden("secret_tokens"), true);
  assert.strictEqual(vsm.isTableHidden("users"), false);
  assert.strictEqual(vsm.isTableHidden("orders"), false);
});

test("Virtual Schema Masking - Column-level RBAC", () => {
  const vsm = new VirtualSchemaManager({
    enabled: true,
    hiddenTables: ["internal_audit"],
    hiddenColumns: {
      users: ["password_hash", "totp_secret", "ssn"],
    },
    defaultRole: "agent",
  });

  assert.strictEqual(vsm.isColumnHidden("users", "password_hash"), true);
  assert.strictEqual(vsm.isColumnHidden("users", "totp_secret"), true);
  assert.strictEqual(vsm.isColumnHidden("users", "email"), false);
  assert.strictEqual(vsm.isColumnHidden("users", "id"), false);
  // Column on hidden table is always hidden
  assert.strictEqual(vsm.isColumnHidden("internal_audit", "action"), true);
});

test("Virtual Schema Masking - Role-based access control (RBAC)", () => {
  const vsm = new VirtualSchemaManager({
    enabled: true,
    hiddenTables: ["credentials"],
    roles: {
      analyst: {
        allowedTables: ["public_metrics", "reports"],
      },
      agent: {
        deniedTables: ["financial_ledger"],
        deniedColumns: {
          customers: ["credit_card"],
        },
      },
    },
    defaultRole: "agent",
  });

  // Analyst role is restricted by allowedTables whitelist
  assert.strictEqual(vsm.isTableHidden("public_metrics", "analyst"), false);
  assert.strictEqual(vsm.isTableHidden("users", "analyst"), true);

  // Agent role is restricted by deniedTables
  assert.strictEqual(vsm.isTableHidden("financial_ledger", "agent"), true);
  assert.strictEqual(vsm.isTableHidden("customers", "agent"), false);
  assert.strictEqual(vsm.isColumnHidden("customers", "credit_card", "agent"), true);
  assert.strictEqual(vsm.isColumnHidden("customers", "name", "agent"), false);
});

test("Virtual Schema Masking - Filters TableSchema arrays and masks columns", () => {
  const vsm = new VirtualSchemaManager({
    enabled: true,
    hiddenTables: ["credentials", "admin_*"],
    hiddenColumns: {
      users: ["password_hash"],
    },
  });

  const rawSchemas: TableSchema[] = [
    {
      tableName: "users",
      columns: [
        { name: "id", type: "INTEGER", nullable: false, primaryKey: true },
        { name: "email", type: "TEXT", nullable: false, primaryKey: false },
        { name: "password_hash", type: "TEXT", nullable: false, primaryKey: false },
      ],
      foreignKeys: [],
      indexes: [
        { name: "idx_users_email", columns: ["email"], unique: true },
        { name: "idx_users_pw", columns: ["password_hash"], unique: false },
      ],
    },
    {
      tableName: "credentials",
      columns: [{ name: "key", type: "TEXT", nullable: false, primaryKey: true }],
      foreignKeys: [],
      indexes: [],
    },
    {
      tableName: "admin_keys",
      columns: [{ name: "secret", type: "TEXT", nullable: false, primaryKey: true }],
      foreignKeys: [],
      indexes: [],
    },
  ];

  const filtered = vsm.filterTableSchemas(rawSchemas);
  assert.strictEqual(filtered.length, 1);
  assert.strictEqual(filtered[0].tableName, "users");
  // password_hash column must be stripped
  assert.strictEqual(filtered[0].columns.length, 2);
  assert.strictEqual(
    filtered[0].columns.some((c) => c.name === "password_hash"),
    false,
  );
  // pw index referencing password_hash must be stripped
  assert.strictEqual(filtered[0].indexes.length, 1);
  assert.strictEqual(filtered[0].indexes[0].name, "idx_users_email");
});

test("Virtual Schema Masking - Filters introspection query rows from information_schema", () => {
  const vsm = new VirtualSchemaManager({
    enabled: true,
    hiddenTables: ["credentials", "internal_audit"],
    hiddenColumns: {
      users: ["password_hash"],
    },
  });

  const introspectionRows = [
    { table_name: "users" },
    { table_name: "orders" },
    { table_name: "credentials" },
    { table_name: "internal_audit" },
  ];

  const filtered = vsm.filterIntrospectionRows(introspectionRows, "postgres");
  assert.strictEqual(filtered.length, 2);
  assert.strictEqual(filtered[0].table_name, "users");
  assert.strictEqual(filtered[1].table_name, "orders");
});

test("Virtual Schema Guardrail - Blocks queries accessing hidden tables or columns", () => {
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
    virtualSchema: {
      enabled: true,
      hiddenTables: ["credentials", "admin_*"],
      hiddenColumns: {
        users: ["password_hash"],
      },
    },
  };

  const guard = new SqlGuardEngine(config);

  // 1. Querying hidden table
  const evalHiddenTbl = guard.evaluate("SELECT * FROM credentials;");
  assert.strictEqual(evalHiddenTbl.allowed, false);
  assert.strictEqual(
    evalHiddenTbl.violations.some((v) => v.code === "RBAC_TABLE_ACCESS_DENIED"),
    true,
  );

  // 2. Querying wildcard hidden table
  const evalWildcard = guard.evaluate("SELECT * FROM admin_keys;");
  assert.strictEqual(evalWildcard.allowed, false);
  assert.strictEqual(
    evalWildcard.violations.some((v) => v.code === "RBAC_TABLE_ACCESS_DENIED"),
    true,
  );

  // 3. Querying hidden column
  const evalHiddenCol = guard.evaluate("SELECT id, email, password_hash FROM users WHERE id = 1;");
  assert.strictEqual(evalHiddenCol.allowed, false);
  assert.strictEqual(
    evalHiddenCol.violations.some((v) => v.code === "RBAC_COLUMN_ACCESS_DENIED"),
    true,
  );

  // 4. Allowed visible query
  const evalAllowed = guard.evaluate("SELECT id, email FROM users WHERE id = 1;");
  assert.strictEqual(evalAllowed.allowed, true);
});

test("Virtual Schema Masking - SqliteAdapter hides tables and columns", async () => {
  const vsm = new VirtualSchemaManager({
    enabled: true,
    hiddenTables: ["credentials"],
    hiddenColumns: {
      users: ["password_hash"],
    },
  });

  const adapter = new SqliteAdapter(":memory:", 500, 50, 5000, vsm);
  await adapter.connect();

  await adapter.query(`
    CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT);
    CREATE TABLE credentials (id INTEGER PRIMARY KEY, secret_key TEXT);
  `);

  // getSchema must only return users
  const schemas = await adapter.getSchema();
  assert.strictEqual(schemas.length, 1);
  assert.strictEqual(schemas[0].tableName, "users");
  assert.strictEqual(
    schemas[0].columns.some((c) => c.name === "password_hash"),
    false,
  );

  // Introspecting hidden table directly returns null
  const credsSchema = await adapter.getTableSchema("credentials");
  assert.strictEqual(credsSchema, null);

  await adapter.disconnect();
});
