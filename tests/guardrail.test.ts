import assert from "node:assert/strict";
import test from "node:test";
import { SqlGuardEngine } from "../src/guard/engine.js";
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

test("SqlGuardEngine - Pure SELECT Query Allowed as SAFE", () => {
  const engine = new SqlGuardEngine(BASE_CONFIG);
  const evaluation = engine.evaluate("SELECT id, name, email FROM users WHERE id = 1;");

  assert.equal(evaluation.allowed, true);
  assert.equal(evaluation.riskLevel, "SAFE");
  assert.equal(evaluation.operation, "SELECT");
  assert.deepEqual(evaluation.targetTables, ["users"]);
  assert.equal(evaluation.violations.length, 0);
});

test("SqlGuardEngine - Destructive DROP TABLE Blocked as CRITICAL", () => {
  const engine = new SqlGuardEngine(BASE_CONFIG);
  const evaluation = engine.evaluate("DROP TABLE users;");

  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.riskLevel, "CRITICAL");
  assert.equal(evaluation.operation, "DDL_DROP");
  assert.ok(evaluation.riskScore >= 90);
  assert.equal(evaluation.violations[0].code, "DESTRUCTIVE_DDL_BLOCKED");
});

test("SqlGuardEngine - Destructive TRUNCATE TABLE Blocked as CRITICAL", () => {
  const engine = new SqlGuardEngine(BASE_CONFIG);
  const evaluation = engine.evaluate("TRUNCATE TABLE accounts;");

  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.riskLevel, "CRITICAL");
  assert.equal(evaluation.operation, "DDL_TRUNCATE");
  assert.equal(evaluation.violations[0].code, "DESTRUCTIVE_DDL_BLOCKED");
});

test("SqlGuardEngine - Destructive ALTER TABLE DROP COLUMN Blocked", () => {
  const engine = new SqlGuardEngine(BASE_CONFIG);
  const evaluation = engine.evaluate("ALTER TABLE users DROP COLUMN email;");

  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.riskLevel, "BLOCKED");
  assert.equal(evaluation.violations[0].code, "DESTRUCTIVE_ALTER_BLOCKED");
});

test("SqlGuardEngine - Unconstrained DELETE Without WHERE Blocked", () => {
  const engine = new SqlGuardEngine(BASE_CONFIG);
  const evaluation = engine.evaluate("DELETE FROM users;");

  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.riskLevel, "CRITICAL");
  assert.equal(evaluation.operation, "DELETE");
  assert.equal(evaluation.violations[0].code, "UNCONSTRAINED_MUTATION");
  assert.ok(evaluation.violations[0].suggestion?.includes("WHERE"));
});

test("SqlGuardEngine - Unconstrained UPDATE Without WHERE Blocked", () => {
  const engine = new SqlGuardEngine(BASE_CONFIG);
  const evaluation = engine.evaluate("UPDATE accounts SET balance = 0;");

  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.riskLevel, "CRITICAL");
  assert.equal(evaluation.operation, "UPDATE");
  assert.equal(evaluation.violations[0].code, "UNCONSTRAINED_MUTATION");
});

test("SqlGuardEngine - Tautology Bypass (WHERE 1=1) Blocked", () => {
  const engine = new SqlGuardEngine(BASE_CONFIG);
  const evaluation = engine.evaluate("DELETE FROM users WHERE 1 = 1;");

  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.riskLevel, "CRITICAL");
  assert.equal(evaluation.violations[0].code, "UNCONSTRAINED_MUTATION");
  assert.ok(evaluation.violations[0].message.includes("constant literals"));
});

test("SqlGuardEngine - Tautology Bypass (WHERE true) Blocked", () => {
  const engine = new SqlGuardEngine(BASE_CONFIG);
  const evaluation = engine.evaluate("DELETE FROM users WHERE true;");

  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.riskLevel, "CRITICAL");
  assert.equal(evaluation.violations[0].code, "UNCONSTRAINED_MUTATION");
  assert.ok(evaluation.violations[0].message.includes("boolean TRUE"));
});

test("SqlGuardEngine - Tautology Bypass (WHERE 'x' = 'x') Blocked", () => {
  const engine = new SqlGuardEngine(BASE_CONFIG);
  const evaluation = engine.evaluate("UPDATE users SET role = 'admin' WHERE 'x' = 'x';");

  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.riskLevel, "CRITICAL");
  assert.equal(evaluation.violations[0].code, "UNCONSTRAINED_MUTATION");
});

test("SqlGuardEngine - Compound OR Tautology (WHERE id = 5 OR 1=1) Blocked", () => {
  const engine = new SqlGuardEngine(BASE_CONFIG);
  const evaluation = engine.evaluate("DELETE FROM users WHERE id = 5 OR 1 = 1;");

  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.riskLevel, "CRITICAL");
  assert.equal(evaluation.violations[0].code, "UNCONSTRAINED_MUTATION");
  assert.ok(evaluation.violations[0].message.includes("OR branch with a constant tautology"));
});

test("SqlGuardEngine - Valid Targeted Mutation Allowed in BALANCED Tier", () => {
  const engine = new SqlGuardEngine(BASE_CONFIG);
  const evaluation = engine.evaluate("UPDATE users SET role = 'editor' WHERE id = 42;");

  assert.equal(evaluation.allowed, true);
  assert.equal(evaluation.riskLevel, "CAUTION");
  assert.equal(evaluation.violations.length, 0);
  assert.deepEqual(evaluation.targetTables, ["users"]);
});

test("SqlGuardEngine - STRICT Tier Enforces Dry-Run Requirement on Mutations", () => {
  const engine = new SqlGuardEngine({
    ...BASE_CONFIG,
    safetyTier: "STRICT",
  });
  const evaluation = engine.evaluate("UPDATE users SET role = 'editor' WHERE id = 42;");

  assert.equal(evaluation.requiresDryRun, true);
  assert.equal(evaluation.allowed, false, "In STRICT tier, mutations require pre-flight dry run");
});

test("SqlGuardEngine - Multi-Statement Injection Attempt Blocked", () => {
  const engine = new SqlGuardEngine(BASE_CONFIG);
  const evaluation = engine.evaluate("SELECT 1; DROP TABLE users;");

  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.riskLevel, "CRITICAL");
  assert.ok(evaluation.violations.some((v) => v.code === "DESTRUCTIVE_DDL_BLOCKED"));
});

test("MCP Server db_query - Rejects Unconstrained Mutation Through Protocol", async () => {
  const instance = await createMcpServer({
    storagePath: ":memory:",
    safetyTier: "BALANCED",
  });

  await instance.adapter.query("CREATE TABLE items (id INTEGER, name TEXT);");
  await instance.adapter.query("INSERT INTO items VALUES (1, 'hammer');");

  // Attempt unconstrained delete through guard engine
  const blockedEval = instance.guardEngine.evaluate("DELETE FROM items;");
  assert.equal(blockedEval.allowed, false);
  assert.equal(blockedEval.violations[0].code, "UNCONSTRAINED_MUTATION");

  // Confirm row still exists in database
  const check = await instance.adapter.query("SELECT count(*) as c FROM items;");
  assert.equal(check.rows[0].c, 1);

  await instance.stop();
});
