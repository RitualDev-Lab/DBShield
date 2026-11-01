import assert from "node:assert";
import test from "node:test";
import { SqliteAdapter } from "../src/adapters/sqlite.js";
import { QueryPlanAdvisor } from "../src/explain/advisor.js";
import { QueryExplainer } from "../src/explain/index.js";
import type { ExplainReport } from "../src/types/index.js";

test("QueryPlanAdvisor - Extracts predicate columns from WHERE and JOIN clauses", () => {
  const sql = "SELECT * FROM users WHERE email = 'test@example.com' AND status = 'active';";
  const cols = QueryPlanAdvisor.extractPredicateColumns(sql, "users", "sqlite");

  assert.strictEqual(cols.includes("email"), true);
  assert.strictEqual(cols.includes("status"), true);
});

test("QueryPlanAdvisor - Generates optimal index DDL for PostgreSQL and SQLite", () => {
  const pgDdl = QueryPlanAdvisor.generateIndexDdl("users", ["email", "status"], "postgres");
  assert.strictEqual(
    pgDdl.ddl,
    'CREATE INDEX CONCURRENTLY idx_users_email_status ON users ("email", "status");',
  );

  const sqliteDdl = QueryPlanAdvisor.generateIndexDdl("users", ["email"], "sqlite");
  assert.strictEqual(sqliteDdl.ddl, 'CREATE INDEX idx_users_email ON users ("email");');
});

test("QueryPlanAdvisor - Severity classification based on row and cost regressions", () => {
  const sql = "SELECT * FROM large_orders WHERE customer_id = 42;";
  const report: ExplainReport = {
    rawPlan: [{ detail: "SCAN large_orders" }],
    bottlenecks: ["Full table sequential scan detected on 'large_orders'."],
    suggestions: [],
    isIndexed: false,
    hasSeqScan: true,
    estimatedRows: 85000,
    estimatedCost: 15000,
  };

  const advice = QueryPlanAdvisor.analyze(sql, report, "postgres");
  assert.strictEqual(advice.hasRegression, true);
  assert.strictEqual(advice.advice.length, 1);
  assert.strictEqual(advice.advice[0].tableName, "large_orders");
  assert.strictEqual(advice.advice[0].regressiveSeverity, "CRITICAL");
  assert.strictEqual(
    advice.suggestedDdls[0],
    'CREATE INDEX CONCURRENTLY idx_large_orders_customer_id ON large_orders ("customer_id");',
  );
});

test("QueryExplainer & QueryPlanAdvisor - End-to-end unindexed query scan analysis", async () => {
  const adapter = new SqliteAdapter(":memory:");
  await adapter.connect();

  await adapter.query(`
    CREATE TABLE employees (id INTEGER PRIMARY KEY, department TEXT, salary REAL);
    INSERT INTO employees (department, salary) VALUES ('Engineering', 120000);
  `);

  const explainer = new QueryExplainer(adapter);
  const report = await explainer.explainQuery(
    "SELECT * FROM employees WHERE department = 'Engineering';",
  );

  assert.strictEqual(report.hasSeqScan, true);
  assert.strictEqual(report.isIndexed, false);
  assert.ok(report.missingIndexes);
  assert.strictEqual(report.missingIndexes.length, 1);
  assert.strictEqual(report.missingIndexes[0].tableName, "employees");
  assert.strictEqual(report.missingIndexes[0].columns.includes("department"), true);
  assert.strictEqual(
    report.suggestions.some((s) => s.includes("CREATE INDEX idx_employees_department")),
    true,
  );

  await adapter.disconnect();
});
