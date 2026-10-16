import assert from "node:assert/strict";
import test from "node:test";
import { SqliteAdapter } from "../src/adapters/sqlite.js";
import { parseSql, stripSqlComments } from "../src/guard/ast.js";
import { SqlGuardEngine } from "../src/guard/engine.js";

test("Phase 1 (B5): stripSqlComments removes comments while preserving string literals", () => {
  assert.equal(stripSqlComments(""), "");
  assert.equal(stripSqlComments("-- single line comment"), "");
  assert.equal(stripSqlComments("/* multi line comment */"), "");
  assert.equal(stripSqlComments("-- first\n-- second\n"), "");

  // Preserves comments inside string literals
  assert.equal(
    stripSqlComments("SELECT * FROM users WHERE note = 'hello -- not a comment';"),
    "SELECT * FROM users WHERE note = 'hello -- not a comment';",
  );
  assert.equal(
    stripSqlComments("SELECT * FROM users WHERE note = '/* keep me */';"),
    "SELECT * FROM users WHERE note = '/* keep me */';",
  );

  // Strips actual comments around SQL
  assert.equal(stripSqlComments("-- comment before\nSELECT 1;"), "SELECT 1;");
  assert.equal(stripSqlComments("/* block before */ SELECT 1;"), "SELECT 1;");
});

test("Phase 1 (B5): SqliteAdapter executes CTE queries and returns rows properly", async () => {
  const adapter = new SqliteAdapter(":memory:");
  await adapter.connect();

  await adapter.query(`
    CREATE TABLE projects (
      id INTEGER PRIMARY KEY,
      title TEXT NOT NULL,
      stars INTEGER DEFAULT 0
    );
  `);

  await adapter.query(
    "INSERT INTO projects (id, title, stars) VALUES (1, 'DBShield', 500), (2, 'AgentShield', 1000);",
  );

  // 1. Common Table Expression (CTE) query
  const cteQuery = `
    WITH popular_projects AS (
      SELECT id, title, stars FROM projects WHERE stars >= 500
    )
    SELECT * FROM popular_projects ORDER BY stars DESC;
  `;

  const cteRes = await adapter.query(cteQuery);
  assert.equal(cteRes.rowCount, 2, "CTE should return 2 rows");
  assert.equal(cteRes.rows[0].title, "AgentShield");
  assert.equal(cteRes.rows[1].title, "DBShield");
  assert.deepEqual(cteRes.columns, ["id", "title", "stars"]);

  await adapter.disconnect();
});

test("Phase 1 (B5): SqliteAdapter executes queries with leading comments and returns rows", async () => {
  const adapter = new SqliteAdapter(":memory:");
  await adapter.connect();

  await adapter.query("CREATE TABLE items (id INT, label TEXT);");
  await adapter.query("INSERT INTO items VALUES (1, 'alpha'), (2, 'beta');");

  // Single-line comment prefix
  const singleLineCommentQuery = `
    -- Fetch all items for active dashboard
    SELECT * FROM items ORDER BY id ASC;
  `;
  const res1 = await adapter.query(singleLineCommentQuery);
  assert.equal(res1.rowCount, 2, "Should return 2 rows despite leading single-line comment");
  assert.equal(res1.rows[0].label, "alpha");

  // Multi-line block comment prefix
  const multiLineCommentQuery = `
    /* 
      Audit ID: 99482
      Target: Items table
    */
    SELECT * FROM items WHERE id = 2;
  `;
  const res2 = await adapter.query(multiLineCommentQuery);
  assert.equal(res2.rowCount, 1, "Should return 1 row despite leading block comment");
  assert.equal(res2.rows[0].label, "beta");

  // CTE with leading comment
  const commentedCteQuery = `
    -- Run analytics CTE
    WITH ranked AS (
      SELECT id, label FROM items WHERE id = 1
    )
    SELECT * FROM ranked;
  `;
  const res3 = await adapter.query(commentedCteQuery);
  assert.equal(res3.rowCount, 1);
  assert.equal(res3.rows[0].label, "alpha");

  // Empty and comment-only queries return safely without throw
  const emptyRes = await adapter.query("-- just a comment without statement");
  assert.equal(emptyRes.rowCount, 0);
  assert.equal(emptyRes.rows.length, 0);

  await adapter.disconnect();
});

test("Phase 1 (B5): SqlGuardEngine handles comments, CTE target tables, and comment-only queries", () => {
  const guard = new SqlGuardEngine({
    dialect: "sqlite",
    safetyTier: "BALANCED",
    maxRowsPerMutation: 50,
    allowDestructiveDDL: false,
    enablePiiMasking: true,
  });

  // 1. Comment-only query evaluation fails gracefully with EMPTY_QUERY violation
  const emptyEval = guard.evaluate("-- this is only a comment\n-- second comment");
  assert.equal(emptyEval.allowed, false);
  assert.equal(emptyEval.violations[0].code, "EMPTY_QUERY");

  // 2. Destructive query with leading comments is strictly caught and blocked
  const dropWithComment = guard.evaluate(`
    -- Attempting to sneak past prefix filters
    DROP TABLE users;
  `);
  assert.equal(dropWithComment.allowed, false);
  assert.equal(dropWithComment.riskLevel, "CRITICAL");
  assert.equal(dropWithComment.violations[0].code, "DESTRUCTIVE_DDL_BLOCKED");

  // 3. CTE query correctly resolves underlying tables
  const cteEval = guard.evaluate(`
    WITH active_users AS (
      SELECT id, email FROM users WHERE active = 1
    )
    SELECT * FROM active_users;
  `);
  assert.equal(cteEval.allowed, true);
  assert.equal(cteEval.operation, "SELECT");
  assert.ok(cteEval.targetTables.includes("users"), "Should detect underlying table 'users'");

  // 4. Mutation with leading comment is properly routed to mutation check
  const updateWithComment = guard.evaluate(`
    /* Update profile */
    UPDATE users SET role = 'guest' WHERE id = 42;
  `);
  assert.equal(updateWithComment.allowed, true);
  assert.equal(updateWithComment.operation, "UPDATE");
  assert.ok(updateWithComment.targetTables.includes("users"));
});
