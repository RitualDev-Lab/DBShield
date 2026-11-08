import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { SqliteAdapter } from "../src/adapters/sqlite.js";
import { DEFAULT_CONFIG } from "../src/config/index.js";
import { normalizeSqlForAudit, parseSql } from "../src/guard/ast.js";
import { SqlGuardEngine } from "../src/guard/engine.js";
import { SandboxEngine } from "../src/sandbox/engine.js";

describe("Phase 1: DBShield SQL Normalizer, Read-Only Envelopes & Intent-Effect Gap", () => {
  describe("AST Lexical Token Normalizer (normalizeSqlForAudit)", () => {
    it("neutralizes zero-width and invisible unicode characters (Unicode smuggling)", () => {
      const sqlWithZeroWidth = "SEL\u200BECT \uFEFF* FROM \u200Dusers\u00A0WHERE id = 1";
      const result = normalizeSqlForAudit(sqlWithZeroWidth);

      assert.equal(result.hasUnicodeSmuggling, true);
      assert.equal(result.normalizedSql, "SELECT * FROM users WHERE id = 1");
      assert.deepEqual(result.tokens, ["SELECT", "*", "FROM", "users", "WHERE", "id", "=", "1"]);
    });

    it("detects inline comment evasion within keywords (e.g. SEL/**/ECT)", () => {
      const evasionSql = "SEL/**/ECT * FR/**/OM users";
      const result = normalizeSqlForAudit(evasionSql);

      assert.equal(result.hasCommentEvasion, true);
      assert.equal(result.normalizedSql, "SELECT * FROM users");
    });

    it("detects unquoted multi-statement injection while preserving semicolons inside strings", () => {
      const injectionSql = "SELECT * FROM users; DROP TABLE audits; DELETE FROM accounts;";
      const result = normalizeSqlForAudit(injectionSql);

      assert.equal(result.hasMultiStatement, true);
      assert.equal(
        result.normalizedSql,
        "SELECT * FROM users; DROP TABLE audits; DELETE FROM accounts",
      );

      // Verify semicolon inside string literals is NOT flagged as multi-statement
      const safeSql =
        "SELECT * FROM logs WHERE message = 'semicolon; here; not; injection' AND code = 200;";
      const safeResult = normalizeSqlForAudit(safeSql);

      assert.equal(safeResult.hasMultiStatement, false);
      assert.equal(
        safeResult.normalizedSql,
        "SELECT * FROM logs WHERE message = 'semicolon; here; not; injection' AND code = 200",
      );
    });

    it("integrates seamlessly into parseSql and flags isMultiStatement correctly", () => {
      const injection = "UPDATE users SET active = 1; DROP TABLE logs;";
      const parsed = parseSql(injection, "sqlite");

      assert.equal(parsed.isMultiStatement, true);
    });
  });

  describe("Dry Run Sandbox: Intent vs. Effect Gap Analysis", () => {
    it("detects discrepancy when stated intent implies single-row mutation but simulation affects multiple", async () => {
      const adapter = new SqliteAdapter(":memory:");
      await adapter.connect();

      // Seed mock table with 10 rows
      await adapter.query(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, status TEXT, active INTEGER);",
      );
      for (let i = 1; i <= 10; i++) {
        await adapter.query(`INSERT INTO users (id, status, active) VALUES (${i}, 'pending', 0);`);
      }

      const guard = new SqlGuardEngine(DEFAULT_CONFIG);
      const sandbox = new SandboxEngine(adapter, guard, DEFAULT_CONFIG);

      // Agent provides intent claiming "Update single user status" but executes broad update
      const broadSql = "UPDATE users SET status = 'active' WHERE active = 0";
      const dryRunRes = await sandbox.dryRun(broadSql, [], {
        intent: "Update single user status to active",
      });

      assert.equal(dryRunRes.safe, true);
      assert.equal(dryRunRes.simulatedAffectedRows, 10);
      assert.equal(dryRunRes.intentAligned, false);
      assert.match(dryRunRes.intentGap || "", /INTENT_EFFECT_DISCREPANCY/);
      assert.match(dryRunRes.intentGap || "", /implied single-record modification/);

      // Verify database state was untouched (auto-rollback verified)
      const countRes = await adapter.query(
        "SELECT COUNT(*) as count FROM users WHERE status = 'active';",
      );
      assert.equal(Number((countRes.rows[0] as { count: number }).count), 0);
      assert.equal(dryRunRes.rollbackVerified, true);

      await adapter.disconnect();
    });

    it("verifies intent alignment when expectedAffectedRows matches simulation", async () => {
      const adapter = new SqliteAdapter(":memory:");
      await adapter.connect();

      await adapter.query("CREATE TABLE items (id INTEGER PRIMARY KEY, qty INTEGER);");
      await adapter.query("INSERT INTO items (id, qty) VALUES (1, 5), (2, 10);");

      const guard = new SqlGuardEngine(DEFAULT_CONFIG);
      const sandbox = new SandboxEngine(adapter, guard, DEFAULT_CONFIG);

      const targetSql = "UPDATE items SET qty = 15 WHERE id = 1";
      const dryRunRes = await sandbox.dryRun(targetSql, [], {
        expectedAffectedRows: 1,
        intent: "Update specific item quantity",
      });

      assert.equal(dryRunRes.safe, true);
      assert.equal(dryRunRes.simulatedAffectedRows, 1);
      assert.equal(dryRunRes.intentAligned, true);
      assert.equal(dryRunRes.intentGap, undefined);

      await adapter.disconnect();
    });

    it("flags discrepancy when expectedAffectedRows differs from simulated rows", async () => {
      const adapter = new SqliteAdapter(":memory:");
      await adapter.connect();

      await adapter.query("CREATE TABLE items (id INTEGER PRIMARY KEY, qty INTEGER);");
      await adapter.query("INSERT INTO items (id, qty) VALUES (1, 5), (2, 10);");

      const guard = new SqlGuardEngine(DEFAULT_CONFIG);
      const sandbox = new SandboxEngine(adapter, guard, DEFAULT_CONFIG);

      const targetSql = "UPDATE items SET qty = 15 WHERE qty > 0";
      const dryRunRes = await sandbox.dryRun(targetSql, [], {
        expectedAffectedRows: 1,
      });

      assert.equal(dryRunRes.safe, true);
      assert.equal(dryRunRes.simulatedAffectedRows, 2);
      assert.equal(dryRunRes.intentAligned, false);
      assert.match(
        dryRunRes.intentGap || "",
        /Expected affected rows was 1, but simulated execution affected 2 rows/,
      );

      await adapter.disconnect();
    });
  });
});
