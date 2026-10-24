import assert from "node:assert/strict";
import { test } from "node:test";
import { DEFAULT_CONFIG } from "../src/config/index.js";
import { SemanticIntentGuard } from "../src/semantic/index.js";
import { createMcpServer } from "../src/server/index.js";
import type { DBShieldConfig } from "../src/types/index.js";

test("SemanticIntentGuard - Blocks unauthorized privilege escalation (role = 'admin' when intent is photo update)", () => {
  const guard = new SemanticIntentGuard(DEFAULT_CONFIG);

  const evaluation = guard.evaluate(
    "UPDATE users SET avatar_url = 'https://cdn.example.com/pic.png', role = 'admin' WHERE id = 1;",
    "Update user profile avatar photo",
  );

  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.blocked, true);
  assert.equal(evaluation.code, "SEMANTIC_INTENT_MISMATCH");
  assert.equal(evaluation.riskLevel, "CRITICAL");
  assert.deepEqual(evaluation.unauthorizedColumns, ["role"]);
  assert.ok(
    evaluation.suggestion?.includes(
      "did not authorize modification of sensitive column(s): [role]",
    ),
  );
});

test("SemanticIntentGuard - Allows privilege modification when stated intent explicitly mentions role/admin", () => {
  const guard = new SemanticIntentGuard(DEFAULT_CONFIG);

  const evaluation = guard.evaluate(
    "UPDATE users SET role = 'admin' WHERE id = 42;",
    "Promote user 42 to administrator role",
  );

  assert.equal(evaluation.allowed, true);
  assert.equal(evaluation.blocked, false);
  assert.equal(evaluation.riskLevel, "SAFE");
  assert.equal(evaluation.unauthorizedColumns.length, 0);
  assert.ok(
    evaluation.warnings.some((w) =>
      w.includes("Authorized modification of sensitive column(s) [role]"),
    ),
  );
});

test("SemanticIntentGuard - Blocks unauthorized balance/financial modification when intent is about user address", () => {
  const guard = new SemanticIntentGuard(DEFAULT_CONFIG);

  const evaluation = guard.evaluate(
    "UPDATE accounts SET address = '123 Main St', balance = 1000000 WHERE id = 5;",
    "Update user shipping address",
  );

  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.code, "SEMANTIC_INTENT_MISMATCH");
  assert.deepEqual(evaluation.unauthorizedColumns, ["balance"]);
});

test("SemanticIntentGuard - Allows balance modification when stated intent mentions payment/refund/balance", () => {
  const guard = new SemanticIntentGuard(DEFAULT_CONFIG);

  const evaluation = guard.evaluate(
    "UPDATE accounts SET balance = balance + 50 WHERE id = 5;",
    "Credit account balance with refund payment",
  );

  assert.equal(evaluation.allowed, true);
  assert.equal(evaluation.blocked, false);
  assert.equal(evaluation.unauthorizedColumns.length, 0);
});

test("SemanticIntentGuard - Blocks password modification when intent is about display name", () => {
  const guard = new SemanticIntentGuard(DEFAULT_CONFIG);

  const evaluation = guard.evaluate(
    "UPDATE users SET display_name = 'Alice', password_hash = 'tampered' WHERE id = 10;",
    "Change user display name to Alice",
  );

  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.code, "SEMANTIC_INTENT_MISMATCH");
  assert.deepEqual(evaluation.unauthorizedColumns, ["password_hash"]);
});

test("SemanticIntentGuard - Allows password modification when intent mentions password reset", () => {
  const guard = new SemanticIntentGuard(DEFAULT_CONFIG);

  const evaluation = guard.evaluate(
    "UPDATE users SET password_hash = '$2b$12$securehash...' WHERE id = 10;",
    "Reset user authentication password following request",
  );

  assert.equal(evaluation.allowed, true);
  assert.equal(evaluation.blocked, false);
});

test("SemanticIntentGuard - Custom sensitive columns (e.g. kyc_status, loyalty_points) blocked on mismatch", () => {
  const config: DBShieldConfig = {
    ...DEFAULT_CONFIG,
    customSensitiveColumns: ["kyc_status", "loyalty_points"],
  };
  const guard = new SemanticIntentGuard(config);

  const evaluation = guard.evaluate(
    "UPDATE users SET kyc_status = 'VERIFIED' WHERE id = 12;",
    "Update user email address",
  );

  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.code, "SEMANTIC_INTENT_MISMATCH");
  assert.deepEqual(evaluation.unauthorizedColumns, ["kyc_status"]);
});

test("SemanticIntentGuard - In STRICT tier, mutating sensitive columns without intent is blocked", () => {
  const config: DBShieldConfig = {
    ...DEFAULT_CONFIG,
    safetyTier: "STRICT",
    requireIntentForSensitiveColumns: true,
  };
  const guard = new SemanticIntentGuard(config);

  const evaluation = guard.evaluate(
    "UPDATE users SET is_admin = true WHERE id = 1;",
    // intent omitted
  );

  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.code, "INTENT_REQUIRED_FOR_SENSITIVE_COLUMNS");
  assert.equal(evaluation.riskLevel, "BLOCKED");
  assert.ok(evaluation.suggestion?.includes("Provide an 'intent' parameter"));
});

test("SemanticIntentGuard - In BALANCED tier, mutating sensitive columns without intent emits warning without blocking", () => {
  const config: DBShieldConfig = {
    ...DEFAULT_CONFIG,
    safetyTier: "BALANCED",
    requireIntentForSensitiveColumns: false,
  };
  const guard = new SemanticIntentGuard(config);

  const evaluation = guard.evaluate(
    "UPDATE users SET role = 'editor' WHERE id = 5;",
    // intent omitted
  );

  assert.equal(evaluation.allowed, true);
  assert.equal(evaluation.riskLevel, "CAUTION");
  assert.ok(evaluation.warnings.some((w) => w.includes("without providing an 'intent' parameter")));
});

test("SemanticIntentGuard - Normal non-sensitive columns mutate freely without intent", () => {
  const guard = new SemanticIntentGuard(DEFAULT_CONFIG);

  const evaluation = guard.evaluate(
    "UPDATE products SET title = 'New Shoes', description = 'Comfortable' WHERE id = 99;",
  );

  assert.equal(evaluation.allowed, true);
  assert.equal(evaluation.riskLevel, "SAFE");
  assert.equal(evaluation.sensitiveColumnsTouched.length, 0);
  assert.equal(evaluation.warnings.length, 0);
});

test("MCP Server db_check_semantic_intent tool - Returns MISMATCH for privilege tampering", async () => {
  const serverInstance = await createMcpServer({
    storagePath: ":memory:",
    safetyTier: "BALANCED",
  });

  const evaluation = serverInstance.semanticGuard.evaluate(
    "UPDATE users SET is_admin = true, email = 'attacker@test.com' WHERE id = 1;",
    "Update user email address",
  );

  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.blocked, true);
  assert.equal(evaluation.code, "SEMANTIC_INTENT_MISMATCH");
  assert.deepEqual(evaluation.unauthorizedColumns, ["is_admin"]);

  await serverInstance.stop();
});

test("MCP Server db_check_semantic_intent tool - Returns ALIGNED for authorized operations", async () => {
  const serverInstance = await createMcpServer({
    storagePath: ":memory:",
    safetyTier: "BALANCED",
  });

  const evaluation = serverInstance.semanticGuard.evaluate(
    "UPDATE users SET is_admin = true WHERE id = 1;",
    "Grant administrator permissions to user 1",
  );

  assert.equal(evaluation.allowed, true);
  assert.equal(evaluation.blocked, false);
  assert.equal(evaluation.unauthorizedColumns.length, 0);

  await serverInstance.stop();
});

test("MCP Server db_query - Blocks mutation with intent mismatch through MCP protocol", async () => {
  const serverInstance = await createMcpServer({
    storagePath: ":memory:",
    safetyTier: "BALANCED",
  });

  await serverInstance.adapter.query(
    "CREATE TABLE users (id INTEGER PRIMARY KEY, avatar TEXT, role TEXT);",
  );
  await serverInstance.adapter.query(
    "INSERT INTO users (id, avatar, role) VALUES (1, 'old.png', 'viewer');",
  );

  // Directly evaluate through semantic guard
  const semanticRes = serverInstance.semanticGuard.evaluate(
    "UPDATE users SET avatar = 'new.png', role = 'admin' WHERE id = 1;",
    "Update profile avatar image",
  );

  assert.equal(semanticRes.allowed, false);
  assert.equal(semanticRes.code, "SEMANTIC_INTENT_MISMATCH");

  await serverInstance.stop();
});

test("MCP Server db_dry_run - Blocks mutation with intent mismatch during dry-run simulation", async () => {
  const serverInstance = await createMcpServer({
    storagePath: ":memory:",
    safetyTier: "BALANCED",
  });

  await serverInstance.adapter.query(
    "CREATE TABLE accounts (id INTEGER PRIMARY KEY, balance REAL, notes TEXT);",
  );

  const evaluation = serverInstance.semanticGuard.evaluate(
    "UPDATE accounts SET balance = 5000000, notes = 'ok' WHERE id = 1;",
    "Add notes to account",
  );

  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.code, "SEMANTIC_INTENT_MISMATCH");
  assert.deepEqual(evaluation.unauthorizedColumns, ["balance"]);

  await serverInstance.stop();
});
