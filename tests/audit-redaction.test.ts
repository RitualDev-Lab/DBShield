import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { AuditLogger } from "../src/audit/index.js";
import { PiiRedactor } from "../src/pii/redactor.js";
import { createMcpServer } from "../src/server/index.js";

test("Phase 5 (B3): PiiRedactor - Redacts sensitive SQL literals in INSERT, UPDATE, and WHERE clauses", () => {
  const redactor = new PiiRedactor(["confidential_token"]);

  // 1. INSERT with sensitive columns (password, email, secret)
  const rawInsert =
    "INSERT INTO users (id, email, password, confidential_token) VALUES (1, 'sarah.connor@cyberdyne.com', 'T800_Terminator!', 'mock_api_key_xyz987654321');";
  const sanitizedInsert = redactor.redactSql(rawInsert);

  assert.ok(
    !sanitizedInsert.includes("T800_Terminator!"),
    "Password must not appear in sanitized SQL",
  );
  assert.ok(sanitizedInsert.includes("[REDACTED_SECRET]"), "Password must be masked");
  assert.ok(
    !sanitizedInsert.includes("sarah.connor@cyberdyne.com"),
    "Email must not appear in plaintext",
  );
  assert.ok(
    sanitizedInsert.includes("s***@cyberdyne.com"),
    "Email must be masked with domain preservation",
  );
  assert.ok(
    sanitizedInsert.includes("[REDACTED_CUSTOM]"),
    "Custom configured column must be masked",
  );

  // 2. UPDATE statement
  const rawUpdate =
    "UPDATE accounts SET password = 'SecretPassword123!', api_key = 'key_9988776655' WHERE id = 1;";
  const sanitizedUpdate = redactor.redactSql(rawUpdate);
  assert.ok(!sanitizedUpdate.includes("SecretPassword123!"));
  assert.ok(sanitizedUpdate.includes("[REDACTED_SECRET]"));
  assert.ok(!sanitizedUpdate.includes("key_9988776655"));
  assert.ok(sanitizedUpdate.includes("[REDACTED_TOKEN]"));

  // 3. WHERE clause with SSN and Phone
  const rawSelect = "SELECT * FROM patients WHERE ssn = '123-45-6789' AND phone = '555-867-5309';";
  const sanitizedSelect = redactor.redactSql(rawSelect);
  assert.ok(!sanitizedSelect.includes("123-45-6789"));
  assert.ok(sanitizedSelect.includes("***-**-6789"));
  assert.ok(!sanitizedSelect.includes("555-867-5309"));
  assert.ok(sanitizedSelect.includes("+***-***-5309"));
});

test("Phase 5 (B3): PiiRedactor - Sanitizes database error messages containing sensitive literals", () => {
  const redactor = new PiiRedactor();
  const rawDbError = "Error: UNIQUE constraint failed: users.email ('founder@stealth-ai.com')";
  const sanitized = redactor.redactErrorMessage(rawDbError);

  assert.ok(
    !sanitized.includes("founder@stealth-ai.com"),
    "Raw sensitive email must be scrubbed from error",
  );
  assert.ok(sanitized.includes("f***@stealth-ai.com"), "Masked email must be present");

  const rawConstraintError = "Error: CHECK constraint failed: password != 'Admin1234!'";
  const sanitizedConstraint = redactor.redactErrorMessage(rawConstraintError);
  assert.ok(!sanitizedConstraint.includes("Admin1234!"));
  assert.ok(sanitizedConstraint.includes("[REDACTED_SECRET]"));
});

test("Phase 5 (B3): AuditLogger - Persists sanitized SQL and violations to disk and memory buffer", async () => {
  const tempLogFile = path.join(process.cwd(), "tests", "scratch", "test-audit.log");
  try {
    await fs.unlink(tempLogFile);
  } catch {
    // Ignore if not exists
  }

  const redactor = new PiiRedactor();
  const logger = new AuditLogger(tempLogFile, 50, redactor);

  await logger.log({
    auditId: "audit-test-1",
    timestamp: new Date().toISOString(),
    sql: "INSERT INTO credentials (user_id, token) VALUES (42, 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M');",
    operation: "INSERT",
    status: "SUCCESS",
    riskLevel: "SAFE",
    riskScore: 10,
    violations: ["Warning: token issued for ceo@corp.com"],
  });

  // Verify memory buffer retrieval is redacted
  const entries = logger.getEntries({ limit: 10 });
  assert.equal(entries.length, 1);
  assert.ok(!entries[0].sql.includes("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
  assert.ok(entries[0].sql.includes("[REDACTED_TOKEN]"));
  assert.ok(!entries[0].violations?.[0].includes("ceo@corp.com"));
  assert.ok(entries[0].violations?.[0].includes("c***@corp.com"));

  // Verify log file persisted to disk contains NO raw secrets
  const diskContent = await fs.readFile(tempLogFile, "utf8");
  assert.ok(
    !diskContent.includes("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
    "Disk log must not contain unmasked secret",
  );
  assert.ok(diskContent.includes("[REDACTED_TOKEN]"), "Disk log must contain masked token");
  assert.ok(!diskContent.includes("ceo@corp.com"), "Disk log must not contain raw email");
  assert.ok(diskContent.includes("c***@corp.com"));

  // Clean up
  try {
    await fs.unlink(tempLogFile);
  } catch {
    // Ignore cleanup error
  }
});

test("Phase 5 (B3): MCP Server - db_audit_log and database error path expose zero unredacted PII", async () => {
  const instance = await createMcpServer({
    storagePath: ":memory:",
    safetyTier: "BALANCED",
  });

  // Create table with CHECK constraint mentioning sensitive email
  await instance.adapter.query(`
    CREATE TABLE members (
      id INTEGER PRIMARY KEY,
      email TEXT CHECK (email != 'forbidden@root.org'),
      secret_key TEXT
    );
  `);

  // Attempt insert violating the constraint
  const duplicateQuery =
    "INSERT INTO members (id, email, secret_key) VALUES (1, 'forbidden@root.org', 'mock_api_key_12345678901234567890123456789012');";

  const tools = (
    instance.server as unknown as {
      _registeredTools: Record<string, { handler: (args: unknown) => Promise<unknown> }>;
    }
  )._registeredTools;
  const dbQueryTool = tools.db_query;

  const errorResult = (await dbQueryTool.handler({ sql: duplicateQuery })) as {
    isError?: boolean;
    content: Array<{ text: string }>;
  };

  assert.equal(errorResult.isError, true);
  const errorJson = JSON.parse(errorResult.content[0].text);
  assert.equal(errorJson.status, "DATABASE_ERROR");
  assert.ok(
    !errorJson.error.includes("forbidden@root.org"),
    "Database error message returned to agent must not expose raw email",
  );
  assert.ok(errorJson.error.includes("f***@root.org"), "Database error must have redacted email");

  // Check db_audit_log tool
  const auditTool = tools.db_audit_log;
  const auditRes = (await auditTool.handler({ limit: 10 })) as { content: Array<{ text: string }> };
  const auditJson = JSON.parse(auditRes.content[0].text);

  assert.ok(auditJson.entries.length > 0);
  for (const entry of auditJson.entries) {
    assert.ok(
      !entry.sql.includes("mock_api_key_12345678901234567890123456789012"),
      "Audit log entry must not leak raw secret key",
    );
    assert.ok(!entry.sql.includes("admin@root.org"), "Audit log entry must not leak raw email");
  }

  await instance.adapter.disconnect();
});
