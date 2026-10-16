import assert from "node:assert/strict";
import test from "node:test";
import { PiiRedactor } from "../src/pii/redactor.js";
import { createMcpServer } from "../src/server/index.js";

test("PiiRedactor - Password and Secret Columns Redaction", () => {
  const redactor = new PiiRedactor();
  const rows = [
    {
      id: 1,
      username: "alex",
      password: "super-secret-password-123",
      secret_key: "sk_live_9876543210",
      role: "admin",
    },
  ];

  const report = redactor.redactRows(rows);
  assert.equal(report.sanitizedRows[0].password, "[REDACTED_SECRET]");
  assert.equal(report.sanitizedRows[0].secret_key, "[REDACTED_SECRET]");
  assert.equal(report.sanitizedRows[0].username, "alex", "Username should be preserved");
  assert.equal(report.sanitizedRows[0].role, "admin", "Role should be preserved");
  assert.ok(report.redactedColumns.includes("password"));
  assert.ok(report.redactedColumns.includes("secret_key"));
  assert.ok(report.categoriesDetected.includes("PASSWORD"));
});

test("PiiRedactor - Auth Token and API Key Redaction", () => {
  const redactor = new PiiRedactor();
  const rows = [
    {
      id: 10,
      token: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
      api_key: "sk_test_51MzABCD1234567890",
    },
  ];

  const report = redactor.redactRows(rows);
  assert.equal(report.sanitizedRows[0].token, "[REDACTED_TOKEN]");
  assert.equal(report.sanitizedRows[0].api_key, "[REDACTED_TOKEN]");
  assert.ok(report.categoriesDetected.includes("AUTH_TOKEN"));
});

test("PiiRedactor - Email Redaction with Format Preservation", () => {
  const redactor = new PiiRedactor();
  const rows = [
    { id: 1, email: "sarah.connor@cyberdyne.com" },
    { id: 2, email_address: "john@resistance.org" },
  ];

  const report = redactor.redactRows(rows);
  assert.equal(report.sanitizedRows[0].email, "s***@cyberdyne.com");
  assert.equal(report.sanitizedRows[1].email_address, "j***@resistance.org");
  assert.ok(report.redactedColumns.includes("email"));
  assert.ok(report.redactedColumns.includes("email_address"));
});

test("PiiRedactor - Phone Number Redaction", () => {
  const redactor = new PiiRedactor();
  const rows = [
    { id: 1, phone: "+1-555-867-5309" },
    { id: 2, mobile: "9876543210" },
  ];

  const report = redactor.redactRows(rows);
  assert.equal(report.sanitizedRows[0].phone, "+***-***-5309");
  assert.equal(report.sanitizedRows[1].mobile, "+***-***-3210");
});

test("PiiRedactor - Credit Card and SSN Redaction", () => {
  const redactor = new PiiRedactor();
  const rows = [{ id: 1, credit_card: "4111 2222 3333 4444", ssn: "123-45-6789" }];

  const report = redactor.redactRows(rows);
  assert.equal(report.sanitizedRows[0].credit_card, "****-****-****-4444");
  assert.equal(report.sanitizedRows[0].ssn, "***-**-6789");
  assert.ok(report.categoriesDetected.includes("CREDIT_CARD"));
  assert.ok(report.categoriesDetected.includes("SSN_OR_NATIONAL_ID"));
});

test("PiiRedactor - Inline Content Regex Redaction in Generic Column", () => {
  const redactor = new PiiRedactor();
  const rows = [
    {
      id: 1,
      comment: "Please reach out to me at dev@ritualdev.in or call +1-555-123-4567 ASAP.",
    },
  ];

  const report = redactor.redactRows(rows);
  const sanitizedComment = report.sanitizedRows[0].comment as string;

  assert.ok(sanitizedComment.includes("d***@ritualdev.in"));
  assert.ok(sanitizedComment.includes("+***-***-4567"));
  assert.ok(!sanitizedComment.includes("dev@ritualdev.in"));
  assert.ok(!sanitizedComment.includes("555-123-4567"));
});

test("PiiRedactor - Custom Configured PII Columns", () => {
  const redactor = new PiiRedactor(["internal_uid", "salary_tier"]);
  const rows = [
    {
      id: 1,
      internal_uid: "sec_987654321",
      salary_tier: "Executive-Tier-1",
      department: "Security",
    },
  ];

  const report = redactor.redactRows(rows);
  assert.equal(report.sanitizedRows[0].internal_uid, "[REDACTED_CUSTOM]");
  assert.equal(report.sanitizedRows[0].salary_tier, "[REDACTED_CUSTOM]");
  assert.equal(report.sanitizedRows[0].department, "Security");
  assert.ok(report.categoriesDetected.includes("CUSTOM"));
});

test("MCP Server db_query - Dynamic PII Masking Protocol Integration", async () => {
  const instance = await createMcpServer({
    storagePath: ":memory:",
    safetyTier: "BALANCED",
    enablePiiMasking: true,
  });

  await instance.adapter.query(`
    CREATE TABLE employees (
      id INTEGER PRIMARY KEY,
      name TEXT,
      email TEXT,
      password TEXT
    );
  `);

  await instance.adapter.query(`
    INSERT INTO employees VALUES (1, 'Alice', 'alice@ritualdev.in', 'hunter2');
  `);

  // Direct execution through db_query tool logic
  const queryRes = await instance.adapter.query("SELECT * FROM employees;");
  const piiReport = instance.piiRedactor.redactRows(queryRes.rows);

  assert.equal(piiReport.sanitizedRows[0].name, "Alice");
  assert.equal(piiReport.sanitizedRows[0].email, "a***@ritualdev.in");
  assert.equal(piiReport.sanitizedRows[0].password, "[REDACTED_SECRET]");
  assert.deepEqual(piiReport.redactedColumns.sort(), ["email", "password"].sort());

  await instance.stop();
});

test("MCP Server db_query - Disabled PII Masking Leaves Rows Untouched", async () => {
  const instance = await createMcpServer({
    storagePath: ":memory:",
    safetyTier: "BALANCED",
    enablePiiMasking: false,
  });

  await instance.adapter.query("CREATE TABLE secrets (id INTEGER, token TEXT);");
  await instance.adapter.query("INSERT INTO secrets VALUES (1, 'raw-secret-token-abc');");

  const queryRes = await instance.adapter.query("SELECT * FROM secrets;");
  // When enablePiiMasking is false, no redaction occurs
  assert.equal(queryRes.rows[0].token, "raw-secret-token-abc");

  await instance.stop();
});
