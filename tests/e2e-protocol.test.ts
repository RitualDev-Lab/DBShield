import assert from "node:assert/strict";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "../src/server/index.js";

test("E2E MCP Protocol - Full Tool Suite & Protocol Interception Flow", async () => {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

  // Initialize DBShield with in-memory SQLite and BALANCED tier
  const instance = await createMcpServer({
    storagePath: ":memory:",
    safetyTier: "BALANCED",
    enablePiiMasking: true,
  });

  await instance.server.connect(serverTransport);

  const client = new Client(
    { name: "dbshield-e2e-tester", version: "1.0.0" },
    { capabilities: {} },
  );
  await client.connect(clientTransport);

  // 1. Tool discovery
  const toolsResult = await client.listTools();
  const toolNames = toolsResult.tools.map((t) => t.name);
  assert.ok(toolNames.includes("db_status"));
  assert.ok(toolNames.includes("db_describe_schema"));
  assert.ok(toolNames.includes("db_query"));
  assert.ok(toolNames.includes("db_dry_run"));
  assert.ok(toolNames.includes("db_commit"));
  assert.ok(toolNames.includes("db_explain_query"));
  assert.ok(toolNames.includes("db_audit_log"));

  // 2. Call db_status
  const statusRes = (await client.callTool({ name: "db_status" })) as {
    content: Array<{ type: string; text: string }>;
  };
  const statusData = JSON.parse(statusRes.content[0].text);
  assert.equal(statusData.status, "ONLINE");
  assert.equal(statusData.safetyTier, "BALANCED");

  // Setup seed tables via adapter
  await instance.adapter.query(`
    CREATE TABLE members (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      phone TEXT,
      password_hash TEXT,
      role TEXT DEFAULT 'user'
    );
  `);
  await instance.adapter.query(`
    INSERT INTO members (email, phone, password_hash, role) VALUES 
    ('alice@ritualdev.in', '+1 (555) 234-5678', 'supersecretpassword123', 'admin'),
    ('bob@ritualdev.in', '+1 (555) 987-6543', 'anothersecretpass987', 'member');
  `);

  // 3. Call db_describe_schema
  const schemaRes = (await client.callTool({
    name: "db_describe_schema",
    arguments: { tableName: "members" },
  })) as { content: Array<{ type: string; text: string }> };
  const schemaData = JSON.parse(schemaRes.content[0].text);
  assert.equal(schemaData.tableName, "members");
  assert.equal(schemaData.columns.length, 5);
  assert.equal(schemaData.columns[0].name, "id");
  assert.equal(schemaData.columns[0].primaryKey, true);

  // 4. Call db_query (Safe SELECT with dynamic PII masking)
  const selectRes = (await client.callTool({
    name: "db_query",
    arguments: { sql: "SELECT * FROM members ORDER BY id ASC;" },
  })) as { content: Array<{ type: string; text: string }> };
  const selectData = JSON.parse(selectRes.content[0].text);
  assert.equal(selectData.status, "SUCCESS");
  assert.equal(selectData.rows.length, 2);
  // Verify PII masking on password_hash, email, phone
  assert.equal(selectData.rows[0].password_hash, "[REDACTED_SECRET]");
  assert.ok(selectData.rows[0].email.includes("***@"));
  assert.ok(selectData.rows[0].phone.includes("***"));
  assert.equal(selectData.piiRedaction.enabled, true);
  assert.ok(selectData.piiRedaction.totalFieldsRedacted > 0);

  // 5. Call db_query with destructive DDL (Must be intercepted and blocked)
  const ddlRes = (await client.callTool({
    name: "db_query",
    arguments: { sql: "DROP TABLE members;" },
  })) as { content: Array<{ type: string; text: string }>; isError?: boolean };
  assert.ok(ddlRes.isError);
  const ddlData = JSON.parse(ddlRes.content[0].text);
  assert.equal(ddlData.status, "BLOCKED");
  assert.ok(
    ddlData.violations.some(
      (v: { code: string; message: string }) =>
        v.code.includes("DESTRUCTIVE_DDL") || v.message.includes("DROP"),
    ),
  );

  // 6. Call db_query with tautology mutation (Must be intercepted and blocked)
  const tautologyRes = (await client.callTool({
    name: "db_query",
    arguments: { sql: "DELETE FROM members WHERE 1=1;" },
  })) as { content: Array<{ type: string; text: string }>; isError?: boolean };
  assert.ok(tautologyRes.isError);
  const tautologyData = JSON.parse(tautologyRes.content[0].text);
  assert.equal(tautologyData.status, "BLOCKED");

  // 7. Call db_dry_run (Simulate valid mutation in sandbox)
  const dryRunRes = (await client.callTool({
    name: "db_dry_run",
    arguments: { sql: "UPDATE members SET role = 'senior-admin' WHERE id = 1;" },
  })) as { content: Array<{ type: string; text: string }> };
  const dryRunData = JSON.parse(dryRunRes.content[0].text);
  assert.equal(dryRunData.safe, true);
  assert.equal(dryRunData.simulatedAffectedRows, 1);
  assert.ok(dryRunData.commitToken, "Must issue HMAC authorization token");

  // Verify rollback took place: member 1 still has 'admin'
  const verifyRollback = await instance.adapter.query("SELECT role FROM members WHERE id = 1;");
  assert.equal(verifyRollback.rows[0].role, "admin");

  // 8. Call db_commit (Two-phase commit execution)
  const commitRes = (await client.callTool({
    name: "db_commit",
    arguments: {
      commitToken: dryRunData.commitToken,
      sql: "UPDATE members SET role = 'senior-admin' WHERE id = 1;",
    },
  })) as { content: Array<{ type: string; text: string }> };
  const commitData = JSON.parse(commitRes.content[0].text);
  assert.equal(commitData.status, "COMMITTED");
  assert.equal(commitData.rowCount, 1);

  // Verify database is now updated
  const verifyCommit = await instance.adapter.query("SELECT role FROM members WHERE id = 1;");
  assert.equal(verifyCommit.rows[0].role, "senior-admin");

  // 9. Replay attack: attempting to use the token again must fail
  const replayRes = (await client.callTool({
    name: "db_commit",
    arguments: {
      commitToken: dryRunData.commitToken,
      sql: "UPDATE members SET role = 'senior-admin' WHERE id = 1;",
    },
  })) as { content: Array<{ type: string; text: string }>; isError?: boolean };
  assert.ok(replayRes.isError);
  const replayData = JSON.parse(replayRes.content[0].text);
  assert.equal(replayData.status, "COMMIT_FAILED");
  assert.ok(replayData.error.includes("already been consumed"));

  // 10. Call db_explain_query
  const explainRes = (await client.callTool({
    name: "db_explain_query",
    arguments: { sql: "SELECT * FROM members WHERE phone = '+1 (555) 234-5678';" },
  })) as { content: Array<{ type: string; text: string }> };
  const explainData = JSON.parse(explainRes.content[0].text);
  assert.equal(explainData.isIndexed, false);
  assert.ok(explainData.bottlenecks.some((b: string) => b.includes("Full table sequential scan")));

  // 11. Call db_audit_log
  const auditRes = (await client.callTool({
    name: "db_audit_log",
    arguments: { limit: 10 },
  })) as { content: Array<{ type: string; text: string }> };
  const auditData = JSON.parse(auditRes.content[0].text);
  assert.ok(auditData.totalRetrieved >= 3);
  // Verify blocked events are logged
  assert.ok(auditData.entries.some((e: { status: string }) => e.status === "BLOCKED"));
  // Verify dry-run events are logged
  assert.ok(auditData.entries.some((e: { status: string }) => e.status === "DRY_RUN_APPROVED"));
  // Verify commit events are logged
  assert.ok(auditData.entries.some((e: { status: string }) => e.status === "COMMITTED"));

  await client.close();
  await instance.stop();
});
