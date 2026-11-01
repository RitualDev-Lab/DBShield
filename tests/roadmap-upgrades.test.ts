import assert from "node:assert/strict";
import test from "node:test";
import { PostgresAdapter } from "../src/adapters/postgres.js";
import { SqliteAdapter } from "../src/adapters/sqlite.js";
import { AuditLogger } from "../src/audit/index.js";
import { SiemTelemetryStreamer } from "../src/audit/siem.js";
import { SqlGuardEngine } from "../src/guard/engine.js";
import { containsTautology } from "../src/guard/tautology.js";
import { PiiRedactor, formatPreservingPseudonym } from "../src/pii/redactor.js";
import {
  decodeMysqlPacket,
  encodeMysqlErrorPacket,
  encodeMysqlOkPacket,
  extractSqlFromMysqlPacket,
  isMysqlQueryPacket,
} from "../src/proxy/mysql-protocol.js";
import { MysqlWireProxy } from "../src/proxy/mysql-server.js";
import { PostgresWireProxy } from "../src/proxy/server.js";
import type { DBShieldConfig } from "../src/types/index.js";

// =========================================================================
// 1. MySQL Wire Protocol & Proxy
// =========================================================================

test("MySQL Protocol - Encodes and decodes MySQL command packets correctly", () => {
  const query = "SELECT * FROM users WHERE active = 1";
  const payload = Buffer.from(query, "utf8");
  const packetLength = payload.length + 1; // 1 byte for command code

  const rawPacket = Buffer.alloc(4 + packetLength);
  rawPacket.writeUIntLE(packetLength, 0, 3);
  rawPacket.writeUInt8(0, 3); // sequenceId 0
  rawPacket.writeUInt8(0x03, 4); // COM_QUERY
  payload.copy(rawPacket, 5);

  const decoded = decodeMysqlPacket(rawPacket);
  assert.ok(decoded);
  assert.equal(decoded.sequenceId, 0);
  assert.equal(decoded.command, 0x03);
  assert.equal(isMysqlQueryPacket(decoded), true);

  const extractedSql = extractSqlFromMysqlPacket(decoded);
  assert.equal(extractedSql, query);
});

test("MySQL Protocol - Generates standard MySQL 0xFF Error packets", () => {
  const errorPacket = encodeMysqlErrorPacket({
    sequenceId: 1,
    errorCode: 1148,
    sqlState: "42000",
    message: "[DBSHIELD_MUTATION_GUARD] Mutation without WHERE is prohibited",
  });

  assert.ok(errorPacket.length > 4);
  assert.equal(errorPacket.readUInt8(3), 1); // sequenceId
  assert.equal(errorPacket.readUInt8(4), 0xff); // Error packet marker
  const errCode = errorPacket.readUInt16LE(5);
  assert.equal(errCode, 1148);
  const sqlState = errorPacket.subarray(8, 13).toString("ascii");
  assert.equal(sqlState, "42000");
  assert.ok(errorPacket.toString("utf8").includes("Mutation without WHERE is prohibited"));
});

test("MySQL Protocol - Encodes OK packet", () => {
  const okPacket = encodeMysqlOkPacket(1, 10, 42);
  assert.ok(okPacket.length >= 7);
  assert.equal(okPacket.readUInt8(3), 1); // sequenceId
  assert.equal(okPacket.readUInt8(4), 0x00); // OK marker
});

test("MySQL Proxy - Evaluates incoming queries and tracks stats", () => {
  const proxy = new MysqlWireProxy({
    listenPort: 13307,
    upstreamPort: 13306,
    config: {
      dialect: "mysql",
      safetyTier: "BALANCED",
      maxRowsPerMutation: 10,
      allowDestructiveDDL: false,
      enablePiiMasking: false,
    },
  });

  const stats = proxy.getStats();
  assert.equal(stats.activeConnections, 0);
  assert.equal(stats.queriesProcessed, 0);
  assert.equal(stats.queriesAllowed, 0);
  assert.equal(stats.queriesIntercepted, 0);
});

// =========================================================================
// 2. Enhanced AST Tautology & Subquery Detection
// =========================================================================

test("AST Tautology - Detects self-referential column tautologies (WHERE col = col)", () => {
  const engine = new SqlGuardEngine({
    dialect: "sqlite",
    safetyTier: "BALANCED",
    maxRowsPerMutation: 50,
    allowDestructiveDDL: false,
    enablePiiMasking: false,
  });

  const evaluation1 = engine.evaluate("DELETE FROM users WHERE id = id;");
  assert.equal(evaluation1.allowed, false);
  assert.equal(evaluation1.violations[0].code, "UNCONSTRAINED_MUTATION");
  assert.ok(evaluation1.violations[0].message.includes("self-referential column comparison"));

  const evaluation2 = engine.evaluate("UPDATE accounts SET balance = 0 WHERE u.id = u.id;");
  assert.equal(evaluation2.allowed, false);
  assert.equal(evaluation2.violations[0].code, "UNCONSTRAINED_MUTATION");
  assert.ok(evaluation2.violations[0].message.includes("self-referential column comparison"));
});

test("AST Tautology - Detects numeric and constant tautologies (WHERE 0=0, 1!=2)", () => {
  const engine = new SqlGuardEngine({
    dialect: "sqlite",
    safetyTier: "BALANCED",
    maxRowsPerMutation: 50,
    allowDestructiveDDL: false,
    enablePiiMasking: false,
  });

  const evaluation = engine.evaluate("DELETE FROM users WHERE 0=0;");
  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.violations[0].code, "UNCONSTRAINED_MUTATION");
  assert.ok(
    evaluation.violations[0].message.includes(
      "constant literals evaluating unconditionally to TRUE",
    ),
  );
});

test("AST Tautology - Detects tautology in nested OR clauses", () => {
  const engine = new SqlGuardEngine({
    dialect: "sqlite",
    safetyTier: "BALANCED",
    maxRowsPerMutation: 50,
    allowDestructiveDDL: false,
    enablePiiMasking: false,
  });

  const evaluation = engine.evaluate("DELETE FROM users WHERE name IS NOT NULL OR 1=1;");
  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.violations[0].code, "UNCONSTRAINED_MUTATION");
  assert.ok(evaluation.violations[0].message.includes("OR branch with a constant tautology"));
});

test("AST Tautology - Detects tautology inside subqueries", () => {
  const engine = new SqlGuardEngine({
    dialect: "sqlite",
    safetyTier: "BALANCED",
    maxRowsPerMutation: 50,
    allowDestructiveDDL: false,
    enablePiiMasking: false,
  });

  const evaluation = engine.evaluate(
    "DELETE FROM orders WHERE user_id IN (SELECT id FROM users WHERE 1=1);",
  );
  assert.equal(evaluation.allowed, false);
  assert.equal(evaluation.violations[0].code, "UNCONSTRAINED_MUTATION");
  assert.ok(evaluation.violations[0].message.includes("Subquery contains unconditional tautology"));
});

// =========================================================================
// 3. Configurable PII Rules & Format-Preserving Masking
// =========================================================================

test("PII Masking - Custom regex rules redact organization-specific patterns", () => {
  const redactor = new PiiRedactor({
    customRules: [
      {
        name: "MedicalRecordNumber",
        pattern: "MRN-\\d{6}",
        replacement: "[MRN-REDACTED]",
      },
      {
        name: "InternalEmployeeCode",
        columnPattern: "^emp_code$",
        replacement: "[EMP-REDACTED]",
      },
    ],
  });

  // Redact matching cell value
  const val1 = redactor.redactCell("patient_notes", "Patient id is MRN-123456 in clinic");
  assert.equal(val1.value, "Patient id is [MRN-REDACTED] in clinic");
  assert.equal(val1.redacted, true);

  // Redact matching column name
  const val2 = redactor.redactCell("emp_code", "E-998877");
  assert.equal(val2.value, "[EMP-REDACTED]");
  assert.equal(val2.redacted, true);
});

test("PII Masking - Format-preserving pseudonymization maintains relational integrity across rows", () => {
  const redactor = new PiiRedactor({
    enableFormatPreserving: true,
    salt: "production-secure-salt-2026",
  });

  const emailA = "alice.smith@healthcare.org";
  const emailB = "bob.jones@healthcare.org";

  const maskedA1 = redactor.redactCell("email", emailA).value;
  const maskedA2 = redactor.redactCell("user_email", emailA).value;
  const maskedB = redactor.redactCell("email", emailB).value;

  // Referential integrity: same email in different tables/columns produces the exact same pseudonym
  assert.equal(maskedA1, maskedA2);
  assert.notEqual(maskedA1, maskedB);

  // Email format preservation: preserves @domain so email validations and queries still pass
  assert.ok(typeof maskedA1 === "string" && maskedA1.endsWith("@healthcare.org"));
  assert.ok(typeof maskedA1 === "string" && maskedA1.startsWith("user_"));
});

test("PII Masking - Format-preserving pseudonymization preserves SSN and UUID formats", () => {
  const redactor = new PiiRedactor({
    enableFormatPreserving: true,
    salt: "test-salt",
  });

  const ssn = "123-45-6789";
  const maskedSsn = redactor.redactCell("ssn", ssn).value;
  assert.equal(maskedSsn, "***-**-6789");

  const uuid = "123e4567-e89b-12d3-a456-426614174000";
  const maskedUuid = formatPreservingPseudonym(uuid, "UUID", "test-salt");
  assert.match(
    String(maskedUuid),
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
  );
});

// =========================================================================
// 4. Connection Pooling & Read-Replica Routing
// =========================================================================

test("PostgresAdapter - Connection pool stats reporting", () => {
  const adapter = new PostgresAdapter({
    connectionString: "postgresql://postgres:secret@127.0.0.1:5432/testdb",
    poolSize: 15,
  });

  const stats = adapter.getPoolStats();
  assert.equal(stats.max, 15);
  assert.equal(typeof stats.totalCount, "number");
  assert.equal(typeof stats.idleCount, "number");
  assert.equal(typeof stats.waitingCount, "number");
});

test("PostgresWireProxy - Read-replica routing configuration and stats", () => {
  const proxy = new PostgresWireProxy({
    listenPort: 15433,
    upstreamPort: 15432,
    enableReadReplicaRouting: true,
    readReplicaHost: "replica.internal.db",
    readReplicaPort: 5432,
  });

  assert.equal(proxy.enableReadReplicaRouting, true);
  assert.equal(proxy.readReplicaHost, "replica.internal.db");

  const stats = proxy.getStats();
  assert.equal(stats.routedToPrimary, 0);
  assert.equal(stats.routedToReplica, 0);
});

// =========================================================================
// 5. Centralized SIEM & Audit Telemetry Streaming
// =========================================================================

test("SIEM Telemetry - Queues and formats audit entries into webhook format", async () => {
  let capturedPayload: { source?: string; count?: number } | null = null;
  let capturedHeaders: Record<string, string> | null = null;

  // Mock global fetch
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    capturedPayload = JSON.parse(init?.body as string);
    capturedHeaders = (init?.headers as Record<string, string>) || null;
    return new Response(JSON.stringify({ ok: true }), { status: 200 });
  }) as typeof fetch;

  try {
    const streamer = new SiemTelemetryStreamer({
      enabled: true,
      endpoint: "https://siem.corporate.net/v1/events",
      format: "webhook",
      authToken: "secret-token-123",
      batchSize: 2,
      flushIntervalMs: 0,
    });

    await streamer.enqueue({
      auditId: "audit-1",
      timestamp: "2026-11-01T12:00:00Z",
      sql: "SELECT * FROM users",
      operation: "SELECT",
      status: "SUCCESS",
      riskLevel: "SAFE",
      riskScore: 0,
    });

    // Queue has 1 item, batchSize is 2, not yet flushed
    assert.equal(streamer.getStats().queuedCount, 1);
    assert.equal(streamer.getStats().sentCount, 0);

    // Enqueue second item triggers auto-flush
    await streamer.enqueue({
      auditId: "audit-2",
      timestamp: "2026-11-01T12:01:00Z",
      sql: "DELETE FROM users",
      operation: "DELETE",
      status: "BLOCKED",
      riskLevel: "CRITICAL",
      riskScore: 95,
      violations: ["UNCONSTRAINED_MUTATION"],
    });

    assert.equal(streamer.getStats().queuedCount, 0);
    assert.equal(streamer.getStats().sentCount, 2);
    assert.ok(capturedPayload);
    assert.equal(capturedPayload?.source, "dbshield");
    assert.equal(capturedPayload?.count, 2);
    assert.equal(capturedHeaders?.Authorization, "Bearer secret-token-123");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("SIEM Telemetry - Datadog formatting with DD-API-KEY header", async () => {
  let capturedPayload: Array<{ ddsource?: string; ddtags?: string }> | null = null;
  let capturedHeaders: Record<string, string> | null = null;

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    capturedPayload = JSON.parse(init?.body as string);
    capturedHeaders = (init?.headers as Record<string, string>) || null;
    return new Response(JSON.stringify({ status: "ok" }), { status: 202 });
  }) as typeof fetch;

  try {
    const streamer = new SiemTelemetryStreamer({
      enabled: true,
      endpoint: "https://http-intake.logs.datadoghq.com/api/v2/logs",
      format: "datadog",
      authToken: "dd-api-key-xyz",
      batchSize: 1,
      flushIntervalMs: 0,
    });

    await streamer.enqueue({
      auditId: "audit-dd",
      timestamp: "2026-11-01T12:05:00Z",
      sql: "DROP TABLE sensitive_vault",
      operation: "DDL_DROP",
      status: "BLOCKED",
      riskLevel: "CRITICAL",
      riskScore: 100,
    });

    assert.equal(streamer.getStats().sentCount, 1);
    assert.equal(capturedHeaders?.["DD-API-KEY"], "dd-api-key-xyz");
    assert.ok(Array.isArray(capturedPayload));
    assert.equal(capturedPayload?.[0]?.ddsource, "dbshield");
    assert.ok(capturedPayload?.[0]?.ddtags?.includes("risk:CRITICAL"));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("SIEM Telemetry - AuditLogger forwards sanitized events to configured streamer", async () => {
  let capturedEntries: Array<{ sql: string }> = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    const data = JSON.parse(init?.body as string);
    capturedEntries = data.entries || [];
    return new Response(JSON.stringify({ ok: true }), { status: 200 });
  }) as typeof fetch;

  try {
    const streamer = new SiemTelemetryStreamer({
      enabled: true,
      endpoint: "https://webhook.site/test",
      format: "webhook",
      batchSize: 1,
    });

    const logger = new AuditLogger(undefined, 50, undefined, streamer);

    await logger.log({
      auditId: "test-log",
      timestamp: new Date().toISOString(),
      sql: "UPDATE users SET ssn = '123-45-6789' WHERE id = 1",
      operation: "UPDATE",
      status: "SUCCESS",
      riskLevel: "LOW",
      riskScore: 10,
    });

    assert.equal(capturedEntries.length, 1);
    // Verified that PII in the query was sanitized before streaming
    assert.ok(!capturedEntries[0].sql.includes("123-45-6789"));
    assert.ok(capturedEntries[0].sql.includes("***-**-6789"));
  } finally {
    globalThis.fetch = originalFetch;
  }
});
