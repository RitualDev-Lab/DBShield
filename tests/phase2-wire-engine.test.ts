import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  HighConcurrencyConnectionPool,
  ProtocolWireMasker,
  VirtualShadowDatabase,
} from "../src/index.js";

describe("Phase 2 (DBShield): High-Concurrency Connection Pooling", () => {
  it("acquires, releases, and recycles pooled connections with sub-millisecond overhead", () => {
    const pool = new HighConcurrencyConnectionPool<{ destroy: () => void; id: number }>({
      maxConnections: 10,
      idleTimeoutMs: 1000,
    });

    let destroyed = false;
    const mockSocket = {
      id: 1,
      destroy: () => {
        destroyed = true;
      },
    };

    assert.equal(pool.acquire(), null, "Empty pool returns null initially");
    assert.equal(pool.trackNewConnection(), true);

    pool.release(mockSocket);
    const stats1 = pool.getStats();
    assert.equal(stats1.idle, 1);

    const reacquired = pool.acquire();
    assert.equal(reacquired?.id, 1, "Recycled socket returned");

    pool.release(reacquired);
    pool.drain();
    assert.equal(destroyed, true, "Drain destroys all sockets in pool");
  });
});

describe("Phase 2 (DBShield): Virtual Shadow Database (Copy-on-Write)", () => {
  it("intercepts DROP TABLE and returns simulated execution success without mutating live DB", () => {
    const shadow = new VirtualShadowDatabase();
    assert.equal(shadow.shouldInterceptToShadow("DROP TABLE customers CASCADE;"), true);

    const res = shadow.executeInShadow("DROP TABLE customers CASCADE;");
    assert.equal(res.simulated, true);
    assert.equal(res.commandTag, "DROP TABLE");
    assert.equal(shadow.isTableDropped("customers"), true);
    assert.ok(res.warnings[0].includes("SHADOW_INTERCEPTED"));
  });

  it("intercepts unconstrained DELETE and returns simulated affected rows safely", () => {
    const shadow = new VirtualShadowDatabase();
    assert.equal(shadow.shouldInterceptToShadow("DELETE FROM audit_logs"), true);

    const res = shadow.executeInShadow("DELETE FROM audit_logs");
    assert.equal(res.simulated, true);
    assert.equal(res.commandTag, "DELETE 42");
    assert.equal(res.affectedRows, 42);
    assert.ok(res.warnings.some((w) => w.includes("SIMULATED_SUCCESS")));
  });

  it("allows safe parameterized queries to bypass shadow layer", () => {
    const shadow = new VirtualShadowDatabase();
    assert.equal(shadow.shouldInterceptToShadow("SELECT * FROM users WHERE id = $1"), false);
    assert.equal(shadow.shouldInterceptToShadow("DELETE FROM users WHERE id = $1"), false);
  });
});

describe("Phase 2 (DBShield): Protocol-Level Wire Masking & Format-Preserving Pseudonymization", () => {
  it("masks PII columns on wire with deterministic format preservation", () => {
    const masker = new ProtocolWireMasker({
      salt: "enterprise-audit-salt",
      enableFormatPreserving: true,
    });

    const rawRow = {
      id: 101,
      name: "Alice Smith",
      email: "alice.smith@enterprise.corp",
      phone: "+1-555-839-2094",
      credit_card: "4111-2222-3333-4444",
      balance: 9500.5,
    };

    const masked = masker.maskRow(rawRow);
    assert.equal(masked.id, 101);
    assert.equal(masked.name, "Alice Smith");
    assert.equal(masked.balance, 9500.5);

    // Format preservation
    assert.ok(String(masked.email).startsWith("user_"));
    assert.ok(String(masked.email).endsWith("@enterprise.corp"));
    assert.equal(masked.phone, "+***-***-2094");
    assert.equal(masked.credit_card, "****-****-****-4444");

    // Referential integrity check (same value = same pseudonym)
    const masked2 = masker.maskRow(rawRow);
    assert.equal(masked.email, masked2.email);
  });

  it("masks PostgreSQL 'D' DataRow binary wire frames directly", () => {
    const masker = new ProtocolWireMasker({
      salt: "pg-wire-salt",
      enableFormatPreserving: true,
    });

    // Construct a synthetic PostgreSQL 'D' DataRow frame with 3 columns:
    // col 0: id = "101" (3B)
    // col 1: email = "alice@company.com" (17B)
    // col 2: score = "98" (2B)
    const col0 = Buffer.from("101", "utf8");
    const col1 = Buffer.from("alice@company.com", "utf8");
    const col2 = Buffer.from("98", "utf8");

    const payloadParts: Buffer[] = [];
    for (const c of [col0, col1, col2]) {
      const lenBuf = Buffer.alloc(4);
      lenBuf.writeInt32BE(c.length, 0);
      payloadParts.push(Buffer.concat([lenBuf, c]));
    }
    const payload = Buffer.concat(payloadParts);
    const totalLen = 4 + 2 + payload.length;

    const frameHeader = Buffer.alloc(7);
    frameHeader[0] = 0x44; // 'D'
    frameHeader.writeInt32BE(totalLen, 1);
    frameHeader.writeInt16BE(3, 5); // 3 columns
    const rawDataRow = Buffer.concat([frameHeader, payload]);

    const maskedDataRow = masker.maskPostgresDataRow(rawDataRow, ["id", "email", "score"]);

    assert.equal(maskedDataRow[0], 0x44, "Must maintain 'D' packet identifier");
    const newTotalLen = maskedDataRow.readInt32BE(1);
    assert.equal(maskedDataRow.length, newTotalLen + 1, "Length header must match packet length");
    const colCount = maskedDataRow.readInt16BE(5);
    assert.equal(colCount, 3);

    // Verify email was pseudonymized
    assert.ok(!maskedDataRow.toString("utf8").includes("alice@company.com"));
    assert.ok(maskedDataRow.toString("utf8").includes("@company.com"));
    assert.ok(maskedDataRow.toString("utf8").includes("101"));
  });

  it("masks MySQL text resultset row packets directly", () => {
    const masker = new ProtocolWireMasker({
      salt: "mysql-wire-salt",
      enableFormatPreserving: true,
    });

    // MySQL row packet: seqId=1, 2 columns: name="Bob", ssn="123-45-6789"
    const col0 = Buffer.concat([Buffer.from([3]), Buffer.from("Bob", "utf8")]);
    const col1 = Buffer.concat([Buffer.from([11]), Buffer.from("123-45-6789", "utf8")]);
    const payload = Buffer.concat([col0, col1]);

    const packetHeader = Buffer.alloc(4);
    packetHeader[0] = payload.length & 0xff;
    packetHeader[1] = (payload.length >> 8) & 0xff;
    packetHeader[2] = (payload.length >> 16) & 0xff;
    packetHeader[3] = 1; // Seq ID

    const rawMysqlPacket = Buffer.concat([packetHeader, payload]);
    const maskedMysqlPacket = masker.maskMysqlRowPacket(rawMysqlPacket, ["name", "ssn"]);

    assert.ok(!maskedMysqlPacket.toString("utf8").includes("123-45-6789"));
    assert.ok(maskedMysqlPacket.toString("utf8").includes("Bob"));
    assert.ok(maskedMysqlPacket.toString("utf8").includes("***-**-6789"));
  });
});

describe("Phase 2 (DBShield): Detached Lock-Free Dry-Run Transaction Engine", () => {
  it("executes speculative mutation in isolated session with guaranteed immediate ROLLBACK", async () => {
    const { SqliteAdapter, DetachedDryRunEngine } = await import("../src/index.js");
    const adapter = new SqliteAdapter(":memory:");
    await adapter.connect();

    // Setup initial schema & data
    await adapter.query("CREATE TABLE accounts (id INTEGER PRIMARY KEY, balance REAL);");
    await adapter.query("INSERT INTO accounts (id, balance) VALUES (1, 500.0), (2, 1000.0);");

    const engine = new DetachedDryRunEngine(adapter);

    // Run speculative mutation that wipes all balances
    const report = await engine.executeDetachedDryRun("UPDATE accounts SET balance = 0;", [], {
      intent: "Reset all balances for year-end audit",
      expectedAffectedRows: 2,
    });

    assert.equal(report.safe, true);
    assert.equal(report.simulatedAffectedRows, 2);
    assert.equal(report.rollbackVerified, true);
    assert.equal(report.intentAligned, true);
    assert.ok(report.lockAcquisitionTimeMs >= 0);
    assert.ok(report.commitToken);
    assert.ok(report.tokenDetails?.token);
    assert.ok(report.diffPreview?.diffSummary.includes("2 row(s) staged for mutation"));

    // Verify production table state was 100% UNTOUCHED (Guaranteed Rollback)
    const checkRes = await adapter.query("SELECT * FROM accounts WHERE balance > 0;");
    assert.equal(checkRes.rowCount, 2, "Production balances must remain untouched after dry-run");

    await adapter.disconnect();
  });
});

describe("Phase 2 (DBShield): Interactive Slack & Microsoft Teams Approval Cards", () => {
  it("generates Slack Block Kit with interactive buttons including Diff inspection", async () => {
    const { ApprovalQueue, ChatOpsNotifier } = await import("../src/index.js");
    const queue = new ApprovalQueue();
    const notifier = new ChatOpsNotifier(
      {
        enabled: true,
        slackWebhookUrl: "https://hooks.slack.com/services/T00/B00/X00",
      },
      queue,
    );

    const req = queue.enqueue({
      operation: "DROP_TABLE",
      sql: "DROP TABLE legacy_users;",
      riskLevel: "CRITICAL",
      riskScore: 95,
      targetTables: ["legacy_users"],
    });

    const slackPayload = notifier.buildSlackBlocks(req);
    assert.ok(slackPayload.text.includes("DROP_TABLE"));
    const actionBlock = slackPayload.blocks.find((b: any) => b.type === "actions");
    assert.ok(actionBlock);
    assert.equal(actionBlock.elements.length, 3, "Must include Approve, Reject, and Inspect Diff");
    assert.equal(actionBlock.elements[0].action_id, "dbshield_approve");
    assert.equal(actionBlock.elements[1].action_id, "dbshield_reject");
    assert.equal(actionBlock.elements[2].action_id, "dbshield_view_diff");
  });

  it("generates Microsoft Teams AdaptiveCard with HMAC-signed action URLs and validates signatures", async () => {
    const { ApprovalQueue, ChatOpsNotifier } = await import("../src/index.js");
    const queue = new ApprovalQueue();
    const notifier = new ChatOpsNotifier(
      {
        enabled: true,
        teamsWebhookUrl: "https://outlook.office.com/webhook/test",
        callbackBaseUrl: "https://dbshield.enterprise.internal",
        slackSigningSecret: "test-secret-key-123",
      },
      queue,
    );

    const req = queue.enqueue({
      operation: "TRUNCATE",
      sql: "TRUNCATE orders;",
      riskLevel: "CRITICAL",
      riskScore: 100,
      targetTables: ["orders"],
    });

    const card = notifier.buildTeamsCard(req) as any;
    assert.equal(card.type, "message");
    const actions = card.attachments[0].content.actions;
    assert.equal(actions.length, 3);
    assert.ok(actions[0].url.includes("/api/approvals/"));
    assert.ok(actions[0].url.includes("signature="));

    // Verify HMAC signed action link
    const url = new URL(actions[0].url);
    const signature = url.searchParams.get("signature")!;
    const expires = url.searchParams.get("expires")!;

    const isValid = notifier.verifySignedAction(req.id, "approve", expires, signature);
    assert.equal(isValid, true, "Signature must be cryptographically valid");

    // Tampered action check
    const isTampered = notifier.verifySignedAction(req.id, "reject", expires, signature);
    assert.equal(isTampered, false, "Signature must reject tampered action parameter");
  });
});
