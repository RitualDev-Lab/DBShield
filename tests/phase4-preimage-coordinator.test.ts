import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { SqliteAdapter } from "../src/adapters/sqlite.js";
import { ChatOpsNotifier } from "../src/approval/chatops.js";
import { ApprovalQueue } from "../src/approval/queue.js";
import { PreImageChecksumCoordinator } from "../src/sandbox/preimage-coordinator.js";

test("Phase 4: Non-blocking Pre-Image Checksum Coordinator releases locks immediately & allows zero-contention concurrent reads", async () => {
  const dir = mkdtempSync(join(tmpdir(), "dbshield-p4-"));
  const dbPath = join(dir, "orders.sqlite");
  const primaryAdapter = new SqliteAdapter(dbPath);
  const readerAdapter = new SqliteAdapter(dbPath);
  const freshCommitAdapter = new SqliteAdapter(dbPath);

  try {
    await primaryAdapter.connect();
    await readerAdapter.connect();
    await freshCommitAdapter.connect();

    await primaryAdapter.query(`
      CREATE TABLE orders (
        id INTEGER PRIMARY KEY,
        status TEXT NOT NULL,
        amount INTEGER NOT NULL,
        updated_at TEXT NOT NULL
      );
    `);
    await primaryAdapter.query(`
      INSERT INTO orders (id, status, amount, updated_at) VALUES
        (1, 'active', 120, '2026-11-18T01:00:00Z'),
        (2, 'archived', 45, '2026-11-18T01:05:00Z'),
        (3, 'archived', 80, '2026-11-18T01:10:00Z');
    `);

    const queue = new ApprovalQueue();
    const notifier = new ChatOpsNotifier(
      {
        enabled: false,
        callbackBaseUrl: "https://approvals.ritualdev.in",
        slackSigningSecret: "test-hmac-secret",
      },
      queue,
    );

    const coordinator = new PreImageChecksumCoordinator({
      adapter: primaryAdapter,
      queue,
      notifier,
      signingSecret: "test-hmac-secret",
    });

    // Phase 1: Synchronous inspection (<5ms target, immediate ROLLBACK, 0 locks held)
    const destructiveSql = "DELETE FROM orders WHERE status = 'archived';";
    const phase1 = await coordinator.inspectAndStage({
      sql: destructiveSql,
      riskLevel: "CRITICAL",
      riskScore: 92,
      agentId: "autonomous-cleaner",
    });

    assert.equal(phase1.rollbackExecuted, true);
    assert.equal(phase1.locksHeldAfterPhase1, 0);
    assert.equal(phase1.dryRun.simulatedAffectedRows, 2);
    assert.equal(phase1.preImage.tables[0].rowCount, 3);
    assert.equal(phase1.preImage.tables[0].latestTimestamp, "2026-11-18T01:10:00Z");
    assert.ok(phase1.signedApproveUrl.includes("signature="));
    assert.ok(
      JSON.stringify(phase1.slackBlockKit).includes(phase1.preImage.checksum.slice(0, 16)),
      "Slack Block Kit card must embed pre-image checksum",
    );

    // Concurrent Load Test: While destructive mutation sits PENDING awaiting human approval,
    // 50 concurrent SELECT reads on a separate connection must complete with ZERO lock contention!
    const readStart = performance.now();
    const readResults = await Promise.all(
      Array.from({ length: 50 }, () => readerAdapter.query("SELECT COUNT(*) AS cnt FROM orders;")),
    );
    const totalReadMs = performance.now() - readStart;
    assert.equal(readResults.length, 50);
    for (const r of readResults) {
      assert.equal(Number(r.rows[0].cnt), 3, "Dry-run rollback must leave all 3 rows intact");
    }
    assert.ok(
      totalReadMs < 2000,
      `Expected zero-contention concurrent reads, got ${totalReadMs.toFixed(1)}ms`,
    );

    // Attempting Phase 2 before approval must fail cleanly
    const premature = await coordinator.executeApprovedCommit(
      phase1.approvalRequest.id,
      freshCommitAdapter,
    );
    assert.equal(premature.committed, false);
    assert.equal(premature.status, "NOT_APPROVED");

    // Human approves via Slack interactive button
    const slackRes = notifier.handleSlackAction({
      actionId: "dbshield_approve",
      requestId: phase1.approvalRequest.id,
      userName: "sec-lead",
    });
    assert.equal(slackRes.success, true);

    // Phase 2: Fresh connection verifies unchanged pre-image checksum and executes approved query
    const phase2 = await coordinator.executeApprovedCommit(
      phase1.approvalRequest.id,
      freshCommitAdapter,
    );
    assert.equal(phase2.committed, true);
    assert.equal(phase2.status, "COMMITTED");
    assert.equal(phase2.liveChecksum, phase1.preImage.checksum);

    const afterCount = await readerAdapter.query("SELECT COUNT(*) AS cnt FROM orders;");
    assert.equal(Number(afterCount.rows[0].cnt), 1, "Approved DELETE must remove 2 archived rows");
  } finally {
    await primaryAdapter.disconnect();
    await readerAdapter.disconnect();
    await freshCommitAdapter.disconnect();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Phase 4: Pre-Image Checksum Coordinator aborts Phase 2 commit on TOCTOU state drift", async () => {
  const adapter = new SqliteAdapter(":memory:");
  await adapter.connect();

  try {
    await adapter.query(`
      CREATE TABLE invoices (
        id INTEGER PRIMARY KEY,
        state TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
    `);
    await adapter.query(`
      INSERT INTO invoices (id, state, updated_at) VALUES
        (1, 'draft', '2026-11-18T02:00:00Z'),
        (2, 'draft', '2026-11-18T02:01:00Z');
    `);

    const queue = new ApprovalQueue();
    const notifier = new ChatOpsNotifier({ enabled: false }, queue);
    const coordinator = new PreImageChecksumCoordinator({ adapter, queue, notifier });

    const phase1 = await coordinator.inspectAndStage({
      sql: "DELETE FROM invoices WHERE state = 'draft';",
      riskLevel: "CRITICAL",
    });

    // Simulate concurrent modification BEFORE human clicks Approve
    await adapter.query(
      "INSERT INTO invoices (id, state, updated_at) VALUES (3, 'draft', '2026-11-18T02:05:00Z');",
    );

    queue.approve(phase1.approvalRequest.id, "oncall-dba");

    const phase2 = await coordinator.executeApprovedCommit(phase1.approvalRequest.id);
    assert.equal(phase2.committed, false);
    assert.equal(phase2.status, "PREIMAGE_DRIFT_DETECTED");
    assert.notEqual(phase2.liveChecksum, phase2.preImageChecksum);

    // Ensure 0 rows were deleted because drift guard aborted safely
    const remaining = await adapter.query("SELECT COUNT(*) AS cnt FROM invoices;");
    assert.equal(Number(remaining.rows[0].cnt), 3);
  } finally {
    await adapter.disconnect();
  }
});
