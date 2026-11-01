import assert from "node:assert";
import test from "node:test";
import { ApprovalQueue } from "../src/approval/queue.js";
import { DashboardServer } from "../src/dashboard/server.js";
import type { DBShieldConfig } from "../src/types/index.js";

test("ApprovalQueue - Enqueues, approves, and notifies subscribers", async () => {
  const queue = new ApprovalQueue();
  let receivedId = "";

  queue.subscribe((req) => {
    receivedId = req.id;
  });

  const req = queue.enqueue({
    sql: "DELETE FROM users WHERE inactive = 1;",
    operation: "DELETE",
    riskLevel: "CAUTION",
    riskScore: 45,
    targetTables: ["users"],
    piiRedacted: true,
  });

  assert.strictEqual(req.status, "PENDING");
  assert.strictEqual(receivedId, req.id);
  assert.strictEqual(queue.getPending().length, 1);

  // 1-Click Approve
  const approved = queue.approve(req.id, "Security Lead");
  assert.strictEqual(approved, true);

  const updated = queue.get(req.id);
  assert.strictEqual(updated?.status, "APPROVED");
  assert.strictEqual(updated?.decidedBy, "Security Lead");
  assert.strictEqual(queue.getPending().length, 0);
});

test("ApprovalQueue - waitForDecision resolves asynchronously on reject", async () => {
  const queue = new ApprovalQueue();
  const req = queue.enqueue({
    sql: "UPDATE balances SET amount = 0;",
    operation: "UPDATE",
    riskLevel: "CRITICAL",
    riskScore: 90,
  });

  const waitPromise = queue.waitForDecision(req.id, 5000);

  // Simulate human rejecting after 50ms
  setTimeout(() => {
    queue.reject(req.id, "Lead Admin", "Unbounded balance reset forbidden");
  }, 50);

  const decision = await waitPromise;
  assert.strictEqual(decision, "REJECTED");
  assert.strictEqual(queue.get(req.id)?.status, "REJECTED");
});

test("DashboardServer - HTTP Lifecycle, REST endpoints and HTML dashboard", async () => {
  const config: DBShieldConfig = {
    dialect: "sqlite",
    safetyTier: "BALANCED",
    maxRowsPerMutation: 50,
    maxRowsPerRead: 500,
    allowDestructiveDDL: false,
    enablePiiMasking: true,
    enableCostGate: false,
    enableMigrationGate: false,
    enableSemanticGuard: false,
    maxEstimatedCost: 50000,
    maxEstimatedRows: 100000,
    statementTimeoutMs: 5000,
    enforceConcurrentIndexCreation: false,
    disallowBreakingRenames: true,
    requireIntentForSensitiveColumns: false,
    dashboardPort: 0, // Random ephemeral port
  };

  const queue = new ApprovalQueue();
  const dashboard = new DashboardServer(config, queue);

  await dashboard.start(0);
  const port = dashboard.getPort();
  const baseUrl = `http://localhost:${port}`;

  // 1. Health check
  const healthRes = await fetch(`${baseUrl}/healthz`);
  assert.strictEqual(healthRes.status, 200);
  const healthJson = await healthRes.json();
  assert.strictEqual(healthJson.status, "ok");

  // 2. HTML UI
  const htmlRes = await fetch(`${baseUrl}/`);
  assert.strictEqual(htmlRes.status, 200);
  const htmlText = await htmlRes.text();
  assert.strictEqual(htmlText.includes("DBShield Live Query Defense & Approval Feed"), true);
  assert.strictEqual(htmlText.includes("1-Click Approve"), true);

  // 3. Enqueue mutation and query via API
  const req = queue.enqueue({
    sql: "UPDATE users SET role = 'admin' WHERE id = 1;",
    operation: "UPDATE",
    riskLevel: "CRITICAL",
    riskScore: 85,
    targetTables: ["users"],
  });

  const listRes = await fetch(`${baseUrl}/api/approvals`);
  const listJson = await listRes.json();
  assert.strictEqual(listJson.approvals.length, 1);
  assert.strictEqual(listJson.approvals[0].id, req.id);

  // 4. 1-Click Approve via POST API
  const apprRes = await fetch(`${baseUrl}/api/approvals/${req.id}/approve`, { method: "POST" });
  assert.strictEqual(apprRes.status, 200);
  const apprJson = await apprRes.json();
  assert.strictEqual(apprJson.success, true);
  assert.strictEqual(apprJson.status, "APPROVED");

  // 5. Verify queue state updated
  assert.strictEqual(queue.get(req.id)?.status, "APPROVED");

  await dashboard.stop();
});
