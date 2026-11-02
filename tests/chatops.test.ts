import assert from "node:assert";
import crypto from "node:crypto";
import test from "node:test";
import { ChatOpsNotifier } from "../src/approval/chatops.js";
import { ApprovalQueue } from "../src/approval/queue.js";
import { DashboardServer } from "../src/dashboard/server.js";
import type { DBShieldConfig } from "../src/types/index.js";

const mockConfig: DBShieldConfig = {
  dialect: "sqlite",
  storagePath: ":memory:",
  safetyTier: "BALANCED",
  maxRowsPerMutation: 50,
  maxRowsPerRead: 500,
  allowDestructiveDDL: false,
  enablePiiMasking: true,
  enableCostGate: false,
  maxEstimatedCost: 10000,
  maxEstimatedRows: 5000,
  blockUnindexedSeqScan: false,
  statementTimeoutMs: 5000,
  enableMigrationGate: false,
  enforceConcurrentIndexCreation: false,
  disallowBreakingRenames: false,
  enableSemanticGuard: false,
  requireIntentForSensitiveColumns: false,
};

test("ChatOpsNotifier - Generates Slack Block Kit with Interactive Action Buttons", () => {
  const queue = new ApprovalQueue();
  const notifier = new ChatOpsNotifier(
    {
      enabled: true,
      slackWebhookUrl: "https://hooks.slack.com/services/test/test/test",
      slackChannel: "#db-approvals",
    },
    queue,
  );

  const req = queue.enqueue({
    sql: "UPDATE employees SET salary = salary * 1.15 WHERE department = 'Sales';",
    operation: "UPDATE",
    riskLevel: "CAUTION",
    riskScore: 75,
    targetTables: ["employees"],
    piiRedacted: true,
  });

  const slackPayload = notifier.buildSlackBlocks(req);
  assert.ok(slackPayload.text.includes("UPDATE on employees"));
  assert.strictEqual(slackPayload.blocks.length, 4);

  // Check header
  assert.strictEqual(slackPayload.blocks[0].type, "header");

  // Check action buttons
  const actionsBlock = slackPayload.blocks[3];
  assert.strictEqual(actionsBlock.type, "actions");
  assert.strictEqual(actionsBlock.elements[0].action_id, "dbshield_approve");
  assert.strictEqual(actionsBlock.elements[0].value, req.id);
  assert.strictEqual(actionsBlock.elements[1].action_id, "dbshield_reject");
  assert.strictEqual(actionsBlock.elements[1].value, req.id);
});

test("ChatOpsNotifier - Generates Microsoft Teams AdaptiveCard", () => {
  const queue = new ApprovalQueue();
  const notifier = new ChatOpsNotifier(
    {
      enabled: true,
      teamsWebhookUrl: "https://outlook.office.com/webhook/test",
      callbackBaseUrl: "https://dbshield.enterprise.internal",
    },
    queue,
  );

  const req = queue.enqueue({
    sql: "DELETE FROM user_tokens WHERE expired = 1;",
    operation: "DELETE",
    riskLevel: "CAUTION",
    riskScore: 40,
    targetTables: ["user_tokens"],
  });

  const card = notifier.buildTeamsCard(req) as any;
  assert.strictEqual(card.type, "message");
  assert.strictEqual(card.attachments[0].contentType, "application/vnd.microsoft.card.adaptive");
  assert.ok(card.attachments[0].content.body.some((b: any) => b.type === "FactSet"));
  assert.strictEqual(card.attachments[0].content.actions.length, 2);
});

test("ChatOpsNotifier - Verifies Slack Request HMAC-SHA256 Signatures", () => {
  const queue = new ApprovalQueue();
  const signingSecret = "slack-secret-key-123456";
  const notifier = new ChatOpsNotifier(
    {
      enabled: true,
      slackSigningSecret: signingSecret,
    },
    queue,
  );

  const timestamp = Math.floor(Date.now() / 1000).toString();
  const rawBody = "payload=%7B%22type%22%3A%22block_actions%22%7D";
  const sigBasestring = `v0:${timestamp}:${rawBody}`;
  const validSignature = `v0=${crypto.createHmac("sha256", signingSecret).update(sigBasestring).digest("hex")}`;

  assert.strictEqual(notifier.verifySlackSignature(rawBody, validSignature, timestamp), true);
  assert.strictEqual(
    notifier.verifySlackSignature(rawBody, "v0=invalid-signature", timestamp),
    false,
  );
});

test("ChatOpsNotifier - Handles Slack [Approve] & [Reject] Actions and Resolves Queue", () => {
  const queue = new ApprovalQueue();
  const notifier = new ChatOpsNotifier({ enabled: true }, queue);

  const req = queue.enqueue({
    sql: "UPDATE orders SET status = 'REFUNDED' WHERE id = 1001;",
    operation: "UPDATE",
    riskLevel: "CAUTION",
    riskScore: 80,
    targetTables: ["orders"],
  });

  assert.strictEqual(req.status, "PENDING");

  // Handle Approve
  const approveResult = notifier.handleSlackAction({
    actionId: "dbshield_approve",
    requestId: req.id,
    userName: "alex_lead_dba",
    userEmail: "alex@ritual.dev",
  });

  assert.strictEqual(approveResult.success, true);
  assert.strictEqual(approveResult.status, "APPROVED");

  const updatedReq = queue.get(req.id)!;
  assert.strictEqual(updatedReq.status, "APPROVED");
  assert.strictEqual(updatedReq.decidedBy, "alex@ritual.dev");
});

test("DashboardServer - Slack Action Webhook Endpoint Integration", async () => {
  const queue = new ApprovalQueue();
  const dashboard = new DashboardServer({ ...mockConfig }, queue);
  await dashboard.start(0);
  const port = dashboard.getPort();

  try {
    const req = queue.enqueue({
      sql: "DROP INDEX idx_logs_created;",
      operation: "DDL",
      riskLevel: "CRITICAL",
      riskScore: 90,
      targetTables: ["logs"],
    });

    const slackPayload = {
      user: { username: "sarah_security", email: "sarah@ritual.dev" },
      actions: [
        {
          action_id: "dbshield_reject",
          value: req.id,
        },
      ],
    };

    const res = await fetch(`http://127.0.0.1:${port}/api/webhooks/slack/actions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: `payload=${encodeURIComponent(JSON.stringify(slackPayload))}`,
    });

    assert.strictEqual(res.status, 200);
    const body = (await res.json()) as any;
    assert.strictEqual(body.replace_original, true);
    assert.ok(body.text.includes("REJECTED"));

    const decided = queue.get(req.id)!;
    assert.strictEqual(decided.status, "REJECTED");
    assert.strictEqual(decided.decidedBy, "sarah@ritual.dev");
  } finally {
    await dashboard.stop();
  }
});
