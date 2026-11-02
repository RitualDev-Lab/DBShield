import crypto from "node:crypto";
import type { ApprovalRequest, ChatOpsConfig } from "../types/index.js";
import type { ApprovalQueue } from "./queue.js";

export class ChatOpsNotifier {
  private readonly config: ChatOpsConfig;
  private readonly queue: ApprovalQueue;

  constructor(config: ChatOpsConfig, queue: ApprovalQueue) {
    this.config = {
      enabled: config.enabled ?? true,
      notifyOnPending: config.notifyOnPending ?? true,
      notifyOnDecision: config.notifyOnDecision ?? true,
      ...config,
    };
    this.queue = queue;

    if (this.isEnabled()) {
      this.queue.subscribe((req) => {
        this.onApprovalEvent(req).catch(() => {});
      });
    }
  }

  public isEnabled(): boolean {
    return Boolean(
      this.config.enabled && (this.config.slackWebhookUrl || this.config.slackBotToken || this.config.teamsWebhookUrl),
    );
  }

  /**
   * Event listener triggered whenever an approval request changes state.
   */
  public async onApprovalEvent(request: ApprovalRequest): Promise<void> {
    if (!this.isEnabled()) return;

    if (request.status === "PENDING" && this.config.notifyOnPending) {
      await Promise.allSettled([
        this.notifySlack(request),
        this.notifyTeams(request),
      ]);
    } else if (
      (request.status === "APPROVED" || request.status === "REJECTED") &&
      this.config.notifyOnDecision
    ) {
      await Promise.allSettled([
        this.notifySlack(request),
        this.notifyTeams(request),
      ]);
    }
  }

  /**
   * Builds Slack Block Kit payload for an approval request.
   */
  public buildSlackBlocks(req: ApprovalRequest): {
    text: string;
    blocks: any[];
  } {
    const isPending = req.status === "PENDING";
    const statusEmoji =
      req.status === "APPROVED" ? "✅ APPROVED" : req.status === "REJECTED" ? "❌ REJECTED" : "🟡 PENDING REVIEW";
    const riskEmoji =
      req.riskLevel === "CRITICAL"
        ? "🚨 CRITICAL"
        : req.riskLevel === "BLOCKED"
          ? "🔴 BLOCKED"
          : req.riskLevel === "CAUTION"
            ? "🟠 CAUTION"
            : "🟢 SAFE";

    const blocks: any[] = [
      {
        type: "header",
        text: {
          type: "plain_text",
          text: `🛡️ DBShield: Mutation Approval Request [${req.operation}]`,
          emoji: true,
        },
      },
      {
        type: "section",
        fields: [
          {
            type: "mrkdwn",
            text: `*Status:* ${statusEmoji}\n*Target Tables:* \`${req.targetTables.join(", ") || "Unknown"}\``,
          },
          {
            type: "mrkdwn",
            text: `*Risk Score:* ${riskEmoji} (${req.riskScore}/100)\n*Agent IP:* \`${req.clientIp || "127.0.0.1"}\``,
          },
        ],
      },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*Intercepted SQL Statement:*\n\`\`\`sql\n${req.sql.slice(0, 1000)}\n\`\`\``,
        },
      },
    ];

    if (!isPending) {
      blocks.push({
        type: "context",
        elements: [
          {
            type: "mrkdwn",
            text: `Decided by *${req.decidedBy || "Developer"}* at _${req.decidedAt || new Date().toISOString()}_${
              req.reason ? `\n*Reason:* ${req.reason}` : ""
            }`,
          },
        ],
      });
    } else {
      // Interactive 1-Click Action Buttons
      blocks.push({
        type: "actions",
        block_id: `approval_actions_${req.id}`,
        elements: [
          {
            type: "button",
            text: {
              type: "plain_text",
              text: "Approve Mutation ✅",
              emoji: true,
            },
            style: "primary",
            action_id: "dbshield_approve",
            value: req.id,
          },
          {
            type: "button",
            text: {
              type: "plain_text",
              text: "Reject Mutation ❌",
              emoji: true,
            },
            style: "danger",
            action_id: "dbshield_reject",
            value: req.id,
          },
        ],
      });
    }

    return {
      text: `[DBShield] Mutation Approval Request: ${req.operation} on ${req.targetTables.join(", ") || "db"} (${req.status})`,
      blocks,
    };
  }

  /**
   * Builds Microsoft Teams AdaptiveCard payload for an approval request.
   */
  public buildTeamsCard(req: ApprovalRequest): object {
    const isPending = req.status === "PENDING";
    const statusColor =
      req.status === "APPROVED" ? "Good" : req.status === "REJECTED" ? "Attention" : "Warning";

    const body: any[] = [
      {
        type: "TextBlock",
        size: "Medium",
        weight: "Bolder",
        text: `🛡️ DBShield Mutation Approval [${req.operation}]`,
      },
      {
        type: "FactSet",
        facts: [
          { title: "Status", value: req.status },
          { title: "Risk Level", value: `${req.riskLevel} (${req.riskScore}/100)` },
          { title: "Target Tables", value: req.targetTables.join(", ") || "Unknown" },
          { title: "Agent ID", value: req.agentId || "agent-runtime" },
        ],
      },
      {
        type: "TextBlock",
        text: `SQL Query:\n\`\`\`sql\n${req.sql}\n\`\`\``,
        wrap: true,
      },
    ];

    if (!isPending) {
      body.push({
        type: "TextBlock",
        isSubtle: true,
        text: `Decided by ${req.decidedBy} at ${req.decidedAt}`,
      });
    }

    const card: any = {
      type: "message",
      attachments: [
        {
          contentType: "application/vnd.microsoft.card.adaptive",
          contentUrl: null,
          content: {
            $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
            type: "AdaptiveCard",
            version: "1.4",
            body,
          },
        },
      ],
    };

    if (isPending && this.config.callbackBaseUrl) {
      const base = this.config.callbackBaseUrl.replace(/\/$/, "");
      card.attachments[0].content.actions = [
        {
          type: "Action.OpenUrl",
          title: "Approve ✅",
          url: `${base}/api/approvals/${req.id}/approve`,
        },
        {
          type: "Action.OpenUrl",
          title: "Reject ❌",
          url: `${base}/api/approvals/${req.id}/reject`,
        },
      ];
    }

    return card;
  }

  /**
   * Verifies Slack request signature using SLACK_SIGNING_SECRET.
   */
  public verifySlackSignature(rawBody: string, signature: string, timestamp: string): boolean {
    if (!this.config.slackSigningSecret) {
      return true; // Skip verification if signing secret is not explicitly configured
    }

    const fiveMinutesAgo = Math.floor(Date.now() / 1000) - 60 * 5;
    const reqTimestamp = Number.parseInt(timestamp, 10);
    if (isNaN(reqTimestamp) || reqTimestamp < fiveMinutesAgo) {
      return false; // Replay attack prevention
    }

    const sigBasestring = `v0:${timestamp}:${rawBody}`;
    const mySignature =
      "v0=" +
      crypto
        .createHmac("sha256", this.config.slackSigningSecret)
        .update(sigBasestring)
        .digest("hex");

    const bufA = Buffer.from(mySignature, "utf8");
    const bufB = Buffer.from(signature, "utf8");

    if (bufA.length !== bufB.length) {
      return false;
    }

    return crypto.timingSafeEqual(bufA, bufB);
  }

  /**
   * Handles incoming Slack interactive webhook payloads when a developer clicks [Approve] or [Reject].
   */
  public handleSlackAction(actionData: {
    actionId: string;
    requestId: string;
    userName: string;
    userEmail?: string;
  }): { success: boolean; status?: string; updatedBlocks?: any; error?: string } {
    const { actionId, requestId, userName, userEmail } = actionData;
    const reviewer = userEmail || userName || "Slack User";

    let success = false;
    let status: "APPROVED" | "REJECTED" = "APPROVED";

    if (actionId === "dbshield_approve") {
      success = this.queue.approve(requestId, reviewer);
      status = "APPROVED";
    } else if (actionId === "dbshield_reject") {
      success = this.queue.reject(requestId, reviewer, "Rejected via Slack #db-approvals button");
      status = "REJECTED";
    } else {
      return { success: false, error: `Unknown action ID: ${actionId}` };
    }

    const updatedReq = this.queue.get(requestId);
    const updatedBlocks = updatedReq ? this.buildSlackBlocks(updatedReq).blocks : undefined;

    return { success, status, updatedBlocks };
  }

  /**
   * Sends a Block Kit message to Slack webhook or channel.
   */
  public async notifySlack(req: ApprovalRequest): Promise<{ success: boolean; error?: string }> {
    if (!this.config.slackWebhookUrl && !this.config.slackBotToken) {
      return { success: false, error: "Slack destination not configured" };
    }

    const payload = this.buildSlackBlocks(req);

    try {
      if (this.config.slackWebhookUrl) {
        const res = await fetch(this.config.slackWebhookUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        return { success: res.ok };
      }

      if (this.config.slackBotToken && this.config.slackChannel) {
        const res = await fetch("https://slack.com/api/chat.postMessage", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${this.config.slackBotToken}`,
          },
          body: JSON.stringify({
            channel: this.config.slackChannel,
            ...payload,
          }),
        });
        return { success: res.ok };
      }

      return { success: false, error: "Missing channel or webhook" };
    } catch (err) {
      return { success: false, error: String(err) };
    }
  }

  /**
   * Sends an AdaptiveCard message to Microsoft Teams incoming webhook.
   */
  public async notifyTeams(req: ApprovalRequest): Promise<{ success: boolean; error?: string }> {
    if (!this.config.teamsWebhookUrl) {
      return { success: false, error: "Teams webhook not configured" };
    }

    try {
      const card = this.buildTeamsCard(req);
      const res = await fetch(this.config.teamsWebhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(card),
      });
      return { success: res.ok };
    } catch (err) {
      return { success: false, error: String(err) };
    }
  }
}
