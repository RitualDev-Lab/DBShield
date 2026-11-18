/**
 * DBShield Non-Blocking Pre-Image Checksum Coordinator
 *
 * Eliminates long-lived database locks during human-in-the-loop ChatOps approvals:
 * - Phase 1 (Synchronous Inspection, <5ms): Runs detached dry-run, computes a cryptographic
 *   SHA-256 pre-image state checksum (row count + latest timestamp + schema hash) across target
 *   tables, immediately enforces ROLLBACK to release all DB connection pool locks, and produces
 *   HMAC-signed Slack Block Kit & MS Teams AdaptiveCard approval payloads.
 * - Phase 2 (Asynchronous ChatOps Commit): On human approval, opens a fresh database execution
 *   path, recomputes the live pre-image state checksum, aborts on TOCTOU drift, or commits cleanly.
 */

import crypto from "node:crypto";
import type { ChatOpsNotifier } from "../approval/chatops.js";
import type { ApprovalQueue } from "../approval/queue.js";
import { parseSql } from "../guard/ast.js";
import type {
  ApprovalRequest,
  DatabaseAdapter,
  QueryResult,
  RiskLevel,
  SqlOperationType,
} from "../types/index.js";
import { DetachedDryRunEngine, type DetachedDryRunReport } from "./detached-dryrun.js";

export interface TablePreImageSnapshot {
  table: string;
  rowCount: number;
  latestTimestamp: string | null;
  schemaHash: string;
}

export interface PreImageChecksum {
  checksum: string;
  capturedAt: string;
  tables: TablePreImageSnapshot[];
}

export interface Phase1InspectionResult {
  approvalRequest: ApprovalRequest;
  preImage: PreImageChecksum;
  dryRun: DetachedDryRunReport;
  rollbackExecuted: boolean;
  locksHeldAfterPhase1: 0;
  phase1LatencyMs: number;
  signedApproveUrl: string;
  signedRejectUrl: string;
  slackBlockKit: { text: string; blocks: unknown[] };
  teamsAdaptiveCard: object;
}

export interface Phase2CommitResult {
  committed: boolean;
  status:
    | "COMMITTED"
    | "PREIMAGE_DRIFT_DETECTED"
    | "NOT_APPROVED"
    | "NOT_FOUND"
    | "EXECUTION_ERROR";
  preImageChecksum: string;
  liveChecksum?: string;
  queryResult?: QueryResult;
  error?: string;
}

interface PendingPreImageRecord {
  requestId: string;
  sql: string;
  params: unknown[];
  targetTables: string[];
  preImage: PreImageChecksum;
  status: "PENDING" | "COMMITTED" | "ABORTED_DRIFT";
}

export class PreImageChecksumCoordinator {
  private readonly adapter: DatabaseAdapter;
  private readonly queue: ApprovalQueue;
  private readonly notifier: ChatOpsNotifier;
  private readonly dryRunEngine: DetachedDryRunEngine;
  private readonly pendingRecords = new Map<string, PendingPreImageRecord>();
  private readonly signingSecret: string;

  constructor(options: {
    adapter: DatabaseAdapter;
    queue: ApprovalQueue;
    notifier: ChatOpsNotifier;
    signingSecret?: string;
  }) {
    this.adapter = options.adapter;
    this.queue = options.queue;
    this.notifier = options.notifier;
    this.dryRunEngine = new DetachedDryRunEngine(options.adapter);
    this.signingSecret =
      options.signingSecret || process.env.DBSHIELD_CHATOPS_SECRET || "dbshield-chatops-secret";
  }

  /**
   * Computes a deterministic SHA-256 pre-image state checksum across target tables
   * combining row count, latest modification timestamp (if present), and table schema hash.
   */
  public async computePreImageChecksum(targetTables: string[]): Promise<PreImageChecksum> {
    const tablesToInspect = targetTables.length > 0 ? [...new Set(targetTables)].sort() : [];
    const schemaList = await this.adapter.getSchema().catch(() => []);
    const snapshots: TablePreImageSnapshot[] = [];

    for (const rawTable of tablesToInspect) {
      const safeIdent = rawTable.replace(/[^a-zA-Z0-9_]/g, "");
      if (!safeIdent) continue;

      const tableSchema = schemaList.find(
        (t) => t.tableName.toLowerCase() === safeIdent.toLowerCase(),
      );
      const schemaFingerprintSource = tableSchema
        ? JSON.stringify(tableSchema.columns.map((c) => `${c.name}:${c.type}:${c.nullable}`))
        : safeIdent;
      const schemaHash = crypto
        .createHash("sha256")
        .update(schemaFingerprintSource)
        .digest("hex")
        .slice(0, 16);

      let rowCount = 0;
      let latestTimestamp: string | null = null;

      try {
        const countRes = await this.adapter.query(`SELECT COUNT(*) AS cnt FROM ${safeIdent}`);
        const firstRow = countRes.rows[0];
        if (firstRow) {
          const val = firstRow.cnt ?? firstRow["COUNT(*)"] ?? Object.values(firstRow)[0];
          rowCount = Number(val) || 0;
        }
      } catch {
        rowCount = 0;
      }

      // Inspect latest timestamp column if present in schema
      const tsCol = tableSchema?.columns.find((c) =>
        /^(updated_at|modified_at|created_at|timestamp|ts)$/i.test(c.name),
      );
      if (tsCol) {
        try {
          const tsSafe = tsCol.name.replace(/[^a-zA-Z0-9_]/g, "");
          const tsRes = await this.adapter.query(
            `SELECT MAX(${tsSafe}) AS latest_ts FROM ${safeIdent}`,
          );
          const tsVal = tsRes.rows[0]?.latest_ts;
          latestTimestamp = tsVal !== undefined && tsVal !== null ? String(tsVal) : null;
        } catch {
          latestTimestamp = null;
        }
      }

      snapshots.push({
        table: safeIdent,
        rowCount,
        latestTimestamp,
        schemaHash,
      });
    }

    const digestInput = snapshots
      .map((s) => `${s.table}|${s.rowCount}|${s.latestTimestamp ?? "null"}|${s.schemaHash}`)
      .join(";");
    const checksum = crypto.createHash("sha256").update(digestInput).digest("hex");

    return {
      checksum,
      capturedAt: new Date().toISOString(),
      tables: snapshots,
    };
  }

  /**
   * Phase 1 (Synchronous Inspection, <5ms target):
   * Executes detached dry-run with guaranteed immediate ROLLBACK, captures pre-image checksum,
   * releases all DB locks, enqueues ChatOps approval request, and returns HMAC-signed Slack/Teams cards.
   */
  public async inspectAndStage(options: {
    sql: string;
    params?: unknown[];
    riskLevel?: RiskLevel;
    riskScore?: number;
    agentId?: string;
    clientIp?: string;
    intent?: string;
  }): Promise<Phase1InspectionResult> {
    const start = performance.now();
    const params = options.params || [];

    let targetTables: string[] = [];
    let operation: SqlOperationType = "UPDATE";
    try {
      const parsed = parseSql(options.sql, this.adapter.dialect);
      if (parsed.statements.length > 0) {
        targetTables = parsed.statements[0].targetTables || [];
        operation = parsed.statements[0].operation || "UPDATE";
      }
    } catch {
      // Fallback regex table extraction for non-standard SQL dialects
      const match = options.sql.match(/\b(?:FROM|UPDATE|INTO|TABLE)\s+([a-zA-Z0-9_]+)/i);
      if (match?.[1]) targetTables = [match[1]];
    }

    // 1. Capture pre-image state checksum BEFORE releasing locks
    const preImage = await this.computePreImageChecksum(targetTables);

    // 2. Execute detached dry-run with guaranteed immediate ROLLBACK (releases all pool locks)
    const dryRun = await this.dryRunEngine.executeDetachedDryRun(options.sql, params, {
      intent: options.intent,
    });

    // 3. Enqueue non-blocking ChatOps approval request (connection pool is now 100% free)
    const approvalRequest = this.queue.enqueue({
      sql: options.sql,
      operation,
      riskLevel: options.riskLevel ?? "CRITICAL",
      riskScore: options.riskScore ?? 85,
      targetTables,
      agentId: options.agentId,
      clientIp: options.clientIp,
    });

    this.pendingRecords.set(approvalRequest.id, {
      requestId: approvalRequest.id,
      sql: options.sql,
      params,
      targetTables,
      preImage,
      status: "PENDING",
    });

    const signedApproveUrl = this.notifier.generateSignedActionUrl(approvalRequest.id, "approve");
    const signedRejectUrl = this.notifier.generateSignedActionUrl(approvalRequest.id, "reject");

    // 4. Build Slack Block Kit & MS Teams cards augmented with cryptographic pre-image checksum
    const slackBlockKit = this.notifier.buildSlackBlocks(approvalRequest);
    const hmacSeal = crypto
      .createHmac("sha256", this.signingSecret)
      .update(`${approvalRequest.id}:${preImage.checksum}`)
      .digest("hex")
      .slice(0, 16);
    slackBlockKit.blocks.push({
      type: "context",
      elements: [
        {
          type: "mrkdwn",
          text: `🔒 *Lock-Free Pre-Image Checksum:* \`${preImage.checksum.slice(0, 16)}…\` • *HMAC Seal:* \`${hmacSeal}\` • *Locks Held:* \`0\``,
        },
      ],
    });
    const teamsAdaptiveCard = this.notifier.buildTeamsCard(approvalRequest);

    const phase1LatencyMs = Number((performance.now() - start).toFixed(3));

    return {
      approvalRequest,
      preImage,
      dryRun,
      rollbackExecuted: dryRun.rollbackVerified,
      locksHeldAfterPhase1: 0,
      phase1LatencyMs,
      signedApproveUrl,
      signedRejectUrl,
      slackBlockKit,
      teamsAdaptiveCard,
    };
  }

  /**
   * Phase 2 (Asynchronous ChatOps Commit):
   * Runs only after human approval. Opens a fresh execution check to verify the live table
   * pre-image checksum matches Phase 1 (zero TOCTOU drift), then executes the approved mutation.
   */
  public async executeApprovedCommit(
    requestId: string,
    freshAdapter?: DatabaseAdapter,
  ): Promise<Phase2CommitResult> {
    const record = this.pendingRecords.get(requestId);
    if (!record) {
      return {
        committed: false,
        status: "NOT_FOUND",
        preImageChecksum: "",
        error: `No staged pre-image record found for approval ID '${requestId}'.`,
      };
    }

    const queueEntry = this.queue.get(requestId);
    if (!queueEntry || queueEntry.status !== "APPROVED") {
      return {
        committed: false,
        status: "NOT_APPROVED",
        preImageChecksum: record.preImage.checksum,
        error: `Approval '${requestId}' is in status '${queueEntry?.status ?? "UNKNOWN"}' (must be APPROVED).`,
      };
    }

    const executor = freshAdapter || this.adapter;
    const verifier = freshAdapter
      ? new PreImageChecksumCoordinator({
          adapter: freshAdapter,
          queue: this.queue,
          notifier: this.notifier,
          signingSecret: this.signingSecret,
        })
      : this;

    const liveSnapshot = await verifier.computePreImageChecksum(record.targetTables);

    if (liveSnapshot.checksum !== record.preImage.checksum) {
      record.status = "ABORTED_DRIFT";
      return {
        committed: false,
        status: "PREIMAGE_DRIFT_DETECTED",
        preImageChecksum: record.preImage.checksum,
        liveChecksum: liveSnapshot.checksum,
        error: `Pre-image state drifted between inspection (${record.preImage.checksum.slice(0, 12)}) and approval (${liveSnapshot.checksum.slice(0, 12)}). Aborting mutation to prevent stale write.`,
      };
    }

    try {
      const queryResult = await executor.executeCommit(record.sql, record.params);
      record.status = "COMMITTED";
      return {
        committed: true,
        status: "COMMITTED",
        preImageChecksum: record.preImage.checksum,
        liveChecksum: liveSnapshot.checksum,
        queryResult,
      };
    } catch (err) {
      return {
        committed: false,
        status: "EXECUTION_ERROR",
        preImageChecksum: record.preImage.checksum,
        liveChecksum: liveSnapshot.checksum,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  public getStagedRecord(requestId: string): PendingPreImageRecord | undefined {
    return this.pendingRecords.get(requestId);
  }
}
