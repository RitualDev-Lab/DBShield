import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { PiiRedactor } from "../pii/redactor.js";
import type { RiskLevel, SqlOperationType } from "../types/index.js";
import {
  type AuditLedgerEntry,
  HmacAuditLedger,
  type HmacLedgerOptions,
  type LedgerVerificationResult,
} from "./hmac-ledger.js";
import { type SiemStreamStats, SiemTelemetryStreamer } from "./siem.js";

export {
  SiemTelemetryStreamer,
  type SiemStreamStats,
  HmacAuditLedger,
  type AuditLedgerEntry,
  type LedgerVerificationResult,
  type HmacLedgerOptions,
};

export interface AuditLogEntry {
  auditId: string;
  timestamp: string;
  sql: string;
  operation: SqlOperationType;
  status:
    | "SUCCESS"
    | "BLOCKED"
    | "DRY_RUN_APPROVED"
    | "DRY_RUN_REJECTED"
    | "COMMITTED"
    | "ERROR"
    | "TIMEOUT";
  riskLevel: RiskLevel;
  riskScore: number;
  rowCount?: number;
  executionTimeMs?: number;
  violations?: string[];
  piiRedacted?: boolean;
  previousHash?: string;
  entryHash?: string;
}

export class AuditLogger {
  private readonly buffer: AuditLogEntry[] = [];
  private readonly maxBufferSize: number;
  private readonly logFilePath?: string;
  private readonly redactor: PiiRedactor;
  private siemStreamer?: SiemTelemetryStreamer;
  private hmacLedger?: HmacAuditLedger;
  private lastHash = "0000000000000000000000000000000000000000000000000000000000000000";

  constructor(
    logFilePath?: string,
    maxBufferSize = 500,
    redactor?: PiiRedactor,
    siemStreamer?: SiemTelemetryStreamer,
    hmacLedger?: HmacAuditLedger,
  ) {
    this.logFilePath = logFilePath;
    this.maxBufferSize = maxBufferSize;
    this.redactor = redactor || new PiiRedactor();
    this.siemStreamer = siemStreamer;
    this.hmacLedger = hmacLedger;
  }

  public enableHmacLedger(options?: HmacLedgerOptions): HmacAuditLedger {
    this.hmacLedger = new HmacAuditLedger({
      logFilePath: this.logFilePath ? `${this.logFilePath}.hmac.jsonl` : undefined,
      redactor: this.redactor,
      ...options,
    });
    return this.hmacLedger;
  }

  public getHmacLedger(): HmacAuditLedger | undefined {
    return this.hmacLedger;
  }

  public setSiemStreamer(streamer: SiemTelemetryStreamer): void {
    this.siemStreamer = streamer;
  }

  public getSiemStreamer(): SiemTelemetryStreamer | undefined {
    return this.siemStreamer;
  }

  public getChainHeadHash(): string {
    return this.lastHash;
  }

  public async log(entry: AuditLogEntry): Promise<void> {
    const previousHash = this.lastHash;
    const sanitizedSql = this.redactor.redactSql(entry.sql);
    const sanitizedViolations = entry.violations?.map((v) => this.redactor.redactErrorMessage(v));

    const hashPayload = `${previousHash}|${entry.auditId}|${entry.timestamp}|${sanitizedSql}|${entry.status}|${entry.riskScore}`;
    const entryHash = crypto.createHash("sha256").update(hashPayload).digest("hex");
    this.lastHash = entryHash;

    const sanitizedEntry: AuditLogEntry = {
      ...entry,
      sql: sanitizedSql,
      violations: sanitizedViolations,
      piiRedacted: true,
      previousHash,
      entryHash,
    };

    this.buffer.unshift(sanitizedEntry);
    if (this.buffer.length > this.maxBufferSize) {
      this.buffer.pop();
    }

    if (this.logFilePath) {
      try {
        const line = `${JSON.stringify(sanitizedEntry)}\n`;
        await fs.mkdir(path.dirname(this.logFilePath), { recursive: true });
        await fs.appendFile(this.logFilePath, line, "utf8");
      } catch {
        // Non-fatal if file write fails in restricted environments
      }
    }

    // Append to cryptographically sealed HMAC ledger if configured
    if (this.hmacLedger) {
      try {
        await this.hmacLedger.append({
          auditId: entry.auditId,
          timestamp: entry.timestamp,
          operation: entry.operation,
          status: entry.status,
          riskLevel: entry.riskLevel,
          riskScore: entry.riskScore,
          sql: sanitizedSql,
          violations: sanitizedViolations,
        });
      } catch {
        // Non-fatal if HMAC append fails
      }
    }

    // Stream telemetry to remote SIEM / webhook if configured
    if (this.siemStreamer) {
      try {
        await this.siemStreamer.enqueue(sanitizedEntry);
      } catch {
        // Non-fatal if SIEM enqueue fails
      }
    }
  }

  /**
   * Verifies the cryptographic tamper-evident hash chain across all stored log entries.
   * Returns verification status, entry count, and chain boundaries.
   */
  public verifyCryptographicChain(): {
    valid: boolean;
    totalVerified: number;
    headHash: string;
    tailHash: string;
    brokenAtIndex?: number;
  } {
    if (this.buffer.length === 0) {
      return {
        valid: true,
        totalVerified: 0,
        headHash: this.lastHash,
        tailHash: this.lastHash,
      };
    }

    // Buffer is stored in reverse chronological order (newest first)
    const chronological = [...this.buffer].reverse();
    let currentExpectedPrev = "0000000000000000000000000000000000000000000000000000000000000000";

    for (let i = 0; i < chronological.length; i++) {
      const entry = chronological[i];
      if (entry.previousHash !== currentExpectedPrev) {
        return {
          valid: false,
          totalVerified: i,
          headHash: chronological[chronological.length - 1].entryHash || "",
          tailHash: chronological[0].previousHash || "",
          brokenAtIndex: i,
        };
      }

      const hashPayload = `${entry.previousHash}|${entry.auditId}|${entry.timestamp}|${entry.sql}|${entry.status}|${entry.riskScore}`;
      const recomputedHash = crypto.createHash("sha256").update(hashPayload).digest("hex");

      if (entry.entryHash !== recomputedHash) {
        return {
          valid: false,
          totalVerified: i,
          headHash: chronological[chronological.length - 1].entryHash || "",
          tailHash: chronological[0].previousHash || "",
          brokenAtIndex: i,
        };
      }

      currentExpectedPrev = entry.entryHash;
    }

    return {
      valid: true,
      totalVerified: chronological.length,
      headHash: chronological[chronological.length - 1].entryHash || "",
      tailHash: chronological[0].previousHash || "",
    };
  }

  public getEntries(
    options: {
      limit?: number;
      status?: string;
      minRiskScore?: number;
    } = {},
  ): AuditLogEntry[] {
    const limit = options.limit || 50;
    let filtered = this.buffer;

    if (options.status) {
      const s = options.status.toUpperCase();
      filtered = filtered.filter((e) => e.status.toUpperCase() === s);
    }

    if (options.minRiskScore !== undefined) {
      filtered = filtered.filter((e) => e.riskScore >= options.minRiskScore!);
    }

    return filtered.slice(0, limit).map((e) => ({
      ...e,
      sql: this.redactor.redactSql(e.sql),
      violations: e.violations?.map((v) => this.redactor.redactErrorMessage(v)),
    }));
  }

  public clear(): void {
    this.buffer.length = 0;
  }
}
