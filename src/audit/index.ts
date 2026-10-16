import fs from "node:fs/promises";
import path from "node:path";
import type { RiskLevel, SqlOperationType } from "../types/index.js";

export interface AuditLogEntry {
  auditId: string;
  timestamp: string;
  sql: string;
  operation: SqlOperationType;
  status: "SUCCESS" | "BLOCKED" | "DRY_RUN_APPROVED" | "DRY_RUN_REJECTED" | "COMMITTED" | "ERROR";
  riskLevel: RiskLevel;
  riskScore: number;
  rowCount?: number;
  executionTimeMs?: number;
  violations?: string[];
  piiRedacted?: boolean;
}

export class AuditLogger {
  private readonly buffer: AuditLogEntry[] = [];
  private readonly maxBufferSize: number;
  private readonly logFilePath?: string;

  constructor(logFilePath?: string, maxBufferSize = 500) {
    this.logFilePath = logFilePath;
    this.maxBufferSize = maxBufferSize;
  }

  public async log(entry: AuditLogEntry): Promise<void> {
    this.buffer.unshift(entry);
    if (this.buffer.length > this.maxBufferSize) {
      this.buffer.pop();
    }

    if (this.logFilePath) {
      try {
        const line = `${JSON.stringify(entry)}\n`;
        await fs.mkdir(path.dirname(this.logFilePath), { recursive: true });
        await fs.appendFile(this.logFilePath, line, "utf8");
      } catch {
        // Non-fatal if file write fails in restricted environments
      }
    }
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

    return filtered.slice(0, limit);
  }

  public clear(): void {
    this.buffer.length = 0;
  }
}
