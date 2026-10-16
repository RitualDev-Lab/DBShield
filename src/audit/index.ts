import fs from "node:fs/promises";
import path from "node:path";
import { PiiRedactor } from "../pii/redactor.js";
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
  private readonly redactor: PiiRedactor;

  constructor(logFilePath?: string, maxBufferSize = 500, redactor?: PiiRedactor) {
    this.logFilePath = logFilePath;
    this.maxBufferSize = maxBufferSize;
    this.redactor = redactor || new PiiRedactor();
  }

  public async log(entry: AuditLogEntry): Promise<void> {
    const sanitizedEntry: AuditLogEntry = {
      ...entry,
      sql: this.redactor.redactSql(entry.sql),
      violations: entry.violations?.map((v) => this.redactor.redactErrorMessage(v)),
      piiRedacted: true,
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
