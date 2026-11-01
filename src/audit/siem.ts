import type { SiemTelemetryConfig } from "../types/index.js";
import type { AuditLogEntry } from "./index.js";

export interface SiemStreamStats {
  queuedCount: number;
  sentCount: number;
  failedCount: number;
  lastFlushTime: string | null;
  lastError: string | null;
}

export class SiemTelemetryStreamer {
  private readonly config: SiemTelemetryConfig;
  private readonly queue: AuditLogEntry[] = [];
  private flushTimer: NodeJS.Timeout | null = null;
  private isFlushing = false;
  private stats: SiemStreamStats = {
    queuedCount: 0,
    sentCount: 0,
    failedCount: 0,
    lastFlushTime: null,
    lastError: null,
  };

  constructor(config: SiemTelemetryConfig) {
    this.config = {
      enabled: config.enabled ?? false,
      endpoint: config.endpoint,
      format: config.format || "webhook",
      authToken: config.authToken,
      batchSize: config.batchSize ?? 10,
      flushIntervalMs: config.flushIntervalMs ?? 5000,
      streamBlockedOnly: config.streamBlockedOnly ?? false,
    };

    if (this.config.enabled && this.config.endpoint && (this.config.flushIntervalMs ?? 0) > 0) {
      this.start();
    }
  }

  public start(): void {
    if (this.flushTimer) return;
    const interval = this.config.flushIntervalMs || 5000;
    this.flushTimer = setInterval(() => {
      this.flush().catch(() => {});
    }, interval);
    this.flushTimer.unref();
  }

  public stop(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
  }

  public getStats(): SiemStreamStats {
    return {
      ...this.stats,
      queuedCount: this.queue.length,
    };
  }

  public async enqueue(entry: AuditLogEntry): Promise<void> {
    if (!this.config.enabled || !this.config.endpoint) {
      return;
    }

    if (this.config.streamBlockedOnly && entry.status !== "BLOCKED") {
      return;
    }

    this.queue.push(entry);
    this.stats.queuedCount = this.queue.length;

    const batchLimit = this.config.batchSize || 10;
    if (this.queue.length >= batchLimit) {
      await this.flush();
    }
  }

  public async flush(): Promise<{ success: boolean; sentCount: number; error?: string }> {
    if (
      !this.config.enabled ||
      !this.config.endpoint ||
      this.queue.length === 0 ||
      this.isFlushing
    ) {
      return { success: true, sentCount: 0 };
    }

    this.isFlushing = true;
    const batch = this.queue.splice(0, this.config.batchSize || 10);

    try {
      const payload = this.formatPayload(batch);
      const headers = this.buildHeaders();

      const response = await fetch(this.config.endpoint, {
        method: "POST",
        headers,
        body: payload,
      });

      if (!response.ok) {
        throw new Error(
          `SIEM destination responded with status ${response.status} ${response.statusText}`,
        );
      }

      this.stats.sentCount += batch.length;
      this.stats.lastFlushTime = new Date().toISOString();
      this.stats.lastError = null;
      return { success: true, sentCount: batch.length };
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      this.stats.failedCount += batch.length;
      this.stats.lastError = errorMessage;
      // Re-queue items that failed (at most 100 to prevent unbounded memory growth)
      if (this.queue.length < 100) {
        this.queue.unshift(...batch);
      }
      return { success: false, sentCount: 0, error: errorMessage };
    } finally {
      this.isFlushing = false;
    }
  }

  private buildHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "User-Agent": "DBShield-SIEM-Telemetry/1.0",
    };

    if (this.config.authToken) {
      if (this.config.format === "datadog") {
        headers["DD-API-KEY"] = this.config.authToken;
      } else {
        headers.Authorization = `Bearer ${this.config.authToken}`;
      }
    }

    return headers;
  }

  private formatPayload(entries: AuditLogEntry[]): string {
    switch (this.config.format) {
      case "datadog":
        return JSON.stringify(
          entries.map((entry) => ({
            ddsource: "dbshield",
            service: "dbshield-guardrail",
            ddtags: `status:${entry.status},risk:${entry.riskLevel},operation:${entry.operation}`,
            message: JSON.stringify(entry),
          })),
        );

      case "elasticsearch":
        // Standard bulk or simple array representation
        return JSON.stringify({
          index: "dbshield-audit-events",
          events: entries.map((entry) => ({
            "@timestamp": entry.timestamp,
            ...entry,
          })),
        });

      case "agentshield":
        return JSON.stringify({
          source: "dbshield",
          kind: "audit_stream",
          batchSize: entries.length,
          generatedAt: new Date().toISOString(),
          events: entries,
        });
      default:
        return JSON.stringify({
          source: "dbshield",
          event: "audit_batch",
          count: entries.length,
          timestamp: new Date().toISOString(),
          entries,
        });
    }
  }
}
