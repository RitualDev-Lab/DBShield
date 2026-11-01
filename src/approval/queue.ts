import { randomUUID } from "node:crypto";
import type { ApprovalRequest, RiskLevel, SqlOperationType } from "../types/index.js";

type ApprovalListener = (request: ApprovalRequest) => void;

export class ApprovalQueue {
  private requests: Map<string, ApprovalRequest> = new Map();
  private listeners: Set<ApprovalListener> = new Set();
  private resolvers: Map<string, (decision: "APPROVED" | "REJECTED") => void> = new Map();

  /**
   * Enqueue a new mutation query for live human review and approval.
   */
  public enqueue(data: {
    sql: string;
    operation: SqlOperationType;
    riskLevel: RiskLevel;
    riskScore: number;
    targetTables?: string[];
    piiRedacted?: boolean;
    agentId?: string;
    clientIp?: string;
  }): ApprovalRequest {
    const id = `appr_${randomUUID().replace(/-/g, "").slice(0, 12)}`;
    const request: ApprovalRequest = {
      id,
      timestamp: new Date().toISOString(),
      agentId: data.agentId || "agent-runtime",
      clientIp: data.clientIp || "127.0.0.1",
      sql: data.sql,
      operation: data.operation,
      riskLevel: data.riskLevel,
      riskScore: data.riskScore,
      targetTables: data.targetTables || [],
      piiRedacted: data.piiRedacted ?? true,
      status: "PENDING",
    };

    this.requests.set(id, request);
    this.notifyListeners(request);
    return request;
  }

  /**
   * Approve a pending mutation query.
   */
  public approve(id: string, reviewer = "Developer (Dashboard)"): boolean {
    const req = this.requests.get(id);
    if (!req || req.status !== "PENDING") {
      return false;
    }

    req.status = "APPROVED";
    req.decidedAt = new Date().toISOString();
    req.decidedBy = reviewer;

    const resolver = this.resolvers.get(id);
    if (resolver) {
      resolver("APPROVED");
      this.resolvers.delete(id);
    }

    this.notifyListeners(req);
    return true;
  }

  /**
   * Reject a pending mutation query.
   */
  public reject(id: string, reviewer = "Developer (Dashboard)", reason?: string): boolean {
    const req = this.requests.get(id);
    if (!req || req.status !== "PENDING") {
      return false;
    }

    req.status = "REJECTED";
    req.decidedAt = new Date().toISOString();
    req.decidedBy = reviewer;
    req.reason = reason || "Rejected by developer in live approval feed";

    const resolver = this.resolvers.get(id);
    if (resolver) {
      resolver("REJECTED");
      this.resolvers.delete(id);
    }

    this.notifyListeners(req);
    return true;
  }

  public get(id: string): ApprovalRequest | undefined {
    return this.requests.get(id);
  }

  public getPending(): ApprovalRequest[] {
    return Array.from(this.requests.values()).filter((r) => r.status === "PENDING");
  }

  public getAll(limit = 100): ApprovalRequest[] {
    return Array.from(this.requests.values())
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, limit);
  }

  /**
   * Wait asynchronously for a human decision (or timeout).
   */
  public waitForDecision(
    id: string,
    timeoutMs = 30000,
  ): Promise<"APPROVED" | "REJECTED" | "TIMEOUT"> {
    const req = this.requests.get(id);
    if (!req) return Promise.resolve("REJECTED");
    if (req.status === "APPROVED") return Promise.resolve("APPROVED");
    if (req.status === "REJECTED") return Promise.resolve("REJECTED");

    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.resolvers.delete(id);
        if (req.status === "PENDING") {
          req.status = "REJECTED";
          req.decidedAt = new Date().toISOString();
          req.decidedBy = "System Timeout";
          req.reason = `Approval timed out after ${timeoutMs}ms`;
          this.notifyListeners(req);
        }
        resolve("TIMEOUT");
      }, timeoutMs);

      this.resolvers.set(id, (decision) => {
        clearTimeout(timer);
        resolve(decision);
      });
    });
  }

  public subscribe(listener: ApprovalListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private notifyListeners(req: ApprovalRequest): void {
    for (const listener of this.listeners) {
      try {
        listener(req);
      } catch {
        // Safe dispatch
      }
    }
  }

  public clear(): void {
    this.requests.clear();
    this.resolvers.clear();
  }
}
