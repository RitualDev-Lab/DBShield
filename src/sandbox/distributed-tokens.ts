import { createHmac, randomBytes, randomUUID } from "node:crypto";
import type { DistributedStoreOperation } from "../types/index.js";

export interface DistributedCommitTokenPayload {
  tokenId: string;
  operationsHash: string;
  operations: DistributedStoreOperation[];
  totalAffectedEntities: number;
  issuedAt: number;
  expiresAt: number;
}

export interface DistributedVerificationResult {
  valid: boolean;
  error?: "TOKEN_NOT_FOUND" | "TOKEN_EXPIRED" | "TOKEN_ALREADY_USED" | "OPERATIONS_TAMPERED";
  payload?: DistributedCommitTokenPayload;
}

export class DistributedCommitTokenManager {
  private readonly secret: string;
  private readonly ttlMs: number;
  private readonly activeTokens: Map<string, DistributedCommitTokenPayload> = new Map();
  private readonly consumedTokens: Map<string, number> = new Map();

  constructor(secret?: string, ttlSeconds = 60) {
    this.secret = secret || randomBytes(32).toString("hex");
    this.ttlMs = ttlSeconds * 1000;
  }

  /**
   * Deterministically hash a multi-store array of operations.
   */
  public static hashOperations(operations: DistributedStoreOperation[]): string {
    const serialized = operations
      .map((op) => {
        const paramsStr = JSON.stringify(op.paramsOrValue ?? null);
        return `${op.storeId}:${op.storeType}:${op.action}:${op.queryOrKey.trim()}:${paramsStr}`;
      })
      .join("|");

    return createHmac("sha256", "dbshield-distributed-salt").update(serialized).digest("hex");
  }

  public issueToken(
    operations: DistributedStoreOperation[],
    totalAffectedEntities: number,
  ): {
    token: string;
    expiresAt: string;
    expiresInSeconds: number;
  } {
    this.cleanupExpired();

    const tokenId = `dbs_dist_${randomUUID().replace(/-/g, "")}`;
    const now = Date.now();
    const expiresAtMs = now + this.ttlMs;
    const operationsHash = DistributedCommitTokenManager.hashOperations(operations);

    const payload: DistributedCommitTokenPayload = {
      tokenId,
      operationsHash,
      operations: JSON.parse(JSON.stringify(operations)),
      totalAffectedEntities,
      issuedAt: now,
      expiresAt: expiresAtMs,
    };

    this.activeTokens.set(tokenId, payload);

    return {
      token: tokenId,
      expiresAt: new Date(expiresAtMs).toISOString(),
      expiresInSeconds: Math.round(this.ttlMs / 1000),
    };
  }

  public verifyAndConsume(
    token: string,
    operations: DistributedStoreOperation[],
  ): DistributedVerificationResult {
    this.cleanupExpired();

    if (this.consumedTokens.has(token)) {
      return { valid: false, error: "TOKEN_ALREADY_USED" };
    }

    const payload = this.activeTokens.get(token);
    if (!payload) {
      return { valid: false, error: "TOKEN_NOT_FOUND" };
    }

    if (Date.now() > payload.expiresAt) {
      this.activeTokens.delete(token);
      return { valid: false, error: "TOKEN_EXPIRED" };
    }

    // Verify operations tamper resistance
    const currentHash = DistributedCommitTokenManager.hashOperations(operations);
    if (currentHash !== payload.operationsHash) {
      return { valid: false, error: "OPERATIONS_TAMPERED" };
    }

    // Atomically consume token
    this.activeTokens.delete(token);
    this.consumedTokens.set(token, payload.expiresAt);

    return { valid: true, payload };
  }

  private cleanupExpired(): void {
    const now = Date.now();
    for (const [id, payload] of this.activeTokens.entries()) {
      if (now > payload.expiresAt) {
        this.activeTokens.delete(id);
      }
    }
    for (const [id, exp] of this.consumedTokens.entries()) {
      if (now > exp) {
        this.consumedTokens.delete(id);
      }
    }
  }

  public getActiveCount(): number {
    return this.activeTokens.size;
  }
}
