import { createHmac, randomBytes, randomUUID } from "node:crypto";

export interface CommitTokenPayload {
  tokenId: string;
  sqlHash: string;
  affectedRows: number;
  issuedAt: number;
  expiresAt: number;
  targetTables: string[];
}

export interface VerificationResult {
  valid: boolean;
  error?: "TOKEN_NOT_FOUND" | "TOKEN_EXPIRED" | "TOKEN_ALREADY_USED" | "QUERY_TAMPERED";
  payload?: CommitTokenPayload;
}

export class CommitTokenManager {
  private readonly secret: string;
  private readonly ttlMs: number;
  private readonly activeTokens = new Map<string, CommitTokenPayload>();
  private readonly consumedTokens = new Map<string, number>(); // tokenId -> expiresAt

  constructor(secret?: string, ttlSeconds = 60) {
    this.secret = secret || randomBytes(32).toString("hex");
    this.ttlMs = ttlSeconds * 1000;
  }

  public static hashQuery(sql: string): string {
    return createHmac("sha256", "dbshield-sql-salt")
      .update(sql.trim().replace(/\s+/g, " "))
      .digest("hex");
  }

  public issueToken(
    sql: string,
    affectedRows: number,
    targetTables: string[],
  ): {
    token: string;
    expiresAt: string;
    expiresInSeconds: number;
  } {
    this.cleanupExpired();

    const tokenId = `dbs_${randomUUID().replace(/-/g, "")}`;
    const now = Date.now();
    const expiresAtMs = now + this.ttlMs;
    const sqlHash = CommitTokenManager.hashQuery(sql);

    const payload: CommitTokenPayload = {
      tokenId,
      sqlHash,
      affectedRows,
      issuedAt: now,
      expiresAt: expiresAtMs,
      targetTables,
    };

    const signature = this.signPayload(payload);
    const token = `${tokenId}.${signature}`;

    this.activeTokens.set(tokenId, payload);

    return {
      token,
      expiresAt: new Date(expiresAtMs).toISOString(),
      expiresInSeconds: Math.round(this.ttlMs / 1000),
    };
  }

  public verifyAndConsume(token: string, sql: string): VerificationResult {
    const parts = token.split(".");
    if (parts.length !== 2) {
      return { valid: false, error: "TOKEN_NOT_FOUND" };
    }

    const [tokenId, signature] = parts;

    // Check if token was already consumed
    if (this.consumedTokens.has(tokenId)) {
      return { valid: false, error: "TOKEN_ALREADY_USED" };
    }

    const payload = this.activeTokens.get(tokenId);

    if (!payload) {
      return { valid: false, error: "TOKEN_NOT_FOUND" };
    }

    // Check expiration before signature verification
    if (Date.now() > payload.expiresAt) {
      return { valid: false, error: "TOKEN_EXPIRED" };
    }

    // Verify signature
    const expectedSig = this.signPayload(payload);
    if (signature !== expectedSig) {
      return { valid: false, error: "TOKEN_NOT_FOUND" };
    }

    // Verify SQL query hash strictly matches (tamper-proofing)
    const currentSqlHash = CommitTokenManager.hashQuery(sql);
    if (currentSqlHash !== payload.sqlHash) {
      return { valid: false, error: "QUERY_TAMPERED" };
    }

    // Mark token as consumed immediately
    this.activeTokens.delete(tokenId);
    this.consumedTokens.set(tokenId, payload.expiresAt);

    return {
      valid: true,
      payload,
    };
  }

  private signPayload(payload: CommitTokenPayload): string {
    const data = `${payload.tokenId}:${payload.sqlHash}:${payload.affectedRows}:${payload.expiresAt}`;
    return createHmac("sha256", this.secret).update(data).digest("hex").slice(0, 32);
  }

  private cleanupExpired(): void {
    const now = Date.now();
    // Keep a 5-minute tombstone grace period so expired or used tokens return clear errors
    const tombstoneLimit = 5 * 60 * 1000;

    for (const [id, payload] of this.activeTokens.entries()) {
      if (now > payload.expiresAt + tombstoneLimit) {
        this.activeTokens.delete(id);
      }
    }

    for (const [id, expiresAt] of this.consumedTokens.entries()) {
      if (now > expiresAt + tombstoneLimit) {
        this.consumedTokens.delete(id);
      }
    }
  }
}
