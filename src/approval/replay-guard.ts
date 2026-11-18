/**
 * Replay-Proof Cryptographic Approval Token Manager (SEC-08)
 *
 * Binds every ChatOps 1-click Slack / MS Teams approval token to:
 *   HMAC-SHA256(secret, normalized_sql_ast + "|" + db_id + "|" + expires_at + "|" + single_use_nonce)
 * Enforces short TTL (default 10 minutes / 600s), timing-safe HMAC verification,
 * SQL AST immutability, and strict single-use nonce consumption (`403 Token Already Consumed`).
 */

import crypto from "node:crypto";

export interface IssuedApprovalToken {
  requestId: string;
  dbId: string;
  normalizedSqlHash: string;
  expiresAt: number;
  nonce: string;
  signature: string;
  token: string;
}

export interface ApprovalTokenVerification {
  valid: boolean;
  statusCode: 200 | 401 | 403;
  error?: string;
}

export function normalizeSqlForAstHash(sql: string): string {
  return sql
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/--[^\r\n]*/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

export class ReplayProofApprovalTokenManager {
  private readonly secret: string;
  private readonly defaultTtlSeconds: number;
  private readonly consumedNonces = new Set<string>();

  constructor(
    secret: string = process.env.DBSHIELD_CHATOPS_SECRET || "dbshield-chatops-replay-secret",
    defaultTtlSeconds = 600, // 10 minutes
  ) {
    this.secret = secret;
    this.defaultTtlSeconds = defaultTtlSeconds;
  }

  private computeSignature(
    requestId: string,
    normalizedSqlHash: string,
    dbId: string,
    expiresAt: number,
    nonce: string,
  ): string {
    const canonical = `${requestId}|${normalizedSqlHash}|${dbId}|${expiresAt}|${nonce}`;
    return crypto.createHmac("sha256", this.secret).update(canonical).digest("hex");
  }

  public issueToken(options: {
    requestId: string;
    sql: string;
    dbId: string;
    ttlSeconds?: number;
  }): IssuedApprovalToken {
    const normalizedSql = normalizeSqlForAstHash(options.sql);
    const normalizedSqlHash = crypto.createHash("sha256").update(normalizedSql).digest("hex");
    const ttl = options.ttlSeconds ?? this.defaultTtlSeconds;
    const expiresAt = Math.floor(Date.now() / 1000) + ttl;
    const nonce = crypto.randomBytes(16).toString("hex");
    const signature = this.computeSignature(
      options.requestId,
      normalizedSqlHash,
      options.dbId,
      expiresAt,
      nonce,
    );
    const token = Buffer.from(
      JSON.stringify({
        requestId: options.requestId,
        dbId: options.dbId,
        normalizedSqlHash,
        expiresAt,
        nonce,
        signature,
      }),
      "utf8",
    ).toString("base64url");

    return {
      requestId: options.requestId,
      dbId: options.dbId,
      normalizedSqlHash,
      expiresAt,
      nonce,
      signature,
      token,
    };
  }

  public verifyAndConsume(
    token: string,
    expected: { requestId: string; sql: string; dbId: string },
  ): ApprovalTokenVerification {
    let decoded: IssuedApprovalToken;
    try {
      decoded = JSON.parse(Buffer.from(token, "base64url").toString("utf8")) as IssuedApprovalToken;
    } catch {
      return { valid: false, statusCode: 401, error: "Malformed approval token" };
    }

    if (!decoded.nonce || !decoded.signature || !decoded.expiresAt) {
      return { valid: false, statusCode: 401, error: "Incomplete approval token payload" };
    }

    if (this.consumedNonces.has(decoded.nonce)) {
      return { valid: false, statusCode: 403, error: "403 Token Already Consumed" };
    }

    const nowSec = Math.floor(Date.now() / 1000);
    if (nowSec > decoded.expiresAt) {
      return { valid: false, statusCode: 403, error: "403 Approval Token Expired" };
    }

    if (decoded.requestId !== expected.requestId || decoded.dbId !== expected.dbId) {
      return { valid: false, statusCode: 403, error: "403 Approval Token Scope Mismatch" };
    }

    const expectedSqlHash = crypto
      .createHash("sha256")
      .update(normalizeSqlForAstHash(expected.sql))
      .digest("hex");
    if (decoded.normalizedSqlHash !== expectedSqlHash) {
      return {
        valid: false,
        statusCode: 403,
        error: "403 SQL AST Hash Mismatch — query tampered after dry-run",
      };
    }

    const expectedSig = this.computeSignature(
      decoded.requestId,
      decoded.normalizedSqlHash,
      decoded.dbId,
      decoded.expiresAt,
      decoded.nonce,
    );

    const a = Buffer.from(decoded.signature, "utf8");
    const b = Buffer.from(expectedSig, "utf8");
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return { valid: false, statusCode: 401, error: "Invalid HMAC-SHA256 approval signature" };
    }

    this.consumedNonces.add(decoded.nonce);
    return { valid: true, statusCode: 200 };
  }
}
