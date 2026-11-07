import assert from "node:assert";
import test from "node:test";
import { ApprovalQueue } from "../src/approval/queue.js";
import { AuditLogger, SiemTelemetryStreamer } from "../src/audit/index.js";
import { SsoAuthenticator } from "../src/auth/sso.js";
import { ComplianceReporter } from "../src/compliance/reporter.js";
import { DashboardServer } from "../src/dashboard/server.js";
import type { DBShieldConfig, SsoConfig } from "../src/types/index.js";

const mockConfig: DBShieldConfig = {
  dialect: "sqlite",
  storagePath: ":memory:",
  safetyTier: "BALANCED",
  maxRowsPerMutation: 50,
  maxRowsPerRead: 500,
  allowDestructiveDDL: false,
  enablePiiMasking: true,
  enableCostGate: true,
  maxEstimatedCost: 10000,
  maxEstimatedRows: 5000,
  blockUnindexedSeqScan: false,
  statementTimeoutMs: 5000,
  enableMigrationGate: true,
  enforceConcurrentIndexCreation: false,
  disallowBreakingRenames: true,
  enableSemanticGuard: true,
  requireIntentForSensitiveColumns: false,
};

test("SSO Authenticator - Generates IdP Authorization URLs", () => {
  const providers = ["okta", "azure-ad", "google", "ping-identity", "saml"] as const;

  for (const provider of providers) {
    const sso = new SsoAuthenticator({
      enabled: true,
      provider,
      clientId: "client_123",
      redirectUri: "http://localhost:3100/auth/callback",
      issuer: "https://auth.enterprise.com",
    });

    const authUrl = sso.generateAuthUrl("state_abc");
    assert.ok(authUrl.length > 20);

    if (provider === "google") {
      const parsedUrl = new URL(authUrl);
      assert.strictEqual(parsedUrl.hostname, "accounts.google.com");
    } else if (provider === "azure-ad") {
      assert.ok(authUrl.includes("oauth2/v2.0/authorize"));
    } else if (provider === "okta") {
      assert.ok(authUrl.includes("auth.enterprise.com/v1/authorize"));
    } else if (provider === "saml") {
      assert.ok(authUrl.includes("SAMLRequest"));
    }
  }
});

test("SSO Authenticator - Session Token Generation and Cryptographic Verification", () => {
  const sso = new SsoAuthenticator({
    enabled: true,
    provider: "okta",
    jwtSecret: "super-secret-enterprise-key-minimum-32chars!",
  });

  const nowSec = Math.floor(Date.now() / 1000);
  const session = sso.createSessionToken({
    id: "usr_42",
    email: "alice@ritual.dev",
    name: "Alice Engineer",
    roles: ["admin", "approver"],
    provider: "okta",
    issuedAt: nowSec,
    expiresAt: nowSec + 3600,
  });

  assert.ok(typeof session === "string");
  assert.strictEqual(session.split(".").length, 3);

  const verification = sso.verifySessionToken(session);
  assert.strictEqual(verification.valid, true);
  assert.strictEqual(verification.user?.email, "alice@ritual.dev");
  assert.deepStrictEqual(verification.user?.roles, ["admin", "approver"]);
});

test("SSO Authenticator - Enforces Email Domain Whitelist", () => {
  const sso = new SsoAuthenticator({
    enabled: true,
    provider: "google",
    allowedDomains: ["ritual.dev", "enterprise.com"],
  });

  const validUser = sso.createSessionToken({
    id: "usr_1",
    email: "dev@ritual.dev",
    roles: ["developer"],
    provider: "google",
    issuedAt: Math.floor(Date.now() / 1000),
    expiresAt: Math.floor(Date.now() / 1000) + 3600,
  });
  assert.strictEqual(sso.verifySessionToken(validUser).valid, true);

  const invalidUser = sso.createSessionToken({
    id: "usr_2",
    email: "hacker@unauthorized-domain.com",
    roles: ["developer"],
    provider: "google",
    issuedAt: Math.floor(Date.now() / 1000),
    expiresAt: Math.floor(Date.now() / 1000) + 3600,
  });
  const invalidResult = sso.verifySessionToken(invalidUser);
  assert.strictEqual(invalidResult.valid, false);
  assert.strictEqual(invalidResult.errorCode, "DOMAIN_NOT_ALLOWED");
});

test("SSO Authenticator - Enforces RBAC Role Restrictions", () => {
  const sso = new SsoAuthenticator({
    enabled: true,
    provider: "azure-ad",
    allowedRoles: ["dba", "security-lead"],
  });

  const authorizedToken = sso.createSessionToken({
    id: "usr_dba",
    email: "dba@ritual.dev",
    roles: ["dba"],
    provider: "azure-ad",
    issuedAt: Math.floor(Date.now() / 1000),
    expiresAt: Math.floor(Date.now() / 1000) + 3600,
  });
  assert.strictEqual(sso.verifySessionToken(authorizedToken).valid, true);

  const unauthorizedToken = sso.createSessionToken({
    id: "usr_viewer",
    email: "viewer@ritual.dev",
    roles: ["viewer"],
    provider: "azure-ad",
    issuedAt: Math.floor(Date.now() / 1000),
    expiresAt: Math.floor(Date.now() / 1000) + 3600,
  });
  const unauthResult = sso.verifySessionToken(unauthorizedToken);
  assert.strictEqual(unauthResult.valid, false);
  assert.strictEqual(unauthResult.errorCode, "INSUFFICIENT_ROLE");
});

test("AuditLogger - Tamper-Evident SHA-256 Cryptographic Hash Chain", async () => {
  const logger = new AuditLogger();

  await logger.log({
    auditId: "aud_1",
    timestamp: new Date().toISOString(),
    sql: "SELECT * FROM users WHERE id = 1;",
    operation: "SELECT",
    status: "SUCCESS",
    riskLevel: "SAFE",
    riskScore: 0,
  });

  await logger.log({
    auditId: "aud_2",
    timestamp: new Date().toISOString(),
    sql: "UPDATE accounts SET balance = 500 WHERE id = 2;",
    operation: "UPDATE",
    status: "DRY_RUN_APPROVED",
    riskLevel: "LOW",
    riskScore: 15,
  });

  await logger.log({
    auditId: "aud_3",
    timestamp: new Date().toISOString(),
    sql: "DROP TABLE users;",
    operation: "DDL",
    status: "BLOCKED",
    riskLevel: "CRITICAL",
    riskScore: 100,
  });

  // Verify chain integrity
  const chainVerification = logger.verifyCryptographicChain();
  assert.strictEqual(chainVerification.valid, true);
  assert.strictEqual(chainVerification.totalVerified, 3);
  assert.ok(chainVerification.headHash.length === 64);
});

test("Compliance Reporter - SOC 2 Audit Report Generation (JSON & HTML)", async () => {
  const logger = new AuditLogger();
  await logger.log({
    auditId: "aud_soc_1",
    timestamp: new Date().toISOString(),
    sql: "SELECT * FROM sensitive_vault;",
    operation: "SELECT",
    status: "SUCCESS",
    riskLevel: "SAFE",
    riskScore: 5,
    rowCount: 10,
  });

  const reporter = new ComplianceReporter(mockConfig, logger);
  const result = await reporter.generateReport({
    framework: "soc2",
    format: "json",
    companyName: "Acme Fintech Corp",
    environment: "production",
  });

  assert.strictEqual(result.framework, "soc2");
  assert.ok(result.reportId.startsWith("rep_soc2_"));
  assert.ok(result.score >= 80);
  assert.ok(result.auditorSignature.length === 64);
  assert.ok(result.proofs.some((p) => p.controlId === "CC6.6"));
  assert.ok(result.proofs.some((p) => p.controlId === "CC7.2"));
  assert.ok(result.proofs.some((p) => p.controlId === "P1-P8"));

  // Verify HTML output
  const htmlResult = await reporter.generateReport({
    framework: "soc2",
    format: "html",
  });
  assert.ok(htmlResult.rawReport?.includes("<!DOCTYPE html>"));
  assert.ok(htmlResult.rawReport?.includes("Trust Services Criteria"));
  assert.ok(htmlResult.rawReport?.includes("Immutable Cryptographic Log Proof"));
});

test("Compliance Reporter - PDF Audit Trail Document Generation", async () => {
  const logger = new AuditLogger();
  const reporter = new ComplianceReporter(mockConfig, logger);
  const pdfResult = await reporter.generateReport({
    framework: "iso27001",
    format: "pdf",
  });

  assert.strictEqual(pdfResult.framework, "iso27001");
  assert.ok(pdfResult.rawReport?.startsWith("%PDF-1.4"));
  assert.ok(pdfResult.rawReport?.includes("%%EOF"));
  assert.ok(pdfResult.rawReport?.includes("ISO27001"));
});

test("DashboardServer - Protects Endpoints Behind Enterprise SSO", async () => {
  const ssoConfig: SsoConfig = {
    enabled: true,
    provider: "okta",
    allowedDomains: ["ritual.dev"],
    jwtSecret: "test-dashboard-sso-secret-32-chars-key!",
  };

  const queue = new ApprovalQueue();
  const dashboard = new DashboardServer({ ...mockConfig, sso: ssoConfig }, queue);
  await dashboard.start(0);
  const port = dashboard.getPort();

  try {
    // 1. Unauthenticated request to protected endpoint fails with 401
    const unauthRes = await fetch(`http://127.0.0.1:${port}/api/approvals`);
    assert.strictEqual(unauthRes.status, 401);
    const unauthBody = (await unauthRes.json()) as any;
    assert.ok(unauthBody.error.includes("SSO"));

    // 2. Authenticated request with valid session token succeeds with 200
    const authenticator = dashboard.getSsoAuthenticator()!;
    const devSession = authenticator.createDevSession({ email: "dba@ritual.dev" });

    const authRes = await fetch(`http://127.0.0.1:${port}/api/approvals`, {
      headers: {
        Authorization: `Bearer ${devSession.sessionToken}`,
      },
    });
    assert.strictEqual(authRes.status, 200);

    // 3. /auth/user endpoint returns logged-in user profile
    const userRes = await fetch(`http://127.0.0.1:${port}/auth/user`, {
      headers: {
        Cookie: `dbshield_session=${devSession.sessionToken}`,
      },
    });
    assert.strictEqual(userRes.status, 200);
    const userBody = (await userRes.json()) as any;
    assert.strictEqual(userBody.authenticated, true);
    assert.strictEqual(userBody.user.email, "dba@ritual.dev");
  } finally {
    await dashboard.stop();
  }
});

test("Air-Gapped Mode - SIEM Streamer Suppresses Network Sockets in Offline Private VPC", async () => {
  const prevEnv = process.env.DBSHIELD_AIR_GAPPED;
  try {
    process.env.DBSHIELD_AIR_GAPPED = "1";

    const streamer = new SiemTelemetryStreamer({
      enabled: true,
      endpoint: "https://telemetry.external-siem.com/v1/events",
      flushIntervalMs: 0,
    });

    await streamer.enqueue({
      auditId: "airgap_1",
      timestamp: new Date().toISOString(),
      sql: "SELECT 1;",
      operation: "SELECT",
      status: "SUCCESS",
      riskLevel: "SAFE",
      riskScore: 0,
    });

    const flushResult = await streamer.flush();
    assert.strictEqual(flushResult.success, true);
    assert.strictEqual(flushResult.sentCount, 0);
    assert.strictEqual(flushResult.airGapped, true);
  } finally {
    process.env.DBSHIELD_AIR_GAPPED = prevEnv;
  }
});
