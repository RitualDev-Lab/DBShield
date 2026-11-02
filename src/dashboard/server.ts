import http from "node:http";
import type { AddressInfo } from "node:net";
import { ChatOpsNotifier } from "../approval/chatops.js";
import { ApprovalQueue } from "../approval/queue.js";
import type { AuditLogEntry, AuditLogger } from "../audit/index.js";
import { SsoAuthenticator } from "../auth/sso.js";
import { ComplianceReporter } from "../compliance/reporter.js";
import type { DBShieldConfig, SsoUser } from "../types/index.js";

export class DashboardServer {
  private server: http.Server | null = null;
  private readonly config: DBShieldConfig;
  private readonly approvalQueue: ApprovalQueue;
  private readonly auditLogger?: AuditLogger;
  private readonly ssoAuthenticator?: SsoAuthenticator;
  private readonly complianceReporter: ComplianceReporter;
  private readonly chatOpsNotifier: ChatOpsNotifier;
  private sseClients: Set<http.ServerResponse> = new Set();
  private listenPort = 3100;

  constructor(
    config: DBShieldConfig,
    approvalQueue?: ApprovalQueue,
    auditLogger?: AuditLogger,
    ssoAuthenticator?: SsoAuthenticator,
  ) {
    this.config = config;
    this.approvalQueue = approvalQueue || new ApprovalQueue();
    this.auditLogger = auditLogger;
    this.ssoAuthenticator =
      ssoAuthenticator || (config.sso ? new SsoAuthenticator(config.sso) : undefined);
    this.complianceReporter = new ComplianceReporter(config, auditLogger);
    this.chatOpsNotifier = new ChatOpsNotifier(config.chatOps || {}, this.approvalQueue);
    this.listenPort = config.dashboardPort || 3100;

    // Broadcast new approval requests to all connected SSE clients
    this.approvalQueue.subscribe((req) => {
      this.broadcastEvent("approval", req);
    });
  }

  public getApprovalQueue(): ApprovalQueue {
    return this.approvalQueue;
  }

  public getChatOpsNotifier(): ChatOpsNotifier {
    return this.chatOpsNotifier;
  }

  public getSsoAuthenticator(): SsoAuthenticator | undefined {
    return this.ssoAuthenticator;
  }

  public getComplianceReporter(): ComplianceReporter {
    return this.complianceReporter;
  }

  public getPort(): number {
    if (this.server) {
      const addr = this.server.address() as AddressInfo;
      return addr ? addr.port : this.listenPort;
    }
    return this.listenPort;
  }

  public async start(port?: number, host = "0.0.0.0"): Promise<void> {
    const targetPort = port ?? this.listenPort;

    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        this.handleRequest(req, res);
      });

      this.server.on("error", (err) => {
        reject(err);
      });

      this.server.listen(targetPort, host, () => {
        const addr = this.server?.address() as AddressInfo;
        this.listenPort = addr.port;
        resolve();
      });
    });
  }

  public async stop(): Promise<void> {
    for (const client of this.sseClients) {
      try {
        client.end();
      } catch {
        // Safe close
      }
    }
    this.sseClients.clear();

    if (this.server) {
      return new Promise((resolve, reject) => {
        this.server?.close((err) => {
          if (err) reject(err);
          else resolve();
        });
        this.server = null;
      });
    }
  }

  /**
   * Broadcast an event to all connected dashboard SSE clients.
   */
  public broadcastEvent(eventType: string, data: unknown): void {
    const message = `event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const client of this.sseClients) {
      try {
        client.write(message);
      } catch {
        this.sseClients.delete(client);
      }
    }
  }

  private extractToken(req: http.IncomingMessage): string | null {
    const authHeader = req.headers.authorization;
    if (authHeader?.toLowerCase().startsWith("bearer ")) {
      return authHeader.slice(7).trim();
    }
    const cookieHeader = req.headers.cookie;
    if (cookieHeader) {
      const parts = cookieHeader.split(";").map((p) => p.trim());
      for (const p of parts) {
        if (p.startsWith("dbshield_session=")) {
          return p.slice("dbshield_session=".length).trim();
        }
      }
    }
    return null;
  }

  private authenticateUser(req: http.IncomingMessage): { authenticated: boolean; user?: SsoUser } {
    if (!this.ssoAuthenticator || !this.ssoAuthenticator.isEnabled()) {
      return {
        authenticated: true,
        user: {
          id: "local_admin",
          email: "developer@local",
          roles: ["admin", "approver"],
          provider: "oidc",
          issuedAt: Math.floor(Date.now() / 1000),
          expiresAt: Math.floor(Date.now() / 1000) + 86400,
        },
      };
    }

    const token = this.extractToken(req);
    if (!token) {
      return { authenticated: false };
    }

    const result = this.ssoAuthenticator.verifySessionToken(token);
    return {
      authenticated: result.valid,
      user: result.user,
    };
  }

  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    const pathname = url.pathname;
    const method = req.method || "GET";

    // Set CORS headers
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    if (method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    // Health check
    if (pathname === "/healthz") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok", timestamp: new Date().toISOString() }));
      return;
    }

    // SSO: Initiate Login
    if (pathname === "/auth/login") {
      if (!this.ssoAuthenticator || !this.ssoAuthenticator.isEnabled()) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({ ssoEnabled: false, message: "SSO is not enabled on this server." }),
        );
        return;
      }

      const providerParam = url.searchParams.get("provider");
      const authUrl = this.ssoAuthenticator.generateAuthUrl();

      if (url.searchParams.get("format") === "json") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ authUrl, provider: this.ssoAuthenticator.getProvider() }));
        return;
      }

      res.writeHead(302, { Location: authUrl });
      res.end();
      return;
    }

    // SSO: Callback
    if (pathname === "/auth/callback") {
      if (!this.ssoAuthenticator || !this.ssoAuthenticator.isEnabled()) {
        res.writeHead(302, { Location: "/" });
        res.end();
        return;
      }

      const code = url.searchParams.get("code") || undefined;
      const idToken = url.searchParams.get("id_token") || undefined;
      const samlResponse = url.searchParams.get("SAMLResponse") || undefined;

      const callbackResult = await this.ssoAuthenticator.handleCallback({
        code,
        id_token: idToken,
        samlResponse,
      });

      if (!callbackResult.success || !callbackResult.sessionToken) {
        res.writeHead(403, { "Content-Type": "text/html; charset=utf-8" });
        res.end(
          `<h1>SSO Authentication Failed</h1><p>${callbackResult.error || "Unknown error"}</p><a href="/auth/login">Try again</a>`,
        );
        return;
      }

      res.writeHead(302, {
        "Set-Cookie": `dbshield_session=${callbackResult.sessionToken}; Path=/; HttpOnly; SameSite=Lax`,
        Location: "/",
      });
      res.end();
      return;
    }

    // SSO: Current User
    if (pathname === "/auth/user") {
      const auth = this.authenticateUser(req);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ authenticated: auth.authenticated, user: auth.user }));
      return;
    }

    // SSO: Logout
    if (pathname === "/auth/logout") {
      res.writeHead(302, {
        "Set-Cookie": "dbshield_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        Location: "/",
      });
      res.end();
      return;
    }

    // Compliance Reporting Endpoint (SOC 2 / ISO 27001)
    if (pathname === "/api/compliance/report") {
      const auth = this.authenticateUser(req);
      if (!auth.authenticated) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            error: "Unauthorized: SSO authentication required",
            loginUrl: "/auth/login",
          }),
        );
        return;
      }

      const framework = (url.searchParams.get("framework") as "soc2" | "iso27001") || "soc2";
      const format = (url.searchParams.get("format") as "json" | "html" | "pdf") || "json";

      const report = await this.complianceReporter.generateReport({
        framework,
        format,
        companyName: url.searchParams.get("company") || undefined,
        environment: url.searchParams.get("env") || undefined,
      });

      if (format === "html") {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(report.rawReport);
      } else if (format === "pdf") {
        res.writeHead(200, {
          "Content-Type": "application/pdf",
          "Content-Disposition": `attachment; filename="${report.reportId}.pdf"`,
        });
        res.end(report.rawReport);
      } else {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(report));
      }
      return;
    }

    // Slack Interactive Webhook Callback
    if (
      (pathname === "/api/webhooks/slack/actions" || pathname === "/slack/actions") &&
      method === "POST"
    ) {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        const signature = (req.headers["x-slack-signature"] as string) || "";
        const timestamp = (req.headers["x-slack-request-timestamp"] as string) || "";

        if (!this.chatOpsNotifier.verifySlackSignature(body, signature, timestamp)) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid Slack signature" }));
          return;
        }

        try {
          let parsed: any;
          if (body.startsWith("payload=")) {
            const decoded = decodeURIComponent(body.slice(8).replace(/\+/g, " "));
            parsed = JSON.parse(decoded);
          } else {
            parsed = JSON.parse(body);
          }

          const action = parsed.actions?.[0];
          const actionId = action?.action_id;
          const requestId = action?.value;
          const userName = parsed.user?.username || parsed.user?.name || "Slack User";
          const userEmail = parsed.user?.email;

          const result = this.chatOpsNotifier.handleSlackAction({
            actionId,
            requestId,
            userName,
            userEmail,
          });

          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              replace_original: true,
              text: `[DBShield] Mutation ${result.status} by @${userName}`,
              blocks: result.updatedBlocks,
            }),
          );
        } catch (err) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: `Invalid Slack payload: ${String(err)}` }));
        }
      });
      return;
    }

    // Teams Interactive Webhook Callback
    if (
      (pathname === "/api/webhooks/teams/actions" || pathname === "/teams/actions") &&
      method === "POST"
    ) {
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        try {
          const parsed = JSON.parse(body);
          const actionId = parsed.action || parsed.verb;
          const requestId = parsed.requestId || parsed.id;
          const userName = parsed.from?.name || "Teams User";

          const result = this.chatOpsNotifier.handleSlackAction({
            actionId: actionId === "approve" ? "dbshield_approve" : "dbshield_reject",
            requestId,
            userName,
          });

          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ success: result.success, status: result.status }));
        } catch (err) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: `Invalid Teams payload: ${String(err)}` }));
        }
      });
      return;
    }

    // Authenticate Protected API Endpoints
    const auth = this.authenticateUser(req);
    const isProtectedApi =
      pathname.startsWith("/api/approvals") ||
      pathname === "/api/audit" ||
      pathname === "/api/stream";

    if (isProtectedApi && !auth.authenticated) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          error: "Unauthorized: SSO authentication required",
          loginUrl: "/auth/login",
        }),
      );
      return;
    }

    // SSE Stream
    if (pathname === "/api/stream") {
      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
      });
      res.write(": keepalive\n\n");
      this.sseClients.add(res);

      req.on("close", () => {
        this.sseClients.delete(res);
      });
      return;
    }

    // List approvals
    if (pathname === "/api/approvals" && method === "GET") {
      const all = this.approvalQueue.getAll();
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ approvals: all }));
      return;
    }

    // Approve endpoint
    const approveMatch = pathname.match(/^\/api\/approvals\/([^/]+)\/approve$/);
    if (approveMatch && method === "POST") {
      const id = approveMatch[1];
      const success = this.approvalQueue.approve(id, auth.user?.email || "developer");
      res.writeHead(success ? 200 : 404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success, id, status: "APPROVED", approvedBy: auth.user?.email }));
      return;
    }

    // Reject endpoint
    const rejectMatch = pathname.match(/^\/api\/approvals\/([^/]+)\/reject$/);
    if (rejectMatch && method === "POST") {
      const id = rejectMatch[1];
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        let reason: string | undefined;
        try {
          if (body) {
            const parsed = JSON.parse(body);
            reason = parsed.reason;
          }
        } catch {
          // ignore parse error
        }
        const success = this.approvalQueue.reject(id, auth.user?.email || "developer", reason);
        res.writeHead(success ? 200 : 404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success, id, status: "REJECTED", rejectedBy: auth.user?.email }));
      });
      return;
    }

    // Audit logs
    if (pathname === "/api/audit" && method === "GET") {
      const entries = this.auditLogger ? this.auditLogger.getEntries({ limit: 50 }) : [];
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ auditLogs: entries }));
      return;
    }

    // Serve HTML Dashboard UI or SSO Portal
    if (pathname === "/" || pathname === "/dashboard") {
      if (this.ssoAuthenticator?.isEnabled() && !auth.authenticated) {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        res.end(this.renderSsoLoginHtml());
        return;
      }

      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(this.renderDashboardHtml(auth.user));
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not Found" }));
  }

  private renderSsoLoginHtml(): string {
    const provider = this.ssoAuthenticator?.getProvider() || "okta";
    const providerNames: Record<string, string> = {
      okta: "Okta Verify / Workforce",
      "azure-ad": "Microsoft Azure AD (Entra ID)",
      google: "Google Workspace",
      "ping-identity": "PingIdentity PingFederate",
      saml: "Enterprise SAML 2.0",
      oidc: "Enterprise OIDC",
    };
    const activeProviderName = providerNames[provider] || provider.toUpperCase();

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DBShield — Enterprise SSO Sign-In</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --border: #1f293d;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --accent: #8b5cf6;
      --accent-hover: #7c3aed;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 20px;
    }
    .login-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      width: 100%;
      max-width: 440px;
      padding: 36px;
      text-align: center;
      box-shadow: 0 20px 40px rgba(0,0,0,0.5);
    }
    .logo {
      font-size: 40px;
      margin-bottom: 12px;
    }
    h1 {
      font-size: 22px;
      font-weight: 700;
      margin-bottom: 8px;
    }
    p {
      color: var(--text-muted);
      font-size: 14px;
      margin-bottom: 28px;
    }
    .sso-btn {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 12px;
      width: 100%;
      padding: 13px 20px;
      margin-bottom: 12px;
      border-radius: 8px;
      font-size: 15px;
      font-weight: 600;
      text-decoration: none;
      color: white;
      background: var(--accent);
      transition: background 0.15s ease;
      cursor: pointer;
      border: none;
    }
    .sso-btn:hover { background: var(--accent-hover); }
    .providers-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
      margin-top: 16px;
    }
    .provider-pill {
      background: #1f2937;
      border: 1px solid #374151;
      padding: 10px;
      border-radius: 6px;
      font-size: 12px;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
    }
    .footer {
      margin-top: 24px;
      font-size: 12px;
      color: var(--text-muted);
      border-top: 1px solid var(--border);
      padding-top: 16px;
    }
  </style>
</head>
<body>
  <div class="login-card">
    <div class="logo">🛡️</div>
    <h1>DBShield Control Plane</h1>
    <p>Sign in with your corporate identity to access live mutation approvals and security guardrails.</p>

    <a href="/auth/login" class="sso-btn">
      <span>Continue with ${activeProviderName}</span>
    </a>

    <div class="providers-grid">
      <div class="provider-pill">🔵 Okta</div>
      <div class="provider-pill">🔷 Azure AD</div>
      <div class="provider-pill">🔴 Google Workspace</div>
      <div class="provider-pill">🟢 PingIdentity</div>
    </div>

    <div class="footer">
      Protected by Enterprise SSO (OIDC / SAML 2.0) & SOC 2 CC6.1
    </div>
  </div>
</body>
</html>`;
  }

  private renderDashboardHtml(user?: SsoUser): string {
    const tier = this.config.safetyTier || "BALANCED";
    const dialect = this.config.dialect || "sqlite";
    const userBadge = user?.email
      ? `<span style="font-size: 13px; color: var(--text-muted); background: var(--card-border); padding: 4px 10px; border-radius: 6px;">👤 ${user.email} (${user.roles.join(", ")}) &middot; <a href="/auth/logout" style="color: var(--accent); text-decoration: none;">Sign Out</a></span>`
      : "";

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DBShield — Live Query Approval Feed & Defense Dashboard</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --card-border: #1f293d;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --accent: #8b5cf6;
      --accent-glow: rgba(139, 92, 246, 0.15);
      --critical: #ef4444;
      --warning: #f59e0b;
      --success: #10b981;
      --info: #3b82f6;
      --code-bg: #030712;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 24px;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--card-border);
    }
    .logo {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .shield-badge {
      background: linear-gradient(135deg, #7c3aed, #4f46e5);
      width: 40px;
      height: 40px;
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 22px;
      box-shadow: 0 4px 14px rgba(124, 58, 237, 0.4);
    }
    .title h1 { font-size: 20px; font-weight: 700; }
    .title p { font-size: 13px; color: var(--text-muted); }
    .meta-badges { display: flex; gap: 8px; }
    .badge {
      display: inline-flex;
      align-items: center;
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      letter-spacing: 0.5px;
    }
    .badge-status { background: rgba(16, 185, 129, 0.15); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-tier { background: rgba(139, 92, 246, 0.15); color: var(--accent); border: 1px solid rgba(139, 92, 246, 0.3); }
    .badge-dialect { background: rgba(59, 130, 246, 0.15); color: var(--info); border: 1px solid rgba(59, 130, 246, 0.3); }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 28px;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 16px 20px;
    }
    .stat-card .label { font-size: 12px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; margin-bottom: 6px; }
    .stat-card .value { font-size: 28px; font-weight: 800; }

    .section-title {
      font-size: 16px;
      font-weight: 700;
      margin-bottom: 14px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .feed-container {
      display: flex;
      flex-direction: column;
      gap: 14px;
    }
    .query-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 18px 20px;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    .query-card.pending {
      border-color: #f59e0b;
      box-shadow: 0 0 16px rgba(245, 158, 11, 0.1);
    }
    .query-card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
    }
    .op-tag {
      font-family: monospace;
      font-weight: 700;
      font-size: 13px;
      padding: 2px 8px;
      border-radius: 4px;
    }
    .op-UPDATE { background: #3b82f6; color: white; }
    .op-DELETE { background: #ef4444; color: white; }
    .op-INSERT { background: #10b981; color: white; }
    .op-SELECT { background: #6b7280; color: white; }
    .op-DDL { background: #a855f7; color: white; }

    .sql-box {
      background: var(--code-bg);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 8px;
      padding: 12px 14px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 13px;
      color: #e5e7eb;
      overflow-x: auto;
      margin-bottom: 14px;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .card-footer {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 12px;
      color: var(--text-muted);
    }
    .action-buttons {
      display: flex;
      gap: 10px;
    }
    .btn {
      cursor: pointer;
      padding: 8px 16px;
      border-radius: 6px;
      font-size: 13px;
      font-weight: 600;
      border: none;
      transition: all 0.15s ease;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .btn-approve {
      background: var(--success);
      color: white;
    }
    .btn-approve:hover { background: #059669; }
    .btn-reject {
      background: var(--critical);
      color: white;
    }
    .btn-reject:hover { background: #dc2626; }
    .status-badge {
      padding: 4px 10px;
      border-radius: 6px;
      font-weight: 700;
      font-size: 12px;
    }
    .status-PENDING { background: rgba(245, 158, 11, 0.2); color: #fbbf24; }
    .status-APPROVED { background: rgba(16, 185, 129, 0.2); color: #34d399; }
    .status-REJECTED { background: rgba(239, 68, 68, 0.2); color: #f87171; }
    .empty-state {
      text-align: center;
      padding: 48px;
      color: var(--text-muted);
      font-size: 14px;
      background: var(--card-bg);
      border-radius: 12px;
      border: 1px dashed var(--card-border);
    }
  </style>
</head>
<body>
  <div class="header">
    <div class="logo">
      <div class="shield-badge">🛡️</div>
      <div class="title">
        <h1>DBShield Live Query Defense & Approval Feed</h1>
        <p>Real-time AI agent query interceptor, risk evaluation, and human-in-the-loop approval gate</p>
      </div>
    </div>
    <div class="meta-badges">
      ${userBadge}
      <span class="badge badge-status">● LIVE GATEWAY</span>
      <span class="badge badge-tier">TIER: ${tier}</span>
      <span class="badge badge-dialect">DIALECT: ${dialect.toUpperCase()}</span>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card">
      <div class="label">Pending Approvals</div>
      <div class="value" id="stat-pending" style="color: var(--warning)">0</div>
    </div>
    <div class="stat-card">
      <div class="label">Approved Mutations</div>
      <div class="value" id="stat-approved" style="color: var(--success)">0</div>
    </div>
    <div class="stat-card">
      <div class="label">Blocked Risk Attacks</div>
      <div class="value" id="stat-blocked" style="color: var(--critical)">0</div>
    </div>
    <div class="stat-card">
      <div class="label">PII Redactions</div>
      <div class="value" id="stat-pii" style="color: var(--accent)">0</div>
    </div>
  </div>

  <div class="section-title">
    <span>⚡ Sensitive Mutation Approvals (1-Click Action)</span>
  </div>

  <div id="approvals-feed" class="feed-container">
    <div class="empty-state">No pending mutations requiring approval. Agents are operating safely within policy thresholds.</div>
  </div>

  <div class="section-title" style="margin-top: 36px;">
    <span>📡 Live Real-Time Agent Query Stream</span>
  </div>

  <div id="live-stream-feed" class="feed-container">
    <!-- Stream entries pop in here -->
  </div>

  <script>
    let approvals = [];
    let piiCount = 0;
    let blockedCount = 0;

    async function fetchApprovals() {
      try {
        const res = await fetch('/api/approvals');
        const data = await res.json();
        approvals = data.approvals || [];
        renderApprovals();
      } catch (err) {
        console.error('Failed fetching approvals:', err);
      }
    }

    async function approve(id) {
      try {
        const btn = document.getElementById('btn-appr-' + id);
        if (btn) btn.disabled = true;
        await fetch('/api/approvals/' + id + '/approve', { method: 'POST' });
        await fetchApprovals();
      } catch (err) {
        alert('Approval failed: ' + err.message);
      }
    }

    async function reject(id) {
      try {
        const btn = document.getElementById('btn-rej-' + id);
        if (btn) btn.disabled = true;
        await fetch('/api/approvals/' + id + '/reject', { method: 'POST' });
        await fetchApprovals();
      } catch (err) {
        alert('Rejection failed: ' + err.message);
      }
    }

    function renderApprovals() {
      const container = document.getElementById('approvals-feed');
      const pending = approvals.filter(a => a.status === 'PENDING');
      const approved = approvals.filter(a => a.status === 'APPROVED');
      
      document.getElementById('stat-pending').textContent = pending.length;
      document.getElementById('stat-approved').textContent = approved.length;

      if (approvals.length === 0) {
        container.innerHTML = '<div class="empty-state">No pending mutations requiring approval. Agents are operating safely within policy thresholds.</div>';
        return;
      }

      container.innerHTML = approvals.map(appr => {
        const isPending = appr.status === 'PENDING';
        return \`
          <div class="query-card \${isPending ? 'pending' : ''}" id="card-\${appr.id}">
            <div class="query-card-header">
              <div style="display: flex; align-items: center; gap: 10px;">
                <span class="op-tag op-\${appr.operation}">\${appr.operation}</span>
                <span style="font-size: 13px; font-weight: 600;">\${appr.id}</span>
                <span style="font-size: 12px; color: var(--text-muted);">\${appr.agentId} (\${appr.clientIp})</span>
              </div>
              <div style="display: flex; align-items: center; gap: 8px;">
                <span style="font-size: 12px; font-weight: 700; color: \${appr.riskScore >= 70 ? 'var(--critical)' : 'var(--warning)'}">Risk: \${appr.riskScore}/100</span>
                <span class="status-badge status-\${appr.status}">\${appr.status}</span>
              </div>
            </div>
            <div class="sql-box">\${escapeHtml(appr.sql)}</div>
            <div class="card-footer">
              <div>Target Tables: <strong>\${(appr.targetTables || []).join(', ') || 'N/A'}</strong> | PII Protected: <strong>\${appr.piiRedacted ? 'YES' : 'NO'}</strong> | Timestamp: \${new Date(appr.timestamp).toLocaleTimeString()}</div>
              \${isPending ? \`
                <div class="action-buttons">
                  <button id="btn-appr-\${appr.id}" class="btn btn-approve" onclick="approve('\${appr.id}')">✓ 1-Click Approve</button>
                  <button id="btn-rej-\${appr.id}" class="btn btn-reject" onclick="reject('\${appr.id}')">✕ Reject</button>
                </div>
              \` : \`
                <div style="font-size: 12px; color: var(--text-muted)">Decided by: \${appr.decidedBy || 'Admin'} at \${new Date(appr.decidedAt).toLocaleTimeString()}</div>
              \`}
            </div>
          </div>
        \`;
      }).join('');
    }

    function escapeHtml(str) {
      return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    // Connect SSE stream
    const evtSource = new EventSource('/api/stream');
    evtSource.addEventListener('approval', (e) => {
      fetchApprovals();
    });
    evtSource.addEventListener('audit', (e) => {
      const entry = JSON.parse(e.data);
      if (entry.status === 'BLOCKED') {
        blockedCount++;
        document.getElementById('stat-blocked').textContent = blockedCount;
      }
      if (entry.piiRedacted) {
        piiCount++;
        document.getElementById('stat-pii').textContent = piiCount;
      }
    });

    fetchApprovals();
  </script>
</body>
</html>`;
  }
}
