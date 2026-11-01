import http from "node:http";
import { type AddressInfo } from "node:net";
import { ApprovalQueue } from "../approval/queue.js";
import { type AuditLogEntry, AuditLogger } from "../audit/index.js";
import type { DBShieldConfig } from "../types/index.js";

export class DashboardServer {
  private server: http.Server | null = null;
  private readonly config: DBShieldConfig;
  private readonly approvalQueue: ApprovalQueue;
  private readonly auditLogger?: AuditLogger;
  private sseClients: Set<http.ServerResponse> = new Set();
  private listenPort = 3100;

  constructor(config: DBShieldConfig, approvalQueue?: ApprovalQueue, auditLogger?: AuditLogger) {
    this.config = config;
    this.approvalQueue = approvalQueue || new ApprovalQueue();
    this.auditLogger = auditLogger;
    this.listenPort = config.dashboardPort || 3100;

    // Broadcast new approval requests to all connected SSE clients
    this.approvalQueue.subscribe((req) => {
      this.broadcastEvent("approval", req);
    });
  }

  public getApprovalQueue(): ApprovalQueue {
    return this.approvalQueue;
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

  private handleRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    const pathname = url.pathname;
    const method = req.method || "GET";

    // Set CORS headers
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

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
      const success = this.approvalQueue.approve(id);
      res.writeHead(success ? 200 : 404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success, id, status: "APPROVED" }));
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
        const success = this.approvalQueue.reject(id, undefined, reason);
        res.writeHead(success ? 200 : 404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success, id, status: "REJECTED" }));
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

    // Serve HTML Dashboard UI
    if (pathname === "/" || pathname === "/dashboard") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(this.renderDashboardHtml());
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not Found" }));
  }

  private renderDashboardHtml(): string {
    const tier = this.config.safetyTier || "BALANCED";
    const dialect = this.config.dialect || "sqlite";

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
