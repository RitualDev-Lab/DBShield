import http from "node:http";
import { type MetricsRegistry, getGlobalMetrics } from "./registry.js";

export interface MetricsServerOptions {
  port?: number;
  host?: string;
  registry?: MetricsRegistry;
  version?: string;
  proxyInfo?: {
    listenPort: number;
    upstreamHost: string;
    upstreamPort: number;
    safetyTier: string;
  };
}

export class MetricsServer {
  private server: http.Server | null = null;
  public readonly port: number;
  public readonly host: string;
  public readonly registry: MetricsRegistry;
  private readonly version: string;
  private readonly startTime = Date.now();
  private proxyInfo?: MetricsServerOptions["proxyInfo"];

  constructor(options: MetricsServerOptions = {}) {
    this.port = options.port ?? 9090;
    this.host = options.host ?? "0.0.0.0";
    this.registry = options.registry || getGlobalMetrics();
    this.version = options.version || "0.2.0";
    this.proxyInfo = options.proxyInfo;
  }

  public setProxyInfo(info: MetricsServerOptions["proxyInfo"]): void {
    this.proxyInfo = info;
  }

  public async start(): Promise<number> {
    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        this.handleRequest(req, res);
      });

      this.server.on("error", (err) => {
        reject(err);
      });

      this.server.listen(this.port, this.host, () => {
        const addr = this.server?.address();
        const actualPort = typeof addr === "object" && addr ? addr.port : this.port;
        resolve(actualPort);
      });
    });
  }

  public async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  private handleRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    const url = new URL(req.url ?? "/", `http://${req.headers.host || "localhost"}`);

    // 1. Prometheus Scrape Endpoint
    if (url.pathname === "/metrics") {
      const output = this.registry.toPrometheus();
      res.writeHead(200, {
        "Content-Type": "text/plain; version=0.0.4; charset=utf-8",
        "Cache-Control": "no-cache",
      });
      res.end(output);
      return;
    }

    // 2. Kubernetes Liveness & Health Probe
    if (url.pathname === "/healthz" || url.pathname === "/health") {
      const uptimeSeconds = Math.floor((Date.now() - this.startTime) / 1000);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          status: "healthy",
          service: "dbshield-proxy",
          version: this.version,
          uptimeSeconds,
          proxy: this.proxyInfo ?? null,
        }),
      );
      return;
    }

    // 3. Kubernetes Readiness Probe
    if (url.pathname === "/ready") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          status: "ready",
          service: "dbshield-proxy",
          version: this.version,
        }),
      );
      return;
    }

    // 4. Default Root Metadata
    if (url.pathname === "/") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          name: "DBShield Prometheus Metrics & Health Exporter",
          version: this.version,
          endpoints: {
            metrics: "/metrics",
            health: "/healthz",
            ready: "/ready",
          },
        }),
      );
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not Found" }));
  }
}
