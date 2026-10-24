import net from "node:net";
import { AuditLogger } from "../audit/index.js";
import { DEFAULT_CONFIG } from "../config/index.js";
import { SqlGuardEngine } from "../guard/engine.js";
import { type MetricsRegistry, MetricsServer, getGlobalMetrics } from "../metrics/index.js";
import { MigrationSafetyEngine } from "../migration/index.js";
import { SemanticIntentGuard } from "../semantic/index.js";
import type { DBShieldConfig } from "../types/index.js";
import {
  encodeErrorResponse,
  encodeReadyForQuery,
  encodeSslDenial,
  extractSqlFromPayload,
  parseFrontendFrame,
} from "./protocol.js";

export interface PostgresWireProxyOptions {
  listenPort?: number;
  listenHost?: string;
  upstreamHost?: string;
  upstreamPort?: number;
  config?: DBShieldConfig;
  logger?: AuditLogger;
  verbose?: boolean;
  enableMetrics?: boolean;
  metricsPort?: number;
  metricsHost?: string;
  metricsRegistry?: MetricsRegistry;
}

export interface ProxyStats {
  activeConnections: number;
  totalConnections: number;
  queriesProcessed: number;
  queriesAllowed: number;
  queriesIntercepted: number;
}

export class PostgresWireProxy {
  private server: net.Server | null = null;
  private activeSockets = new Set<net.Socket>();
  private config: DBShieldConfig;
  private logger: AuditLogger;
  private sqlGuard: SqlGuardEngine;
  private migrationGuard: MigrationSafetyEngine;
  private semanticGuard: SemanticIntentGuard;
  private metricsServer: MetricsServer | null = null;
  private metricsRegistry: MetricsRegistry;

  public readonly listenPort: number;
  public readonly listenHost: string;
  public readonly upstreamHost: string;
  public readonly upstreamPort: number;
  public readonly verbose: boolean;
  public readonly enableMetrics: boolean;
  public readonly metricsPort: number;
  public readonly metricsHost: string;

  private stats: ProxyStats = {
    activeConnections: 0,
    totalConnections: 0,
    queriesProcessed: 0,
    queriesAllowed: 0,
    queriesIntercepted: 0,
  };

  constructor(options: PostgresWireProxyOptions = {}) {
    this.config = options.config || DEFAULT_CONFIG;
    this.listenPort = options.listenPort ?? 5433;
    this.listenHost = options.listenHost ?? "127.0.0.1";
    this.upstreamHost = options.upstreamHost ?? "127.0.0.1";
    this.upstreamPort = options.upstreamPort ?? 5432;
    this.verbose = options.verbose ?? false;
    this.enableMetrics = options.enableMetrics ?? this.config.enableMetrics ?? false;
    this.metricsPort = options.metricsPort ?? this.config.metricsPort ?? 9090;
    this.metricsHost = options.metricsHost ?? this.config.metricsHost ?? "0.0.0.0";
    this.metricsRegistry = options.metricsRegistry || getGlobalMetrics();

    this.logger = options.logger || new AuditLogger(this.config.auditLogPath);
    this.sqlGuard = new SqlGuardEngine(this.config);
    this.migrationGuard = new MigrationSafetyEngine(this.config);
    this.semanticGuard = new SemanticIntentGuard(this.config);
  }

  public getStats(): ProxyStats {
    return { ...this.stats };
  }

  /**
   * Start listening on TCP port for incoming PostgreSQL client connections.
   */
  public async start(): Promise<void> {
    if (this.enableMetrics) {
      this.metricsServer = new MetricsServer({
        port: this.metricsPort,
        host: this.metricsHost,
        registry: this.metricsRegistry,
        proxyInfo: {
          listenPort: this.listenPort,
          upstreamHost: this.upstreamHost,
          upstreamPort: this.upstreamPort,
          safetyTier: this.config.safetyTier,
        },
      });
      await this.metricsServer.start();
    }

    return new Promise((resolve, reject) => {
      this.server = net.createServer((clientSocket) => {
        this.handleClientConnection(clientSocket);
      });
      this.server.unref();

      this.server.on("error", (err) => {
        reject(err);
      });

      this.server.listen(this.listenPort, this.listenHost, () => {
        resolve();
      });
    });
  }

  /**
   * Stop the proxy server and close all sockets.
   */
  public async stop(): Promise<void> {
    if (this.metricsServer) {
      await this.metricsServer.stop();
      this.metricsServer = null;
    }

    for (const s of this.activeSockets) {
      if (!s.destroyed) s.destroy();
    }
    this.activeSockets.clear();

    return new Promise((resolve) => {
      if (!this.server) {
        resolve();
        return;
      }
      const s = this.server;
      this.server = null;
      const timer = setTimeout(() => resolve(), 200);
      s.close(() => {
        clearTimeout(timer);
        resolve();
      });
    });
  }

  /**
   * Handle an individual incoming client TCP connection.
   */
  private handleClientConnection(clientSocket: net.Socket): void {
    this.stats.activeConnections++;
    this.stats.totalConnections++;
    this.metricsRegistry.connectionsActive.inc();
    this.metricsRegistry.connectionsTotal.inc();
    this.activeSockets.add(clientSocket);

    if (this.verbose) {
      console.log(
        `🔌 [CONNECT] Client connected from ${clientSocket.remoteAddress || "127.0.0.1"}`,
      );
    }

    let clientBuffer = Buffer.alloc(0);
    let expectingStartup = true;
    let inErrorState = false;
    let upstreamConnected = false;
    const queuedClientPackets: Buffer[] = [];

    // Create upstream connection to target PostgreSQL server
    const upstreamSocket = new net.Socket();
    this.activeSockets.add(upstreamSocket);

    clientSocket.on("close", () => {
      this.activeSockets.delete(clientSocket);
      this.metricsRegistry.connectionsActive.dec();
      if (this.verbose) {
        console.log("🔌 [DISCONNECT] Client disconnected");
      }
    });
    upstreamSocket.on("close", () => {
      this.activeSockets.delete(upstreamSocket);
    });

    upstreamSocket.connect(this.upstreamPort, this.upstreamHost, () => {
      upstreamConnected = true;
      // Flush any queued packets
      while (queuedClientPackets.length > 0) {
        const pkt = queuedClientPackets.shift();
        if (pkt) upstreamSocket.write(pkt);
      }
    });

    // Pipe upstream responses back to client
    upstreamSocket.on("data", (data) => {
      if (!clientSocket.destroyed) {
        clientSocket.write(data);
      }
    });

    upstreamSocket.on("error", (err) => {
      if (!clientSocket.destroyed) {
        const errorPacket = encodeErrorResponse({
          severity: "FATAL",
          code: "08006",
          message: `[DBSHIELD_PROXY] Failed to connect to upstream PostgreSQL server at ${this.upstreamHost}:${this.upstreamPort}: ${err.message}`,
        });
        clientSocket.write(errorPacket);
        clientSocket.end();
      }
    });

    upstreamSocket.on("close", () => {
      if (!clientSocket.destroyed) {
        clientSocket.end();
      }
    });

    const forwardToUpstream = (data: Buffer) => {
      if (upstreamConnected && !upstreamSocket.destroyed) {
        upstreamSocket.write(data);
      } else {
        queuedClientPackets.push(data);
      }
    };

    clientSocket.on("data", (chunk) => {
      clientBuffer = Buffer.concat([clientBuffer, chunk]);

      while (clientBuffer.length > 0) {
        const parsed = parseFrontendFrame(clientBuffer, expectingStartup);
        if (!parsed) {
          // Incomplete frame, wait for more chunks
          break;
        }

        const { message, bytesConsumed } = parsed;
        clientBuffer = clientBuffer.subarray(bytesConsumed);

        if (expectingStartup) {
          if (message.type === "SSLRequest") {
            // Refuse SSL so client falls back to plaintext TCP over localhost
            clientSocket.write(encodeSslDenial());
            // Client will follow up with plaintext StartupMessage
            continue;
          }

          if (message.type === "StartupMessage") {
            expectingStartup = false;
            forwardToUpstream(message.raw);
            continue;
          }

          // Other startup messages (CancelRequest, etc.)
          forwardToUpstream(message.raw);
          continue;
        }

        // Post-startup message handling
        if (message.type === "Query" || message.type === "Parse") {
          this.stats.queriesProcessed++;
          const sql = extractSqlFromPayload(message.type, message.payload);

          if (!sql || !sql.trim()) {
            forwardToUpstream(message.raw);
            continue;
          }

          // Evaluate SQL with DBShield guardrails
          const startTime = Date.now();
          const evaluation = this.evaluateQuery(sql);
          const durationSec = (Date.now() - startTime) / 1000;
          this.metricsRegistry.queryDurationSeconds.observe(durationSec, {
            operation: evaluation.operation,
          });

          if (!evaluation.allowed) {
            this.stats.queriesIntercepted++;
            inErrorState = message.type === "Parse";
            const primaryViolation = evaluation.violations[0];
            const ruleCode = primaryViolation?.code || "BLOCKED";

            this.metricsRegistry.queriesTotal.inc({
              status: "blocked",
              safety_tier: this.config.safetyTier,
              operation: evaluation.operation,
            });
            this.metricsRegistry.queriesBlockedTotal.inc({
              rule: ruleCode,
              severity: evaluation.riskLevel,
            });

            // Estimated cloud infrastructure savings
            const savings =
              evaluation.operation === "DDL_DROP" || evaluation.operation === "DDL_TRUNCATE"
                ? 100
                : evaluation.operation === "UPDATE" || evaluation.operation === "DELETE"
                  ? 50
                  : 10;
            this.metricsRegistry.costSavingsDollarsTotal.inc(undefined, savings);

            // Log security event
            this.logger.log({
              auditId: `audit-proxy-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
              timestamp: new Date().toISOString(),
              sql,
              status: "BLOCKED",
              riskLevel: evaluation.riskLevel,
              riskScore: evaluation.riskScore,
              operation: evaluation.operation,
              violations: evaluation.violations.map((v) => `${v.code}: ${v.message}`),
            });

            // Return native PostgreSQL ErrorResponse packet
            if (this.verbose) {
              console.error(
                `🛑 [INTERCEPTED] ${evaluation.operation} on [${evaluation.targetTables.join(", ") || "table"}]: ${primaryViolation?.message || "Policy violation"}`,
              );
            }

            const errorPacket = encodeErrorResponse({
              severity: "ERROR",
              code: "42501", // insufficient_privilege
              message: `[DBSHIELD_INTERCEPTED] ${primaryViolation?.message || "Query blocked by DBShield safety policy"}`,
              detail: `Risk Level: ${evaluation.riskLevel} | Safety Tier: ${this.config.safetyTier} | Target: ${evaluation.targetTables.join(", ") || "N/A"}`,
              hint:
                primaryViolation?.suggestion ||
                "Modify your query or adjust safety settings in dbshield.config.json.",
            });

            clientSocket.write(errorPacket);

            // For simple Query ('Q'), immediately send ReadyForQuery so client doesn't hang
            if (message.type === "Query") {
              clientSocket.write(encodeReadyForQuery("I"));
            }
            continue;
          }

          // Query is allowed
          this.stats.queriesAllowed++;
          this.metricsRegistry.queriesTotal.inc({
            status: "allowed",
            safety_tier: this.config.safetyTier,
            operation: evaluation.operation,
          });
          if (this.verbose) {
            const preview = sql.trim().replace(/\s+/g, " ");
            console.log(
              `✅ [FORWARDED] ${evaluation.operation} on [${evaluation.targetTables.join(", ") || "table"}] (${preview.substring(0, 60)}${preview.length > 60 ? "..." : ""})`,
            );
          }

          this.logger.log({
            auditId: `audit-proxy-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
            timestamp: new Date().toISOString(),
            sql,
            status: "SUCCESS",
            riskLevel: evaluation.riskLevel,
            riskScore: evaluation.riskScore,
            operation: evaluation.operation,
          });

          forwardToUpstream(message.raw);
          continue;
        }

        if (inErrorState) {
          if (message.type === "Sync") {
            // Reset error state and send ReadyForQuery
            clientSocket.write(encodeReadyForQuery("I"));
            inErrorState = false;
          }
          // Discard Bind, Execute, Describe while in error state
          continue;
        }

        // Forward all other protocol packets (Sync, Bind, Execute, Terminate, Password, etc.)
        forwardToUpstream(message.raw);
      }
    });

    clientSocket.on("close", () => {
      this.stats.activeConnections = Math.max(0, this.stats.activeConnections - 1);
      if (!upstreamSocket.destroyed) {
        upstreamSocket.end();
      }
    });

    clientSocket.on("error", () => {
      if (!upstreamSocket.destroyed) {
        upstreamSocket.destroy();
      }
    });
  }

  /**
   * Evaluate a SQL query across all active DBShield guardrails:
   * 1. SqlGuardEngine (AST safety, unconstrained mutations, drops, tautologies)
   * 2. MigrationSafetyEngine (DDL table locking, non-concurrent index, breaking renames)
   * 3. SemanticIntentGuard (sensitive privilege & financial columns)
   */
  public evaluateQuery(sql: string) {
    // 1. Core AST Guard
    const astResult = this.sqlGuard.evaluate(sql);
    if (!astResult.allowed) {
      return astResult;
    }

    // 2. Migration & DDL Guard
    if (this.config.enableMigrationGate && astResult.operation.startsWith("DDL_")) {
      const migrationReport = this.migrationGuard.validateMigration(sql, "postgres");
      if (!migrationReport.safe) {
        return {
          allowed: false,
          riskLevel: "CRITICAL" as const,
          riskScore: migrationReport.riskScore,
          operation: astResult.operation,
          targetTables: astResult.targetTables,
          violations: migrationReport.violations.map((v) => ({
            code: v.code,
            message: v.message,
            severity: v.severity,
            suggestion: migrationReport.safeMigrationPlan.join(" -> "),
          })),
          warnings: migrationReport.warnings,
          requiresDryRun: false,
        };
      }
    }

    // 3. Semantic Guard on sensitive columns
    if (
      this.config.enableSemanticGuard &&
      (astResult.operation === "UPDATE" || astResult.operation === "INSERT")
    ) {
      const semanticResult = this.semanticGuard.evaluate(sql);
      if (!semanticResult.allowed) {
        return {
          allowed: false,
          riskLevel: semanticResult.riskLevel,
          riskScore: 85,
          operation: astResult.operation,
          targetTables: astResult.targetTables,
          violations: [
            {
              code: semanticResult.code || "SEMANTIC_GUARD_BLOCKED",
              message:
                semanticResult.warnings[0] ||
                "Unauthorized modification of sensitive column without validated intent.",
              severity: semanticResult.riskLevel,
              suggestion: semanticResult.suggestion,
            },
          ],
          warnings: semanticResult.warnings,
          requiresDryRun: false,
        };
      }
    }

    return astResult;
  }
}
