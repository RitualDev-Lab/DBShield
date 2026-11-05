import net from "node:net";
import { AuditLogger, SiemTelemetryStreamer } from "../audit/index.js";
import { DEFAULT_CONFIG } from "../config/index.js";
import { SqlGuardEngine } from "../guard/engine.js";
import { type MetricsRegistry, getGlobalMetrics } from "../metrics/index.js";
import type { DBShieldConfig } from "../types/index.js";
import {
  decodeMysqlPacket,
  encodeMysqlErrorPacket,
  extractSqlFromMysqlPacket,
  hasCompleteMysqlPacket,
  isMysqlQueryPacket,
} from "./mysql-protocol.js";

export interface MysqlWireProxyOptions {
  listenPort?: number;
  listenHost?: string;
  upstreamHost?: string;
  upstreamPort?: number;
  config?: DBShieldConfig;
  logger?: AuditLogger;
  verbose?: boolean;
  metricsRegistry?: MetricsRegistry;
  enableReadReplicaRouting?: boolean;
  readReplicaHost?: string;
  readReplicaPort?: number;
}

export interface MysqlProxyStats {
  activeConnections: number;
  totalConnections: number;
  queriesProcessed: number;
  queriesAllowed: number;
  queriesIntercepted: number;
  routedToPrimary: number;
  routedToReplica: number;
}

export class MysqlWireProxy {
  private server: net.Server | null = null;
  private activeSockets = new Set<net.Socket>();
  private config: DBShieldConfig;
  private logger: AuditLogger;
  private sqlGuard: SqlGuardEngine;
  private metricsRegistry: MetricsRegistry;

  public readonly listenPort: number;
  public readonly listenHost: string;
  public readonly upstreamHost: string;
  public readonly upstreamPort: number;
  public readonly verbose: boolean;
  public readonly enableReadReplicaRouting: boolean;
  public readonly readReplicaHost?: string;
  public readonly readReplicaPort: number;

  private stats: MysqlProxyStats = {
    activeConnections: 0,
    totalConnections: 0,
    queriesProcessed: 0,
    queriesAllowed: 0,
    queriesIntercepted: 0,
    routedToPrimary: 0,
    routedToReplica: 0,
  };

  constructor(options: MysqlWireProxyOptions = {}) {
    this.config = {
      ...DEFAULT_CONFIG,
      dialect: "mysql",
      ...options.config,
    };
    this.listenPort = options.listenPort ?? this.config.mysqlProxyPort ?? 3307;
    this.listenHost = options.listenHost ?? "127.0.0.1";
    this.upstreamHost = options.upstreamHost ?? this.config.mysqlUpstreamHost ?? "127.0.0.1";
    this.upstreamPort = options.upstreamPort ?? this.config.mysqlUpstreamPort ?? 3306;
    this.verbose = options.verbose ?? false;
    this.metricsRegistry = options.metricsRegistry || getGlobalMetrics();
    this.enableReadReplicaRouting =
      options.enableReadReplicaRouting ?? this.config.enableReadReplicaRouting ?? false;
    this.readReplicaHost = options.readReplicaHost ?? this.config.readReplicaHost;
    this.readReplicaPort = options.readReplicaPort ?? this.config.readReplicaPort ?? 3306;

    this.logger = options.logger || new AuditLogger(this.config.auditLogPath);
    if (this.config.siemTelemetry?.enabled && !this.logger.getSiemStreamer()) {
      this.logger.setSiemStreamer(new SiemTelemetryStreamer(this.config.siemTelemetry));
    }
    this.sqlGuard = new SqlGuardEngine(this.config);
  }

  public getStats(): MysqlProxyStats {
    return { ...this.stats };
  }

  public async start(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      this.server = net.createServer((clientSocket) => {
        this.handleClientConnection(clientSocket);
      });

      this.server.on("error", (err) => {
        reject(err);
      });

      this.server.listen(this.listenPort, this.listenHost, () => {
        if (this.verbose) {
          console.log(
            `🛡️ [MYSQL_PROXY] Listening on ${this.listenHost}:${this.listenPort} -> Upstream MySQL ${this.upstreamHost}:${this.upstreamPort}`,
          );
        }
        resolve();
      });
    });
  }

  public async stop(): Promise<void> {
    for (const socket of this.activeSockets) {
      socket.destroy();
    }
    this.activeSockets.clear();

    return new Promise((resolve) => {
      if (!this.server) {
        resolve();
        return;
      }
      const s = this.server;
      this.server = null;
      s.close(() => resolve());
    });
  }

  private handleClientConnection(clientSocket: net.Socket): void {
    this.stats.activeConnections++;
    this.stats.totalConnections++;
    this.metricsRegistry.connectionsActive.inc();
    this.metricsRegistry.connectionsTotal.inc();
    this.activeSockets.add(clientSocket);

    let clientBuffer = Buffer.alloc(0);
    let upstreamConnected = false;
    const queuedClientPackets: Buffer[] = [];

    const upstreamSocket = new net.Socket();
    this.activeSockets.add(upstreamSocket);

    clientSocket.on("close", () => {
      this.activeSockets.delete(clientSocket);
      this.metricsRegistry.connectionsActive.dec();
      upstreamSocket.destroy();
    });

    upstreamSocket.on("close", () => {
      this.activeSockets.delete(upstreamSocket);
      clientSocket.destroy();
    });

    upstreamSocket.connect(this.upstreamPort, this.upstreamHost, () => {
      upstreamConnected = true;
      while (queuedClientPackets.length > 0) {
        const pkt = queuedClientPackets.shift();
        if (pkt) upstreamSocket.write(pkt);
      }
    });

    upstreamSocket.on("data", (data) => {
      if (!clientSocket.destroyed) {
        clientSocket.write(data);
      }
    });

    upstreamSocket.on("error", (err) => {
      if (!clientSocket.destroyed) {
        const errorPacket = encodeMysqlErrorPacket({
          sequenceId: 1,
          errorCode: 2003,
          message: `[DBSHIELD_PROXY] Failed to connect to upstream MySQL server at ${this.upstreamHost}:${this.upstreamPort}: ${err.message}`,
        });
        clientSocket.write(errorPacket);
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

    clientSocket.on("data", (chunk: Buffer | string) => {
      const buf = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
      clientBuffer = Buffer.concat([clientBuffer, buf]);

      while (hasCompleteMysqlPacket(clientBuffer)) {
        const packet = decodeMysqlPacket(clientBuffer);
        if (!packet) break;

        // Advance buffer past this packet
        clientBuffer = clientBuffer.subarray(packet.raw.length);

        if (isMysqlQueryPacket(packet)) {
          this.stats.queriesProcessed++;

          const sql = extractSqlFromMysqlPacket(packet) || "";
          const guardResult = this.sqlGuard.evaluate(sql);

          if (!guardResult.allowed) {
            this.stats.queriesIntercepted++;
            this.metricsRegistry.queriesTotal.inc({ status: "blocked" });
            this.metricsRegistry.queriesBlockedTotal.inc({ rule: "BLOCKED" });

            const primaryViolation =
              guardResult.violations[0]?.message ||
              "Query blocked by DBShield SQL guardrail policy.";

            const errorPacket = encodeMysqlErrorPacket({
              sequenceId: packet.sequenceId + 1,
              errorCode: 1148,
              sqlState: "42000",
              message: `[DBSHIELD_MUTATION_GUARD] ${primaryViolation}`,
            });

            clientSocket.write(errorPacket);

            this.logger.log({
              auditId: `mysql-${Date.now()}`,
              timestamp: new Date().toISOString(),
              sql,
              operation: guardResult.operation,
              status: "BLOCKED",
              riskLevel: guardResult.riskLevel,
              riskScore: guardResult.riskScore,
              violations: guardResult.violations.map((v) => v.message),
            });
            continue;
          }

          this.stats.queriesAllowed++;
          this.metricsRegistry.queriesTotal.inc({ status: "allowed" });

          const isSelect = guardResult.operation === "SELECT";
          if (this.enableReadReplicaRouting && this.readReplicaHost && isSelect) {
            this.stats.routedToReplica++;
          } else {
            this.stats.routedToPrimary++;
          }

          forwardToUpstream(packet.raw);
        } else {
          // Handshake, authentication, ping, or status packet
          forwardToUpstream(packet.raw);
        }
      }
    });
  }
}
