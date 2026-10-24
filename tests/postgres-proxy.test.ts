import assert from "node:assert/strict";
import net from "node:net";
import test from "node:test";
import { DEFAULT_CONFIG } from "../src/config/index.js";
import {
  PostgresWireProxy,
  encodeErrorResponse,
  encodeNoticeResponse,
  encodeReadyForQuery,
  encodeSslDenial,
  extractSqlFromPayload,
  isSslRequest,
  isStartupMessage,
  parseFrontendFrame,
  parseStartupParams,
} from "../src/proxy/index.js";

// Helper: build a Frontend Query ('Q') packet
function buildQueryPacket(sql: string): Buffer {
  const sqlBuf = Buffer.from(`${sql}\0`, "utf8");
  const header = Buffer.alloc(5);
  header.writeUInt8(0x51, 0); // 'Q'
  header.writeInt32BE(sqlBuf.length + 4, 1);
  return Buffer.concat([header, sqlBuf]);
}

// Helper: build a Frontend Parse ('P') packet
function buildParsePacket(name: string, sql: string): Buffer {
  const nameBuf = Buffer.from(`${name}\0`, "utf8");
  const sqlBuf = Buffer.from(`${sql}\0`, "utf8");
  const paramCountBuf = Buffer.alloc(2); // 0 params
  const payload = Buffer.concat([nameBuf, sqlBuf, paramCountBuf]);

  const header = Buffer.alloc(5);
  header.writeUInt8(0x50, 0); // 'P'
  header.writeInt32BE(payload.length + 4, 1);
  return Buffer.concat([header, payload]);
}

// Helper: build a Frontend Sync ('S') packet
function buildSyncPacket(): Buffer {
  const buf = Buffer.alloc(5);
  buf.writeUInt8(0x53, 0); // 'S'
  buf.writeInt32BE(4, 1);
  return buf;
}

// Helper: build an SSLRequest packet
function buildSslRequestPacket(): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeInt32BE(8, 0);
  buf.writeInt32BE(80877103, 4);
  return buf;
}

// Helper: build a standard StartupMessage packet
function buildStartupPacket(user = "postgres", database = "testdb"): Buffer {
  const params = `user\0${user}\0database\0${database}\0\0`;
  const body = Buffer.from(params, "utf8");
  const totalLength = 8 + body.length;
  const header = Buffer.alloc(8);
  header.writeInt32BE(totalLength, 0);
  header.writeInt32BE(196608, 4); // v3.0
  return Buffer.concat([header, body]);
}

// Helper: parse ErrorResponse body into fields
function parseErrorResponseBody(buf: Buffer): Record<string, string> {
  const fields: Record<string, string> = {};
  if (buf[0] !== 0x45) return fields; // Not 'E'
  let offset = 5;
  while (offset < buf.length) {
    const code = String.fromCharCode(buf[offset]);
    offset++;
    if (code === "\0") break;
    const nullIdx = buf.indexOf(0, offset);
    if (nullIdx === -1) break;
    const value = buf.toString("utf8", offset, nullIdx);
    fields[code] = value;
    offset = nullIdx + 1;
  }
  return fields;
}

test("Postgres Protocol - SSLRequest detection and denial", () => {
  const sslPacket = buildSslRequestPacket();
  assert.equal(isSslRequest(sslPacket), true);

  const denial = encodeSslDenial();
  assert.equal(denial.length, 1);
  assert.equal(denial.toString("ascii"), "N");
});

test("Postgres Protocol - StartupMessage parsing and parameters extraction", () => {
  const startup = buildStartupPacket("agent_admin", "ecommerce_db");
  assert.equal(isStartupMessage(startup), true);

  const params = parseStartupParams(startup);
  assert.equal(params.user, "agent_admin");
  assert.equal(params.database, "ecommerce_db");
});

test("Postgres Protocol - ErrorResponse packet serialization", () => {
  const errorBuf = encodeErrorResponse({
    severity: "ERROR",
    code: "42501",
    message: "[DBSHIELD_INTERCEPTED] Destructive DROP TABLE blocked",
    detail: "Safety Tier: BALANCED",
    hint: "Use safe migration pattern",
  });

  assert.equal(errorBuf[0], 0x45); // 'E'
  const length = errorBuf.readInt32BE(1);
  assert.equal(errorBuf.length, 1 + length);

  const fields = parseErrorResponseBody(errorBuf);
  assert.equal(fields.S, "ERROR");
  assert.equal(fields.C, "42501");
  assert.ok(fields.M.includes("Destructive DROP TABLE blocked"));
  assert.ok(fields.D.includes("BALANCED"));
  assert.ok(fields.H.includes("Use safe migration pattern"));
});

test("Postgres Protocol - ReadyForQuery packet serialization", () => {
  const rfq = encodeReadyForQuery("I");
  assert.equal(rfq.length, 6);
  assert.equal(rfq[0], 0x5a); // 'Z'
  assert.equal(rfq.readInt32BE(1), 5);
  assert.equal(rfq[5], 0x49); // 'I'
});

test("Postgres Protocol - NoticeResponse packet serialization", () => {
  const notice = encodeNoticeResponse("Test warning notice", "Extra detail");
  assert.equal(notice[0], 0x4e); // 'N'
  assert.ok(notice.toString("utf8").includes("Test warning notice"));
});

test("Postgres Protocol - Frontend frame parser decodes Query and Parse packets", () => {
  const queryBuf = buildQueryPacket("SELECT id, name FROM users;");
  const parsedQ = parseFrontendFrame(queryBuf, false);
  assert.ok(parsedQ);
  assert.equal(parsedQ.message.type, "Query");
  const sqlQ = extractSqlFromPayload("Query", parsedQ.message.payload);
  assert.equal(sqlQ, "SELECT id, name FROM users;");

  const parseBuf = buildParsePacket("prep1", "SELECT * FROM orders WHERE id = $1;");
  const parsedP = parseFrontendFrame(parseBuf, false);
  assert.ok(parsedP);
  assert.equal(parsedP.message.type, "Parse");
  const sqlP = extractSqlFromPayload("Parse", parsedP.message.payload);
  assert.equal(sqlP, "SELECT * FROM orders WHERE id = $1;");
});

test("PostgresWireProxy - End-to-end TCP interceptor workflow", async () => {
  const upstreamPort = 19532;
  const proxyPort = 19533;

  // 1. Launch Mock Upstream PostgreSQL Server
  let receivedUpstreamQueries: string[] = [];
  const upstreamSockets = new Set<net.Socket>();
  const upstreamServer = net.createServer((socket) => {
    socket.unref();
    upstreamSockets.add(socket);
    socket.on("close", () => upstreamSockets.delete(socket));
    let buf = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      // If startup message arrives, send ReadyForQuery
      if (isStartupMessage(buf)) {
        buf = Buffer.alloc(0);
        socket.write(encodeReadyForQuery("I"));
        return;
      }

      // If query arrives, capture SQL and reply with CommandComplete + ReadyForQuery
      const parsed = parseFrontendFrame(buf, false);
      if (parsed) {
        buf = buf.subarray(parsed.bytesConsumed);
        if (parsed.message.type === "Query") {
          const sql = extractSqlFromPayload("Query", parsed.message.payload);
          if (sql) receivedUpstreamQueries.push(sql);

          // CommandComplete ('C'): 'SELECT 1\0'
          const ccPayload = Buffer.from("SELECT 1\0", "utf8");
          const ccHeader = Buffer.alloc(5);
          ccHeader.writeUInt8(0x43, 0); // 'C'
          ccHeader.writeInt32BE(ccPayload.length + 4, 1);
          const ccPacket = Buffer.concat([ccHeader, ccPayload]);

          socket.write(Buffer.concat([ccPacket, encodeReadyForQuery("I")]));
        }
      }
    });
  });

  await new Promise<void>((resolve) => upstreamServer.listen(upstreamPort, "127.0.0.1", resolve));
  upstreamServer.unref();

  // 2. Launch DBShield PostgresWireProxy
  const proxy = new PostgresWireProxy({
    listenPort: proxyPort,
    listenHost: "127.0.0.1",
    upstreamHost: "127.0.0.1",
    upstreamPort,
    config: {
      ...DEFAULT_CONFIG,
      safetyTier: "BALANCED",
      allowDestructiveDDL: false,
    },
  });

  await proxy.start();
  let client: net.Socket | null = null;

  try {
    // 3. Connect Mock Client to DBShield Proxy
    client = new net.Socket();
    client.unref();
    const receivedClientPackets: Buffer[] = [];

    await new Promise<void>((resolve) => {
      client.connect(proxyPort, "127.0.0.1", resolve);
    });

    client.on("data", (chunk) => {
      receivedClientPackets.push(chunk);
    });

    try {
      // Test A: SSLRequest negotiation
      client.write(buildSslRequestPacket());
      await new Promise((r) => setTimeout(r, 60));
      assert.equal(receivedClientPackets.length, 1);
      assert.equal(receivedClientPackets[0].toString("ascii"), "N"); // SSL Denied, client continues

      // Test B: Handshake with StartupMessage
      receivedClientPackets.length = 0;
      client.write(buildStartupPacket());
      await new Promise((r) => setTimeout(r, 60));
      const rfqReceived = Buffer.concat(receivedClientPackets);
      assert.ok(rfqReceived.includes(0x5a)); // 'Z' ReadyForQuery

      // Test C: Safe Query passthrough
      receivedClientPackets.length = 0;
      receivedUpstreamQueries = [];
      client.write(buildQueryPacket("SELECT id, name FROM users WHERE id = 1;"));
      await new Promise((r) => setTimeout(r, 80));

      assert.equal(receivedUpstreamQueries.length, 1);
      assert.equal(receivedUpstreamQueries[0], "SELECT id, name FROM users WHERE id = 1;");
      const statsAfterSafe = proxy.getStats();
      assert.equal(statsAfterSafe.queriesAllowed, 1);

      // Test D: Intercept Destructive DDL (DROP TABLE)
      receivedClientPackets.length = 0;
      receivedUpstreamQueries = [];
      client.write(buildQueryPacket("DROP TABLE users;"));
      await new Promise((r) => setTimeout(r, 80));

      // Must NOT reach upstream PostgreSQL
      assert.equal(receivedUpstreamQueries.length, 0);

      // Client receives native Postgres ErrorResponse ('E') and ReadyForQuery ('Z')
      const combined = Buffer.concat(receivedClientPackets);
      assert.equal(combined[0], 0x45); // 'E'
      const errorFields = parseErrorResponseBody(combined);
      assert.equal(errorFields.C, "42501");
      assert.ok(errorFields.M.includes("[DBSHIELD_INTERCEPTED]"));
      assert.ok(errorFields.M.includes("DROP") || errorFields.M.includes("DDL_DROP"));
      assert.ok(combined.includes(0x5a)); // Contains 'Z' ReadyForQuery

      const statsAfterIntercept = proxy.getStats();
      assert.equal(statsAfterIntercept.queriesIntercepted, 1);

      // Test E: Intercept Unconstrained UPDATE (Blast Radius Protection)
      receivedClientPackets.length = 0;
      receivedUpstreamQueries = [];
      client.write(buildQueryPacket("UPDATE users SET is_active = true;"));
      await new Promise((r) => setTimeout(r, 80));

      assert.equal(receivedUpstreamQueries.length, 0); // Blocked before upstream
      const errUnconstrained = parseErrorResponseBody(Buffer.concat(receivedClientPackets));
      assert.equal(errUnconstrained.C, "42501");
      assert.ok(errUnconstrained.M.includes("WHERE"));

      // Test F: Intercept Forbidden Parse in Extended Query Protocol
      receivedClientPackets.length = 0;
      client.write(buildParsePacket("stmt_bad", "TRUNCATE TABLE accounts;"));
      client.write(buildSyncPacket());
      await new Promise((r) => setTimeout(r, 80));

      const errParse = parseErrorResponseBody(Buffer.concat(receivedClientPackets));
      assert.equal(errParse.C, "42501");
      assert.ok(errParse.M.includes("TRUNCATE") || errParse.M.includes("DDL_TRUNCATE"));

      client.destroy();
    } catch (err) {
      console.error("DIAGNOSTIC FAILURE IN TEST:", err);
      throw err;
    }
  } finally {
    if (client && !client.destroyed) client.destroy();
    for (const s of upstreamSockets) {
      if (!s.destroyed) s.destroy();
    }
    upstreamSockets.clear();
    await proxy.stop();
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => resolve(), 300);
      upstreamServer.close(() => {
        clearTimeout(timer);
        resolve();
      });
    });
  }
});
