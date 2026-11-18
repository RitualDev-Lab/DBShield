import assert from "node:assert/strict";
import net from "node:net";
import test from "node:test";
import { ReplayProofApprovalTokenManager } from "../src/approval/replay-guard.js";
import {
  parseBindMessage,
  parseExecuteMessage,
  parseParseMessage,
  reconstructParameterizedSql,
} from "../src/proxy/protocol.js";
import { PostgresWireProxy } from "../src/proxy/server.js";

function encodeStartupPacket(user = "agent", database = "prod"): Buffer {
  const body = Buffer.from(`user\0${user}\0database\0${database}\0\0`, "utf8");
  const buf = Buffer.alloc(8 + body.length);
  buf.writeInt32BE(8 + body.length, 0);
  buf.writeInt32BE(196608, 4);
  body.copy(buf, 8);
  return buf;
}

function encodeParseFrame(statementName: string, query: string): Buffer {
  const stmtBuf = Buffer.from(`${statementName}\0`, "utf8");
  const queryBuf = Buffer.from(`${query}\0`, "utf8");
  const paramCount = Buffer.alloc(2);
  paramCount.writeInt16BE(0, 0);
  const body = Buffer.concat([stmtBuf, queryBuf, paramCount]);
  const header = Buffer.alloc(5);
  header.writeUInt8(0x50, 0); // 'P'
  header.writeInt32BE(4 + body.length, 1);
  return Buffer.concat([header, body]);
}

function encodeBindFrame(portalName: string, statementName: string, params: string[]): Buffer {
  const parts: Buffer[] = [
    Buffer.from(`${portalName}\0`, "utf8"),
    Buffer.from(`${statementName}\0`, "utf8"),
  ];
  const fmtCount = Buffer.alloc(2);
  fmtCount.writeInt16BE(0, 0);
  parts.push(fmtCount);

  const pCount = Buffer.alloc(2);
  pCount.writeInt16BE(params.length, 0);
  parts.push(pCount);

  for (const p of params) {
    const valBuf = Buffer.from(p, "utf8");
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeInt32BE(valBuf.length, 0);
    parts.push(lenBuf, valBuf);
  }

  const resFmtCount = Buffer.alloc(2);
  resFmtCount.writeInt16BE(0, 0);
  parts.push(resFmtCount);

  const body = Buffer.concat(parts);
  const header = Buffer.alloc(5);
  header.writeUInt8(0x42, 0); // 'B'
  header.writeInt32BE(4 + body.length, 1);
  return Buffer.concat([header, body]);
}

function encodeExecuteFrame(portalName = "", maxRows = 0): Buffer {
  const portalBuf = Buffer.from(`${portalName}\0`, "utf8");
  const rowsBuf = Buffer.alloc(4);
  rowsBuf.writeInt32BE(maxRows, 0);
  const body = Buffer.concat([portalBuf, rowsBuf]);
  const header = Buffer.alloc(5);
  header.writeUInt8(0x45, 0); // 'E'
  header.writeInt32BE(4 + body.length, 1);
  return Buffer.concat([header, body]);
}

function encodeSyncFrame(): Buffer {
  const buf = Buffer.alloc(5);
  buf.writeUInt8(0x53, 0); // 'S'
  buf.writeInt32BE(4, 1);
  return buf;
}

test("Phase 7 (SEC-08): Decodes PostgreSQL Extended Query P/B/E frames & reconstructs bound SQL", () => {
  const parseFrame = encodeParseFrame("stmt_1", "DELETE FROM orders WHERE status = $1 AND id = $2");
  const parsedP = parseParseMessage(parseFrame.subarray(5));
  assert.deepEqual(parsedP, {
    statementName: "stmt_1",
    query: "DELETE FROM orders WHERE status = $1 AND id = $2",
  });

  const bindFrame = encodeBindFrame("portal_1", "stmt_1", ["archived", "42"]);
  const parsedB = parseBindMessage(bindFrame.subarray(5));
  assert.deepEqual(parsedB, {
    portalName: "portal_1",
    statementName: "stmt_1",
    parameters: ["archived", "42"],
  });

  const reconstructed = reconstructParameterizedSql(parsedP!.query, parsedB!.parameters);
  assert.equal(reconstructed, "DELETE FROM orders WHERE status = 'archived' AND id = 42");

  const execFrame = encodeExecuteFrame("portal_1", 10);
  const parsedE = parseExecuteMessage(execFrame.subarray(5));
  assert.deepEqual(parsedE, { portalName: "portal_1", maxRows: 10 });
});

test("Phase 7 (SEC-08): PostgresWireProxy intercepts destructive Extended Query DROP TABLE & bound tautology", async () => {
  const upstreamReceived: Buffer[] = [];
  const mockUpstream = net.createServer((sock) => {
    sock.on("data", (d) => upstreamReceived.push(d));
  });
  await new Promise<void>((resolve) => mockUpstream.listen(0, "127.0.0.1", resolve));
  const upstreamPort = (mockUpstream.address() as net.AddressInfo).port;

  const proxyPort = 54000 + Math.floor(Math.random() * 5000);
  const proxy = new PostgresWireProxy({
    listenHost: "127.0.0.1",
    listenPort: proxyPort,
    upstreamHost: "127.0.0.1",
    upstreamPort,
    config: {
      dialect: "postgres",
      safetyTier: "STRICT",
      maxRowsPerMutation: 50,
      allowDestructiveDDL: false,
      enablePiiMasking: true,
      customPiiColumns: [],
    },
  });

  await proxy.start();
  try {
    const client = net.createConnection({ host: "127.0.0.1", port: proxyPort });
    const responses: Buffer[] = [];

    await new Promise<void>((resolve, reject) => {
      client.on("connect", () => {
        client.write(encodeStartupPacket());
        // Send ORM-style Extended Query: Parse('DROP TABLE users') + Bind + Execute + Sync
        client.write(encodeParseFrame("orm_drop", "DROP TABLE users;"));
        client.write(encodeBindFrame("p1", "orm_drop", []));
        client.write(encodeExecuteFrame("p1", 0));
        client.write(encodeSyncFrame());
      });
      client.on("data", (d) => {
        responses.push(d);
        const combined = Buffer.concat(responses).toString("utf8");
        if (combined.includes("DBSHIELD_INTERCEPTED")) {
          client.end();
          resolve();
        }
      });
      client.on("error", reject);
      setTimeout(() => reject(new Error("Timed out waiting for proxy ErrorResponse")), 3000);
    });

    const wireText = Buffer.concat(responses).toString("utf8");
    assert.match(wireText, /DBSHIELD_INTERCEPTED/);
    assert.equal(proxy.getStats().queriesIntercepted >= 1, true);
    // Upstream must NEVER receive the DROP TABLE statement
    const upstreamText = Buffer.concat(upstreamReceived).toString("utf8");
    assert.equal(upstreamText.includes("DROP TABLE users"), false);
  } finally {
    await proxy.stop();
    await new Promise<void>((resolve) => mockUpstream.close(() => resolve()));
  }
});

test("Phase 7 (SEC-08): ReplayProofApprovalTokenManager rejects replayed Slack webhooks with 403 Token Already Consumed", () => {
  const mgr = new ReplayProofApprovalTokenManager("test-replay-secret-key", 600);
  const sql = "DELETE FROM sessions WHERE expired = true;";
  const issued = mgr.issueToken({
    requestId: "appr_abc123def456",
    sql,
    dbId: "prod-pg-01",
  });

  // 1st consumption: 200 OK (whitespace/comment normalization preserved)
  const first = mgr.verifyAndConsume(issued.token, {
    requestId: "appr_abc123def456",
    sql: "DELETE   FROM sessions /* cleanup */ WHERE expired = true;",
    dbId: "prod-pg-01",
  });
  assert.equal(first.valid, true);
  assert.equal(first.statusCode, 200);

  // 2nd consumption (Replay Attack): 403 Token Already Consumed
  const replay = mgr.verifyAndConsume(issued.token, {
    requestId: "appr_abc123def456",
    sql,
    dbId: "prod-pg-01",
  });
  assert.equal(replay.valid, false);
  assert.equal(replay.statusCode, 403);
  assert.match(replay.error || "", /403 Token Already Consumed/);

  // Tampered SQL AST rejected with 403
  const fresh = mgr.issueToken({
    requestId: "appr_999",
    sql: "UPDATE users SET role = 'viewer' WHERE id = 5;",
    dbId: "prod-pg-01",
  });
  const tampered = mgr.verifyAndConsume(fresh.token, {
    requestId: "appr_999",
    sql: "UPDATE users SET role = 'superadmin' WHERE id = 5;",
    dbId: "prod-pg-01",
  });
  assert.equal(tampered.valid, false);
  assert.equal(tampered.statusCode, 403);
  assert.match(tampered.error || "", /AST Hash Mismatch/);
});
