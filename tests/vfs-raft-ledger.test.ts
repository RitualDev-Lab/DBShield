import assert from "node:assert/strict";
import crypto from "node:crypto";
import { describe, it } from "node:test";
import { AuditLogger, HmacAuditLedger } from "../src/audit/index.js";
import {
  type AppendEntriesArgs,
  type AppendEntriesReply,
  RaftConsensusCoordinator,
  type RequestVoteArgs,
  type RequestVoteReply,
} from "../src/sandbox/raft-consensus.js";
import { SqliteVfsShim } from "../src/sandbox/sqlite-vfs-shim.js";

describe("Phase 3: DBShield High Availability, SQLite VFS Shim & Append-Only HMAC Ledger", () => {
  describe("SQLite Virtual File System (VFS) Shim", () => {
    it("allows page read and write operations for an authorized proxy session", () => {
      const shim = new SqliteVfsShim(4096);
      const sessionId = "proxy_sess_99182";
      shim.registerAuthorizedSession(sessionId);

      const handle = shim.openFile("test_database.sqlite", false, {
        proxySessionId: sessionId,
      });

      // Construct a valid SQLite page 1 (header + dummy btree payload)
      const page1Buf = Buffer.alloc(4096);
      page1Buf.write("SQLite format 3\0", 0, 16, "utf8");
      page1Buf.writeUInt16BE(4096, 16); // Page size

      const writeRes = shim.interceptPageWrite(handle, 1, page1Buf, {
        proxySessionId: sessionId,
      });

      assert.equal(writeRes.allowed, true);
      assert.equal(writeRes.pageNumber, 1);
      assert.ok(writeRes.checksum.length === 64);

      // Read back page 1
      const readRes = shim.interceptPageRead(handle, 1, page1Buf, {
        proxySessionId: sessionId,
      });
      assert.equal(readRes.allowed, true);
      assert.equal(readRes.checksum, writeRes.checksum);

      shim.closeFile(handle);
    });

    it("blocks direct unbrokered filesystem writes attempting to bypass wire proxy", () => {
      const shim = new SqliteVfsShim(4096);
      const handle = shim.openFile("unprotected_db.sqlite");

      const page2Buf = Buffer.alloc(4096, 0xaa);

      assert.throws(
        () => {
          // Attempt write without authorized proxySessionId or maintenance token
          shim.interceptPageWrite(handle, 2, page2Buf, {
            actorId: "autonomous_agent_rogue",
          });
        },
        (err: Error) => {
          return (
            err.message.includes("UNAUTHORIZED_DIRECT_FS_WRITE") &&
            err.message.includes("wire proxy session")
          );
        },
      );

      const auditTrail = shim.getAuditTrail();
      const blockedEvent = auditTrail.find((e) => e.decision.allowed === false);
      assert.ok(blockedEvent);
      assert.equal(blockedEvent?.decision.violationCode, "UNAUTHORIZED_DIRECT_FS_WRITE");
    });

    it("strictly blocks page writes when under read-only envelope or dry-run mode", () => {
      const shim = new SqliteVfsShim(4096);
      const sessionId = "sess_readonly_123";
      shim.registerAuthorizedSession(sessionId);

      const handle = shim.openFile("production_db.sqlite", true, {
        proxySessionId: sessionId,
        isReadOnly: true,
      });

      const dummyPage = Buffer.alloc(4096, 0xbb);

      assert.throws(
        () => {
          shim.interceptPageWrite(handle, 3, dummyPage, {
            proxySessionId: sessionId,
            isReadOnly: true,
          });
        },
        (err: Error) => {
          return err.message.includes("READONLY_ENVELOPE_VIOLATION");
        },
      );
    });

    it("detects and rejects corrupted or forged SQLite Page 1 magic header", () => {
      const shim = new SqliteVfsShim(4096);
      const sessionId = "sess_tamper_chk";
      shim.registerAuthorizedSession(sessionId);

      const handle = shim.openFile("tamper_test.sqlite", false, {
        proxySessionId: sessionId,
      });

      const corruptedPage1 = Buffer.alloc(4096);
      corruptedPage1.write("MALICIOUS_HEADER", 0, 16, "utf8");

      assert.throws(
        () => {
          shim.interceptPageWrite(handle, 1, corruptedPage1, {
            proxySessionId: sessionId,
          });
        },
        (err: Error) => {
          return err.message.includes("HEADER_TAMPER_DETECTED");
        },
      );
    });

    it("verifies page cryptographic integrity and identifies out-of-band tampered pages", () => {
      const shim = new SqliteVfsShim(4096);
      const sessionId = "sess_integ_chk";
      shim.registerAuthorizedSession(sessionId);

      const handle = shim.openFile("integrity_test.sqlite", false, {
        proxySessionId: sessionId,
      });

      const page1 = Buffer.alloc(4096);
      page1.write("SQLite format 3\0", 0, 16, "utf8");
      const page2 = Buffer.alloc(4096, 0x11);
      const page3 = Buffer.alloc(4096, 0x22);

      shim.interceptPageWrite(handle, 1, page1, { proxySessionId: sessionId });
      shim.interceptPageWrite(handle, 2, page2, { proxySessionId: sessionId });
      shim.interceptPageWrite(handle, 3, page3, { proxySessionId: sessionId });

      // Simulate on-disk pages
      const diskPages = new Map<number, Buffer>();
      diskPages.set(1, Buffer.from(page1));
      diskPages.set(2, Buffer.from(page2));
      diskPages.set(3, Buffer.from(page3));

      let integrity = shim.verifyPageIntegrity(handle.fileId, diskPages);
      assert.equal(integrity.valid, true);
      assert.equal(integrity.tamperedPages.length, 0);

      // Tamper page 2 on disk directly
      diskPages.set(2, Buffer.alloc(4096, 0x99));
      integrity = shim.verifyPageIntegrity(handle.fileId, diskPages);
      assert.equal(integrity.valid, false);
      assert.deepEqual(integrity.tamperedPages, [2]);
    });
  });

  describe("Raft Consensus & Distributed Transaction Coordinator", () => {
    it("single node self-elects and commits commands with monotonic fencing tokens", async () => {
      const coord = new RaftConsensusCoordinator({
        nodeId: "proxy_node_1",
      });

      const lease = await coord.acquireDistributedLease("users_table", "agent_worker_1", 3000);
      assert.equal(lease.acquired, true);
      assert.ok(lease.fenceToken >= 1000);
      assert.equal(lease.ownerId, "agent_worker_1");

      // Verify mutual exclusion: another worker fails to acquire the same resource
      const conflict = await coord.acquireDistributedLease("users_table", "agent_worker_2", 3000);
      assert.equal(conflict.acquired, false);
      assert.equal(conflict.ownerId, "agent_worker_1");

      // Release lease
      const released = await coord.releaseDistributedLease("users_table", "agent_worker_1");
      assert.equal(released, true);

      // Now agent 2 can acquire
      const lease2 = await coord.acquireDistributedLease("users_table", "agent_worker_2", 3000);
      assert.equal(lease2.acquired, true);
      assert.ok(lease2.fenceToken > lease.fenceToken);

      coord.stop();
    });

    it("coordinates multi-replica consensus quorum and 2PC transaction voting", async () => {
      // Setup 3-node cluster: nodeA, nodeB, nodeC
      const nodeA = new RaftConsensusCoordinator({ nodeId: "nodeA", peers: ["nodeB", "nodeC"] });
      const nodeB = new RaftConsensusCoordinator({ nodeId: "nodeB", peers: ["nodeA", "nodeC"] });
      const nodeC = new RaftConsensusCoordinator({ nodeId: "nodeC", peers: ["nodeA", "nodeB"] });

      const clusterMap: Record<string, RaftConsensusCoordinator> = { nodeA, nodeB, nodeC };

      // In-memory peer transport router
      const dispatchTransport = async (
        targetId: string,
        rpc: "RequestVote" | "AppendEntries",
        payload: RequestVoteArgs | AppendEntriesArgs,
      ): Promise<RequestVoteReply | AppendEntriesReply | null> => {
        const target = clusterMap[targetId];
        if (!target) return null;
        if (rpc === "RequestVote") {
          return target.handleRequestVote(payload as RequestVoteArgs);
        }
        return target.handleAppendEntries(payload as AppendEntriesArgs);
      };

      nodeA.setPeerTransport(dispatchTransport);
      nodeB.setPeerTransport(dispatchTransport);
      nodeC.setPeerTransport(dispatchTransport);

      // nodeA runs election and becomes leader
      await nodeA.startElection();
      assert.equal(nodeA.role, "LEADER");

      // Propose 2PC transaction prepare
      const prepared = await nodeA.prepareDistributedTransaction(
        "tx_9920",
        "accounts_table",
        "worker_x",
      );
      assert.equal(prepared, true);

      // Commit 2PC transaction
      const committed = await nodeA.commitDistributedTransaction(
        "tx_9920",
        "accounts_table",
        "worker_x",
      );
      assert.equal(committed, true);

      // Verify nodeB and nodeC replicated entries
      assert.ok(nodeB.log.length >= 2);
      assert.ok(nodeC.log.length >= 2);

      nodeA.stop();
      nodeB.stop();
      nodeC.stop();
    });
  });

  describe("Append-Only HMAC-SHA256 Audit Ledger (PCI-DSS v4.0 Req 10 & SOC 2 CC6.8)", () => {
    it("appends audit events with HMAC-SHA256 signatures and validates tamper-evident chain", async () => {
      const ledger = new HmacAuditLedger({
        secretKey: "super_secret_audit_key_32bytes_min",
        keyId: "primary_key_v1",
      });

      await ledger.append({
        auditId: "aud_001",
        actor: "agent_analyst",
        database: "finance_prod",
        operation: "SELECT",
        status: "SUCCESS",
        riskLevel: "LOW",
        riskScore: 5,
        sql: "SELECT balance FROM customer_accounts WHERE id = 101;",
      });

      await ledger.append({
        auditId: "aud_002",
        actor: "agent_reconciler",
        database: "finance_prod",
        operation: "UPDATE",
        status: "COMMITTED",
        riskLevel: "MEDIUM",
        riskScore: 40,
        sql: "UPDATE customer_accounts SET reconciled = true WHERE id = 101;",
      });

      await ledger.append({
        auditId: "aud_003",
        actor: "agent_attacker",
        database: "finance_prod",
        operation: "DROP",
        status: "BLOCKED",
        riskLevel: "CRITICAL",
        riskScore: 100,
        sql: "DROP TABLE customer_accounts;",
      });

      assert.equal(ledger.length, 3);
      const verification = ledger.verifyLedgerIntegrity();
      assert.equal(verification.valid, true);
      assert.equal(verification.totalEntries, 3);
      assert.ok(verification.headHmac.length === 64);
      assert.ok(verification.tailHmac === HmacAuditLedger.GENESIS_HMAC);

      // Verify Merkle tree root hash generation
      const merkleRoot = ledger.computeMerkleRoot();
      assert.ok(merkleRoot.length === 64);
      assert.notEqual(merkleRoot, HmacAuditLedger.GENESIS_HMAC);
    });

    it("detects tampered query payload or modified SQL text at exact index", async () => {
      const ledger = new HmacAuditLedger({
        secretKey: "test_tamper_audit_secret_key",
      });

      await ledger.append({
        auditId: "ev_1",
        actor: "user_a",
        operation: "SELECT",
        status: "SUCCESS",
        riskLevel: "LOW",
        riskScore: 0,
        sql: "SELECT 1;",
      });

      await ledger.append({
        auditId: "ev_2",
        actor: "user_b",
        operation: "UPDATE",
        status: "COMMITTED",
        riskLevel: "HIGH",
        riskScore: 75,
        sql: "UPDATE payroll SET salary = 200000 WHERE id = 1;",
      });

      // Tamper second entry's SQL in memory
      const entries = ledger.getEntries();
      // @ts-expect-error - deliberate test tampering
      entries[1].sql = "UPDATE payroll SET salary = 1000000 WHERE id = 1;";

      const result = ledger.verifyLedgerIntegrity();
      assert.equal(result.valid, false);
      assert.equal(result.brokenAtIndex, 1);
      assert.equal(result.brokenReason, "PAYLOAD_HASH_MISMATCH");
    });

    it("detects tampered entry HMAC or dropped sequence entry", async () => {
      const ledger = new HmacAuditLedger({
        secretKey: "test_seq_audit_secret_key",
      });

      await ledger.append({
        auditId: "ev_10",
        operation: "SELECT",
        status: "SUCCESS",
        riskLevel: "LOW",
        riskScore: 0,
        sql: "SELECT * FROM items;",
      });

      await ledger.append({
        auditId: "ev_11",
        operation: "SELECT",
        status: "SUCCESS",
        riskLevel: "LOW",
        riskScore: 0,
        sql: "SELECT * FROM orders;",
      });

      await ledger.append({
        auditId: "ev_12",
        operation: "DELETE",
        status: "COMMITTED",
        riskLevel: "HIGH",
        riskScore: 80,
        sql: "DELETE FROM orders WHERE id = 5;",
      });

      // Simulate attacker dropping event 11 directly in ledger storage
      const internalEntries = (ledger as unknown as { entries: unknown[] }).entries;
      internalEntries.splice(1, 1);

      const result = ledger.verifyLedgerIntegrity();
      assert.equal(result.valid, false);
      assert.equal(result.brokenAtIndex, 1);
      assert.equal(result.brokenReason, "SEQUENCE_GAP");
    });

    it("integrates seamlessly into AuditLogger with enableHmacLedger", async () => {
      const logger = new AuditLogger();
      const hmacLedger = logger.enableHmacLedger({
        secretKey: "audit_logger_integration_key",
      });

      await logger.log({
        auditId: "log_int_1",
        timestamp: new Date().toISOString(),
        sql: "SELECT * FROM test_table;",
        operation: "SELECT",
        status: "SUCCESS",
        riskLevel: "LOW",
        riskScore: 10,
      });

      await logger.log({
        auditId: "log_int_2",
        timestamp: new Date().toISOString(),
        sql: "INSERT INTO test_table VALUES (1, 'val');",
        operation: "INSERT",
        status: "COMMITTED",
        riskLevel: "MEDIUM",
        riskScore: 30,
      });

      assert.equal(hmacLedger.length, 2);
      const v = hmacLedger.verifyLedgerIntegrity();
      assert.equal(v.valid, true);
      assert.equal(v.totalEntries, 2);
    });
  });
});
