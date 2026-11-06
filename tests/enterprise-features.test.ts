import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { runAuditScan } from "../src/audit-scanner.js";
import { installAntigravity, installWindsurf } from "../src/configurator/index.js";
import { getTopMonitorSnapshot } from "../src/top-monitor.js";

test("Audit Scanner - Detects destructive DDL and unconstrained mutations", async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "dbshield-audit-test-"));
  const hazardFile = path.join(tmpDir, "001_destructive.sql");
  await fs.writeFile(
    hazardFile,
    `
    -- Some migration
    ALTER TABLE users ADD COLUMN age INT;
    DROP TABLE customers;
    DELETE FROM sessions WHERE 1=1;
    `,
    "utf8",
  );

  const report = await runAuditScan(tmpDir);
  assert.equal(report.scannedFiles, 1);
  assert.ok(report.hazards.length >= 2);
  assert.equal(report.passed, false);
  assert.ok(report.hazards.some((h) => h.category === "DESTRUCTIVE_DDL"));
  assert.ok(report.hazards.some((h) => h.category === "TAUTOLOGY"));

  await fs.rm(tmpDir, { recursive: true, force: true });
});

test("Top Monitor - Returns healthy snapshot with active isolation and shadow tokens", () => {
  const snapshot = getTopMonitorSnapshot("BALANCED");
  assert.equal(snapshot.version, "0.2.0");
  assert.equal(snapshot.safetyTier, "BALANCED");
  assert.equal(snapshot.proxyListenPort, 5433);
  assert.ok(snapshot.activeSessions.length > 0);
  assert.ok(snapshot.stats.totalQueriesProcessed > 0);
  assert.ok(snapshot.stats.avgProxyLatencyMs < 0.42);
});

test("Configurator - Antigravity MCP Auto-Configuration", async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "dbshield-antigravity-test-"));
  const res = await installAntigravity(tmpDir);

  assert.equal(res.success, true);
  assert.ok(res.configPath.includes(".antigravity"));
  const content = JSON.parse(await fs.readFile(res.configPath, "utf8"));
  assert.ok(content.mcpServers.dbshield);
  assert.equal(content.mcpServers.dbshield.command, "npx");

  await fs.rm(tmpDir, { recursive: true, force: true });
});
