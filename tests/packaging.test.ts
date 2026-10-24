import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("Packaging - CLI Subcommands (init, status, help) and Tarball Verification", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dbshield-pack-test-"));

  // 1. Test 'init' in fresh directory
  const initOutput = execSync(`"${process.execPath}" "${path.resolve("dist/cli.js")}" init`, {
    cwd: tempDir,
    encoding: "utf8",
  });
  assert.ok(initOutput.includes("Created dbshield.config.json"));

  const configPath = path.join(tempDir, "dbshield.config.json");
  const configRaw = await fs.readFile(configPath, "utf8");
  const parsed = JSON.parse(configRaw);
  assert.equal(parsed.dialect, "sqlite");
  assert.equal(parsed.safetyTier, "BALANCED");

  // 2. Test 'status' in that directory
  const statusOutput = execSync(`"${process.execPath}" "${path.resolve("dist/cli.js")}" status`, {
    cwd: tempDir,
    encoding: "utf8",
  });
  assert.ok(statusOutput.includes("DBShield Security Gateway Status"));
  assert.ok(statusOutput.includes("Dialect:"));
  assert.ok(statusOutput.includes("sqlite"));
  assert.ok(statusOutput.includes("BALANCED"));

  // 3. Test pack dry-run returns valid tarball without error
  const packOutput = execSync("npm pack --dry-run --json", {
    encoding: "utf8",
  });
  const jsonStart = packOutput.indexOf("[");
  assert.ok(jsonStart !== -1, "npm pack must output json array");
  const packInfo = JSON.parse(packOutput.slice(jsonStart))[0];
  assert.equal(packInfo.name, "@ritualdev-lab/dbshield");
  const packedFiles = packInfo.files.map((f: { path: string }) => f.path);
  assert.ok(packedFiles.includes("dist/cli.js"));
  assert.ok(packedFiles.includes("dist/index.js"));
  assert.ok(packedFiles.includes("README.md"));
  assert.ok(packedFiles.includes("LICENSE"));

  await fs.rm(tempDir, { recursive: true, force: true });
});

test("Packaging - Docker Container Multi-Stage & Security Hardening Verification", async () => {
  const dockerfilePath = path.resolve("Dockerfile");
  const dockerfileContent = await fs.readFile(dockerfilePath, "utf8");

  // Verify multi-stage build
  assert.ok(dockerfileContent.includes("AS builder"));
  assert.ok(dockerfileContent.includes("AS runtime"));

  // Verify unprivileged non-root user
  assert.ok(dockerfileContent.includes("10001"));
  assert.ok(dockerfileContent.includes("USER 10001:10001"));

  // Verify exposed ports
  assert.ok(dockerfileContent.includes("EXPOSE 5433 9090"));

  // Verify container health check
  assert.ok(dockerfileContent.includes("HEALTHCHECK"));
  assert.ok(dockerfileContent.includes("http://127.0.0.1:9090/healthz"));

  // Verify .dockerignore
  const dockerignoreContent = await fs.readFile(path.resolve(".dockerignore"), "utf8");
  assert.ok(dockerignoreContent.includes("node_modules"));
  assert.ok(dockerignoreContent.includes(".git"));
  assert.ok(dockerignoreContent.includes("coverage"));

  // Verify docker-compose.yml
  const composeContent = await fs.readFile(path.resolve("docker-compose.yml"), "utf8");
  assert.ok(composeContent.includes("dbshield-postgres"));
  assert.ok(composeContent.includes("dbshield-proxy"));
  assert.ok(composeContent.includes("dbshield-prometheus"));
  assert.ok(composeContent.includes('DBSHIELD_ENABLE_METRICS: "true"'));
});

test("Packaging - Kubernetes Helm Chart Schema & Templates Verification", async () => {
  const chartPath = path.resolve("charts/dbshield/Chart.yaml");
  const chartContent = await fs.readFile(chartPath, "utf8");
  assert.ok(chartContent.includes("apiVersion: v2"));
  assert.ok(chartContent.includes("name: dbshield"));
  assert.ok(chartContent.includes("version: 0.2.0"));

  const valuesPath = path.resolve("charts/dbshield/values.yaml");
  const valuesContent = await fs.readFile(valuesPath, "utf8");
  assert.ok(valuesContent.includes("replicaCount: 2"));
  assert.ok(valuesContent.includes("upstreamHost:"));
  assert.ok(valuesContent.includes('safetyTier: "BALANCED"'));
  assert.ok(valuesContent.includes("serviceMonitor:"));
  assert.ok(valuesContent.includes("autoscaling:"));

  // Verify all template files exist
  const templateFiles = [
    "deployment.yaml",
    "service.yaml",
    "configmap.yaml",
    "servicemonitor.yaml",
    "hpa.yaml",
    "serviceaccount.yaml",
    "_helpers.tpl",
    "NOTES.txt",
  ];

  for (const tpl of templateFiles) {
    const tplPath = path.resolve("charts/dbshield/templates", tpl);
    const stat = await fs.stat(tplPath);
    assert.ok(stat.isFile(), `Template file ${tpl} must exist`);
  }
});
