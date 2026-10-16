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
