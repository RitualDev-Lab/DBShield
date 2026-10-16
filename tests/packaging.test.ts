import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("Packaging - CLI Subcommands (init, status, help) and Tarball Verification", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "dbshield-pack-test-"));

  // 1. Test 'init' in fresh directory
  const initOutput = execSync(`node ${path.resolve("dist/cli.js")} init`, {
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
  const statusOutput = execSync(`node ${path.resolve("dist/cli.js")} status`, {
    cwd: tempDir,
    encoding: "utf8",
  });
  assert.ok(statusOutput.includes("DBShield Security Gateway Status"));
  assert.ok(statusOutput.includes("Dialect:"));
  assert.ok(statusOutput.includes("sqlite"));
  assert.ok(statusOutput.includes("BALANCED"));

  // 3. Test pack dry-run returns valid tarball without error
  const packOutput = execSync("pnpm pack --dry-run", {
    encoding: "utf8",
  });
  assert.ok(packOutput.includes("@ritualdev-lab/dbshield"));
  assert.ok(packOutput.includes("dist/cli.js"));
  assert.ok(packOutput.includes("dist/index.js"));

  await fs.rm(tempDir, { recursive: true, force: true });
});
