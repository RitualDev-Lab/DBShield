# 🚀 DBShield Launch & Release Guide

This guide details the release verification process, packaging standards, and deployment workflow for **DBShield** (`@ritualdev-lab/dbshield`).

---

## 📋 Pre-Flight Verification Checklist

Before publishing any release or bumping versions, execute the full automated verification pipeline:

```bash
# 1. Format & Lint Verification
pnpm run check

# 2. TypeScript Compilation to dist/
pnpm run build

# 3. Complete Test Suite (44 Unit, E2E Protocol & Packaging Tests)
pnpm test

# 4. Dry-Run Tarball Packaging Verification
pnpm pack --dry-run
```

All 44 automated tests across 7 test suites must pass cleanly:
- `architecture.test.ts` (Config loading, adapters, CLI help/version)
- `guardrail.test.ts` (AST inspection, DDL blocking, blind mutations, tautology detection)
- `pii.test.ts` (Credential/secret masking, format-preserving phone/email redaction)
- `sandbox.test.ts` (Auto-rollback transactions, HMAC token verification, TTL expiry)
- `tools-and-cli.test.ts` (Query explainer, audit logger, Claude & Cursor configurators)
- `e2e-protocol.test.ts` (Full MCP client in-memory handshake across all 7 tools)
- `packaging.test.ts` (CLI init, status, and tarball distribution checks)

---

## 📦 Automated Release via GitHub Actions

DBShield features automated publishing via GitHub Actions (`.github/workflows/release.yml`).

### Step 1: Bump Version in `package.json`
```json
{
  "name": "@ritualdev-lab/dbshield",
  "version": "0.1.0"
}
```

### Step 2: Commit and Tag the Release
```bash
git add package.json
git commit -m "chore(release): v0.1.0"
git tag -a v0.1.0 -m "Release v0.1.0: Safety-First Database Guardrail & Sandboxing MCP Server"
git push origin main --tags
```

### Step 3: Automated Pipeline Execution
When a `v*` tag is pushed:
1. Multi-platform testing runs on Node.js 22 & 24.
2. Code style and TypeScript builds are verified.
3. Package is published directly to npm registry with public access.
4. GitHub Release is automatically drafted with changelog notes.

---

## 🛠️ Manual npm Registry Publishing

If publishing manually with an npm authorization token:

```bash
# Verify login
npm whoami

# Build fresh production distribution
pnpm run build

# Publish public package
pnpm publish --access public
```

---

## 💻 1-Click Client Onboarding

Once published to npm or installed locally, users can integrate DBShield with their favorite AI coding assistants in seconds:

### Claude Desktop
```bash
npx @ritualdev-lab/dbshield install-claude
```
*Automatically locates and gracefully merges DBShield into `claude_desktop_config.json` across Windows, macOS, and Linux without disturbing existing MCP servers.*

### Cursor IDE
```bash
npx @ritualdev-lab/dbshield install-cursor
```
*Creates or patches `.cursor/mcp.json` in the current project root.*

### Verification
```bash
# Check connectivity and detected database tables
npx @ritualdev-lab/dbshield status

# Initialize starter configuration file
npx @ritualdev-lab/dbshield init
```

---

## 🛡️ Support & Community
- **GitHub Repository**: [https://github.com/RitualDev-Lab/DBShield](https://github.com/RitualDev-Lab/DBShield)
- **Issue Tracker**: [https://github.com/RitualDev-Lab/DBShield/issues](https://github.com/RitualDev-Lab/DBShield/issues)
- **License**: MIT © [RitualDev Lab](https://github.com/RitualDev-Lab)
