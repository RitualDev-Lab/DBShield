# Contributing to DBShield

Thank you for your interest in contributing to **DBShield**! We welcome contributions from database architects, security engineers, and AI practitioners.

---

## 🛠️ Development Setup

DBShield is built with Node.js 20+, TypeScript, ESM, and pnpm/npm.

```bash
# 1. Clone your fork
git clone https://github.com/<your-username>/DBShield.git
cd DBShield

# 2. Install dependencies
pnpm install

# 3. Build project
pnpm run build

# 4. Run full test suite
pnpm test
```

---

## 📐 Guidelines

### 1. Code Standards & Tooling
- We use [Biome](https://biomejs.dev/) for ultra-fast linting and code formatting:
  ```bash
  pnpm run lint
  pnpm run format
  pnpm run check
  ```
- All code must pass Biome checks with 0 errors before opening a PR.

### 2. Zero-Telemetry & Air-Gapped Invariants
- DBShield must NEVER phone home, make unsolicited outbound telemetry calls, or leak database contents.
- All testing databases must use local in-memory SQLite, local PostgreSQL instances, or mock connection sockets.

### 3. Submitting Pull Requests
1. Fork the repo and create your feature branch: `git checkout -b feat/my-improvement`.
2. Ensure all tests pass: `pnpm test`.
3. Verify Biome checks: `pnpm run check`.
4. Open a PR against `main` on `RitualDev-Lab/DBShield`.
5. Maintain clear semantic commits (`feat:`, `fix:`, `docs:`, `perf:`).

---

## 🔒 Security Vulnerabilities

Please do NOT report security vulnerabilities via public GitHub issues. Follow the instructions in [SECURITY.md](SECURITY.md) or email `security@ritualdev.in`.
