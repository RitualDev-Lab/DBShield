# 🏛️ SOC 2 Type II & ISO/IEC 27001:2022 Compliance Readiness Matrix

> **Document Version**: 1.0.0  
> **Effective Date**: November 2026  
> **Vendor Entity**: RitualDev Lab (`ritualdev.in`)  
> **Applies to**: DBShield Enterprise, Database Guardrail Proxy & MCP Sandboxing Suite  
> **Official Audit Inquiries**: `security@ritualdev.in` | `developer@ritualdev.in`  
> **Trust Portal**: [https://ritualdev.in/trust](https://ritualdev.in/trust)  
> **Enterprise SLA**: [https://ritualdev.in/sla](https://ritualdev.in/sla)  

---

## 1. Executive Summary & Zero-Data-Custody Architecture

DBShield is engineered specifically for enterprise security, compliance, and zero-trust database access by autonomous AI agents (Cursor, Claude Desktop, Antigravity, Windsurf).

Unlike legacy cloud-based database proxies that require tunneling production database connections through third-party multi-tenant SaaS clouds, **DBShield operates with a strictly Local-First and Zero-Data-Custody model**:
- **Zero External Data Retention**: SQL AST parsing, query cost estimation, tautology detection, and PII masking execute 100% locally on customer infrastructure (`127.0.0.1` or inside customer private VPC runners).
- **No Third-Party Telemetry**: Zero lines of SQL queries, table schemas, credentials, or result sets are egressed to RitualDev cloud endpoints.
- **Cryptographic Audit Ledger**: Audit events and mutation approvals are recorded locally in a sequential HMAC-SHA256 chained ledger (`dbshield.ledger.jsonl`), verifiable offline via `dbshield report`.
- **End-to-End Supply Chain Provenance**: Releases include SLSA Level 3 build provenance, Sigstore cryptographic signing, and automated CycloneDX / SPDX Software Bill of Materials (SBOM).

---

## 2. Commercial CPA Audit Execution Model ("When Revenue Demands It")

| Milestone | Action Trigger | Platform & Execution | Deliverable |
| :--- | :--- | :--- | :--- |
| **Phase 0: Technical Readiness** | *Completed (Live)* | Pre-mapped AICPA Trust Services Criteria (CC1–CC9, A1, C1, PI1, P1–P8) and ISO 27001 Annex A controls | Technical Readiness Matrix & Mutual NDA Bridge Letter |
| **Phase 1: Revenue Trigger** | Enterprise prospect signs Annual Enterprise Agreement ($\ge \$25,000–\$50,000$/year) contingent on formal report | Connect AWS/GitHub/Google Workspace to **Vanta** or **Drata** | Automated Continuous Evidence Collection |
| **Phase 2: SOC 2 Type I Examination** | Days 1–30 | Engage accredited AICPA CPA firm (e.g., Johanson Group, Barr Advisory, Schellman) | Certified SOC 2 Type I Audit Report |
| **Phase 3: SOC 2 Type II Audit** | Months 3–6 (Observation Window) | CPA auditor evaluates operational effectiveness over a continuous observation period | Official Certified SOC 2 Type II + ISO 27001 Audit Report |

---

## 3. AICPA Trust Services Criteria (TSC) Control Mapping

| SOC 2 TSC Criteria | Requirement Description | DBShield Technical Implementation & Evidence | Audit Verification Command |
| :--- | :--- | :--- | :--- |
| **CC6.1 (Logical Access)** | Logical access to systems, data, and database connections is restricted to authorized entities. | Virtual Schema Masking restricts table access via role-based access control (RBAC). Introspection queries filter out sensitive internal catalogs (`information_schema`, `credentials`). | `dbshield status` |
| **CC6.6 (Boundary Protection)** | Network boundaries and proxy connections are protected from unauthorized intrusion. | Local loopback wire proxy (`127.0.0.1:5433`) with strict TLS termination and air-gapped isolation flags (`--air-gapped`). | `dbshield proxy --air-gapped` |
| **CC6.8 (Malicious Code & SQL Injection)** | Systems protect against unauthorized or malicious code execution and SQL manipulation. | AST Tautology Trap blocks destructive injection patterns (`WHERE 1=1`, `WHERE 'a'='a'`, nested OR bypasses). | `npm test` (169/169 tests pass) |
| **CC7.2 (Security Monitoring & Anomaly Detection)** | Infrastructure monitors operational activities for anomalous data mutations. | Real-time Prometheus metrics exporter (`/metrics`, `/healthz`) tracks blocked queries, AST inspection latencies, and active agent connections. | `curl http://localhost:9090/metrics` |
| **A1.2 (System Availability & Blast Radius)** | Environmental and operational safeguards prevent cascading system locks and service outages. | Statement timeout killer (`[QUERY_TIMEOUT_EXCEEDED]`) terminates runaway unindexed queries before connection pool exhaustion. CostGateEngine blocks unindexed full-table sequential scans. | `dbshield proxy --tier STRICT` |
| **C1.1 (Confidentiality & Secret Protection)** | Confidential database records and customer secrets are shielded from unauthorized disclosure. | Dynamic Zero-Leak PII redactor sanitizes emails, API tokens, SSNs, and passwords using format-preserving pseudonymization before returning results to LLM context. | `dbshield report --compliance soc2` |
| **PI1.2 (Processing Integrity & Mutation Safety)** | System processing is complete, valid, accurate, timely, and authorized. | Two-Phase Distributed Dry-Run Engine executes mutations in an isolated transaction block (`BEGIN ... ROLLBACK`). Commits require cryptographic HMAC-SHA256 single-use tokens. | `dbshield report --format json` |
| **P1–P8 (Privacy Protection)** | Personal identifiable information (PII) is handled in accordance with privacy commitments. | PII Masking and Virtual Schema Masking prevent unredacted customer data from ever entering agent transcripts or external LLM inference prompts. | `dbshield report --audit-pdf audit.pdf` |

---

## 4. ISO/IEC 27001:2022 Annex A Control Mapping

| ISO 27001 Control | Control Objective | DBShield Security Architecture Implementation |
| :--- | :--- | :--- |
| **A.5.15 (Access Control)** | Access to information and assets is controlled based on business requirements. | Virtual Schema Masking hides sensitive tables (`credentials`, `api_keys`) and applies column-level restrictions. |
| **A.8.12 (Data Leakage Prevention)** | Data leakage prevention measures are applied to sensitive database columns. | Automated regex and format-preserving pseudonymization strips sensitive fields from query results and error traces. |
| **A.8.15 (Logging & Event Monitoring)** | Event logs recording user activities, exceptions, and security events are generated and protected. | Sequential HMAC-SHA256 chained audit ledger (`dbshield.ledger.jsonl`) guarantees tamper-evident provenance. |
| **A.8.20 (Network Security)** | Networks and proxy sockets are secured and monitored. | Local-first PostgreSQL wire proxy (`PostgresWireProxy`) with read-replica routing and strict connection pool management. |
| **A.8.25 (Secure Development Lifecycle)** | Security requirements are identified and applied across the development lifecycle. | Automated CodeQL SAST scanning, OpenSSF Scorecard compliance, SLSA Level 3 provenance, and CycloneDX / SPDX SBOMs. |

---

## 5. Audit Request Protocol

For enterprise procurement teams requiring a formal SOC 2 Type II or ISO 27001 bridge letter under mutual NDA:
1. Contact: `security@ritualdev.in`
2. Subject: `Enterprise Security Audit Package Request - [Company Name]`
3. Attached Materials: Standard mutual non-disclosure agreement (MNDA) or request for RitualDev standard MNDA.
