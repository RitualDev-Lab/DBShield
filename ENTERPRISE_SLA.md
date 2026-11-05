# 📜 Formal Enterprise Service Level Agreement (SLA)

> **Document Version**: 1.0.0  
> **Effective Date**: November 2026  
> **Vendor Entity**: RitualDev Lab (`ritualdev.in`)  
> **Applies to**: DBShield Enterprise, Database Guardrail Proxy & MCP Sandboxing Suite  
> **Official Intake**: `support@ritualdev.in` | `security@ritualdev.in` | `developer@ritualdev.in`  
> **Enterprise Trust Portal**: [https://ritualdev.in/trust](https://ritualdev.in/trust)  
> **Status**: Active & Operationally Guaranteed  

---

## 1. Executive Summary & Purpose

This Enterprise Service Level Agreement (**"SLA"**) governs the technical support response guarantees, availability targets, and critical incident escalation workflows provided by **RitualDev Lab** to enterprise customers deploying **DBShield** within on-premises, hybrid cloud, or private VPC architectures.

DBShield provides deterministic, zero-overhead database guardrails, PostgreSQL/MySQL wire proxies, virtual schema masking, and autonomous agent sandboxing to protect relational databases from unconstrained mutations, accidental table drops, and PII leakage.

---

## 2. Priority Classification & Response Time Guarantees

All inquiries submitted to `support@ritualdev.in` or `security@ritualdev.in` are automatically triaged by severity classification based on the operational impact to customer database integrity:

| Severity Level | Definition & Operational Impact | Initial Response Guarantee | Target Resolution / Mitigation | Coverage Window |
| :--- | :--- | :---: | :---: | :---: |
| **P1 — Critical Outage / Data Protection Failure** | Complete database wire proxy outage; critical mutation firewall bypass; unauthorized production table lock or drop; zero-day SQL injection vulnerability. | **< 1 Hour** | **< 4 Hours** | **24/7/365** |
| **P2 — High Severity / Partial Degradation** | Core guardrail impairment; wire proxy throughput degradation exceeding 5ms P99 latency; false-positive mutation blockages impacting developer workflows; SSO/OIDC authentication disruption. | **< 4 Hours** | **< 1 Business Day** | **24/7/365** |
| **P3 — General Support & Architecture Advisory** | General questions; configuration tuning; new SQL AST rule definitions; query execution plan advice; virtual schema masking advisory. | **< 1 Business Day** | Next Sprint / Scheduled Release | Standard Business Hours (Mon–Fri, 9am–6pm IST/UTC) |

---

## 3. Availability & Uptime Commitments

### 3.1 Availability Metric (99.95%)
For customers utilizing managed or containerized DBShield wire proxy sidecars deployed per RitualDev High-Availability (HA) reference architecture, RitualDev Lab commits to an operational uptime of **99.95%** per calendar month.

### 3.2 Service Credits
If monthly proxy availability falls below the guaranteed threshold:
- **99.0% – 99.95%**: 10% monthly service fee credit.
- **95.0% – 99.0%**: 25% monthly service fee credit.
- **< 95.0%**: 50% monthly service fee credit.

---

## 4. Security Incident Response & Zero-Day Patching

1. **Security Vulnerability Intake**: Dedicated cryptographically monitored channel at `security@ritualdev.in`.
2. **Triaging & Advisory SLA**:
   - Critical vulnerabilities (CVSS $\ge 9.0$): Formal CVE advisory & hotfix container build dispatched within **24 hours**.
   - High vulnerabilities (CVSS $7.0 - 8.9$): Patch released within **72 hours**.
3. **Automated CycloneDX & SPDX SBOM**: Every release attaches automated cryptographic SBOMs detailing sub-dependencies with SHA-256 hashes for enterprise supply-chain compliance (NIST SP 800-218 and US Executive Order 14028).

---

## 5. Escalation & Contact Channels

- **Enterprise Commercial & Support**: `support@ritualdev.in`
- **Security Incident Response Team**: `security@ritualdev.in`
- **Core Engineering & Technical Reviews**: `developer@ritualdev.in`
- **Customer Portal**: [https://ritualdev.in/enterprise](https://ritualdev.in/enterprise)
