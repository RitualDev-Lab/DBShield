# 05 — Enterprise VPC & Security Controls

## Private VPC & Kubernetes Deployment
DBShield deploys alongside AgentShield and SkillPrism using the canonical Helm charts and Terraform modules in [`RitualDev-Lab/enterprise-governance-suite`](https://github.com/RitualDev-Lab/enterprise-governance-suite):
- Zero-egress `NetworkPolicy` isolating DBShield between agent pods and internal RDS/CloudSQL/Aurora endpoints.
- Virtual Schema RBAC hiding sensitive tables (`credentials`, `audit_*`) and columns per SSO role.
- Append-only HMAC-SHA256 audit ledger aligned with **PCI-DSS v4.0 Req 10** and **SOC 2 CC6.8**.
- Multi-SIEM streaming to Splunk HEC, Datadog Logs, and ArcSight CEF via `agent-defense-hub`.

## Responsible Security Disclosure
Report vulnerabilities privately via [SECURITY.md](../SECURITY.md) or `security@ritualdev.in`.
