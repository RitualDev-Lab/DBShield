export type DatabaseDialect = "sqlite" | "postgres" | "mysql";

export type SafetyTier = "STRICT" | "BALANCED" | "PERMISSIVE";

export type RiskLevel = "SAFE" | "CAUTION" | "BLOCKED" | "CRITICAL";

export type SqlOperationType =
  | "SELECT"
  | "INSERT"
  | "UPDATE"
  | "DELETE"
  | "DDL_CREATE"
  | "DDL_ALTER"
  | "DDL_DROP"
  | "DDL_TRUNCATE"
  | "UNKNOWN";

export interface GuardrailViolation {
  code: string;
  message: string;
  severity: RiskLevel;
  suggestion?: string;
}

export interface GuardrailEvaluation {
  allowed: boolean;
  riskLevel: RiskLevel;
  riskScore: number; // 0 to 100
  operation: SqlOperationType;
  targetTables: string[];
  violations: GuardrailViolation[];
  warnings: string[];
  requiresDryRun: boolean;
}

export interface QueryPaginationMeta {
  totalReturned: number;
  isTruncated: boolean;
  maxAllowedRows: number;
  hasMore?: boolean;
  warning?: string;
}

export interface QueryResult {
  rows: Record<string, unknown>[];
  rowCount: number;
  columns: string[];
  executionTimeMs: number;
  redactedColumns: string[];
  auditId: string;
  meta?: QueryPaginationMeta;
}

export interface DryRunResult {
  safe: boolean;
  simulatedAffectedRows: number;
  targetTables: string[];
  executionTimeMs: number;
  commitToken?: string;
  expiresAt?: string;
  warnings: string[];
  rollbackVerified: boolean;
  intentAligned?: boolean;
  intentGap?: string;
}

export interface ColumnDefinition {
  name: string;
  type: string;
  nullable: boolean;
  primaryKey: boolean;
  defaultValue?: string | null;
}

export interface ForeignKeyDefinition {
  column: string;
  referencedTable: string;
  referencedColumn: string;
}

export interface IndexDefinition {
  name: string;
  columns: string[];
  unique: boolean;
}

export interface TableSchema {
  tableName: string;
  columns: ColumnDefinition[];
  foreignKeys: ForeignKeyDefinition[];
  indexes: IndexDefinition[];
}

export interface ExplainReport {
  rawPlan: Record<string, unknown>[];
  bottlenecks: string[];
  suggestions: string[];
  isIndexed: boolean;
  estimatedCost?: number;
  estimatedRows?: number;
  hasSeqScan?: boolean;
  missingIndexes?: MissingIndexAdvice[];
  advisorReport?: QueryPlanAdvisorReport;
}

export interface CostGateResult {
  allowed: boolean;
  blocked: boolean;
  code?: "EXCESSIVE_QUERY_COST" | "UNINDEXED_SCAN_DISALLOWED" | "UNBOUNDED_SCAN_DISALLOWED";
  riskLevel: RiskLevel;
  estimatedCost?: number;
  maxAllowedCost?: number;
  estimatedRows?: number;
  maxAllowedRows?: number;
  bottlenecks: string[];
  suggestions: string[];
  warnings: string[];
  explainReport?: ExplainReport;
}

export interface MigrationViolation {
  code: string;
  statement: string;
  targetTable: string;
  targetColumn?: string;
  severity: RiskLevel;
  lockType: "ACCESS_EXCLUSIVE" | "SHARE" | "SHARE_UPDATE_EXCLUSIVE" | "NONE";
  message: string;
  safeAlternative: string;
}

export interface MigrationValidationReport {
  safe: boolean;
  riskScore: number;
  highestLockLevel: "ACCESS_EXCLUSIVE" | "SHARE" | "SHARE_UPDATE_EXCLUSIVE" | "NONE";
  violations: MigrationViolation[];
  warnings: string[];
  safeMigrationPlan: string[];
}

export interface SchemaDriftDifference {
  type: "MISSING_TABLE" | "UNEXPECTED_TABLE" | "MISSING_COLUMN" | "TYPE_MISMATCH" | "MISSING_INDEX";
  table: string;
  column?: string;
  expected?: string;
  actual?: string;
  recommendation: string;
}

export interface SchemaDriftReport {
  inSync: boolean;
  totalTables: number;
  differences: SchemaDriftDifference[];
  unindexedForeignKeys: Array<{ table: string; column: string; referencedTable: string }>;
}

export interface SemanticEvaluationResult {
  allowed: boolean;
  blocked: boolean;
  code?: "SEMANTIC_INTENT_MISMATCH" | "INTENT_REQUIRED_FOR_SENSITIVE_COLUMNS";
  riskLevel: RiskLevel;
  modifiedColumns: string[];
  sensitiveColumnsTouched: string[];
  unauthorizedColumns: string[];
  statedIntent?: string;
  warnings: string[];
  suggestion?: string;
}

export interface CustomPiiRule {
  name: string;
  pattern?: string; // Regex string for cell value
  columnPattern?: string; // Regex string for column name
  replacement?: string; // Custom replacement template e.g. "[REDACTED_<NAME>]"
  formatPreserving?: boolean; // When true, deterministic pseudonym preserves referential integrity
}

export interface MissingIndexAdvice {
  tableName: string;
  columns: string[];
  suggestedIndexName: string;
  suggestedDdl: string;
  regressiveSeverity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  reason: string;
  estimatedCost?: number;
  estimatedRows?: number;
}

export interface QueryPlanAdvisorReport {
  hasRegression: boolean;
  advice: MissingIndexAdvice[];
  alerts: string[];
  suggestedDdls: string[];
}

export interface VirtualSchemaRoleConfig {
  allowedTables?: string[];
  deniedTables?: string[];
  deniedColumns?: Record<string, string[]>; // tableName -> columnNames[]
}

export interface VirtualSchemaConfig {
  enabled: boolean;
  hiddenTables?: string[]; // Glob or table names e.g. ["credentials", "internal_audit", "admin_keys", "secret_*"]
  hiddenColumns?: Record<string, string[]>; // tableName -> columnNames[]
  roles?: Record<string, VirtualSchemaRoleConfig>;
  defaultRole?: string;
}

export interface ApprovalRequest {
  id: string;
  timestamp: string;
  agentId?: string;
  clientIp?: string;
  sql: string;
  operation: SqlOperationType;
  riskLevel: RiskLevel;
  riskScore: number;
  targetTables: string[];
  piiRedacted: boolean;
  status: "PENDING" | "APPROVED" | "REJECTED";
  decidedAt?: string;
  decidedBy?: string;
  reason?: string;
}

export type DistributedStoreType = "postgres" | "sqlite" | "mysql" | "redis";

export interface DistributedStoreOperation {
  storeId: string;
  storeType: DistributedStoreType;
  action: "SQL" | "KV_SET" | "KV_DEL" | "KV_EXPIRE";
  queryOrKey: string;
  paramsOrValue?: unknown;
  estimatedImpact?: {
    affectedRows?: number;
    affectedKeys?: number;
  };
}

export interface DistributedStoreDryRunResult {
  storeId: string;
  storeType: DistributedStoreType;
  safe: boolean;
  affectedRows?: number;
  affectedKeys?: number;
  rollbackVerified: boolean;
  warnings: string[];
  error?: string;
}

export interface DistributedDryRunResult {
  safe: boolean;
  distributedCommitToken?: string;
  expiresAt?: string;
  totalAffectedEntities: number;
  storeResults: Record<string, DistributedStoreDryRunResult>;
  warnings: string[];
  rollbackVerified: boolean;
}

export interface DistributedCommitResult {
  committed: boolean;
  storeResults: Record<
    string,
    { success: boolean; affectedRows?: number; affectedKeys?: number; error?: string }
  >;
  distributedAuditId: string;
}

export interface SiemTelemetryConfig {
  enabled: boolean;
  endpoint: string; // Remote HTTP/HTTPS webhook or SIEM collector
  format?: "webhook" | "datadog" | "elasticsearch" | "agentshield";
  authToken?: string; // Bearer token or API key
  batchSize?: number; // Maximum events to queue before flushing (default 10)
  flushIntervalMs?: number; // Periodic flush interval in milliseconds (default 5000)
  streamBlockedOnly?: boolean;
  headers?: Record<string, string>; // Additional custom headers
}

export interface DBShieldConfig {
  dialect: DatabaseDialect;
  connectionString?: string;
  storagePath?: string; // for SQLite file path or :memory:
  safetyTier: SafetyTier;
  maxRowsPerMutation: number; // Hard ceiling (default 50 in BALANCED, 1 in STRICT, 500 in PERMISSIVE)
  warnRowsPerMutation?: number; // Soft warning threshold (default 10 in BALANCED, 1 in STRICT, 100 in PERMISSIVE)
  maxRowsPerRead: number; // Hard server-controlled ceiling for row-returning queries (default 500)
  allowDestructiveDDL: boolean; // Default false
  enablePiiMasking: boolean; // Default true
  customPiiColumns?: string[];
  customPiiRules?: CustomPiiRule[];
  enableFormatPreservingPii?: boolean;
  piiPseudonymSalt?: string;
  auditLogPath?: string;
  siemTelemetry?: SiemTelemetryConfig;
  enableCostGate: boolean; // Phase 2: Runaway query and cost gate (default true)
  maxEstimatedCost: number; // Maximum query planner cost allowed (default 50000 in BALANCED, 10000 in STRICT)
  warnEstimatedCost?: number; // Soft warning cost threshold (default 10000)
  maxEstimatedRows: number; // Maximum planner estimated rows scanned (default 100000 in BALANCED, 20000 in STRICT)
  warnEstimatedRows?: number; // Soft warning row scan threshold (default 20000)
  blockUnindexedSeqScan: boolean; // Disallows full table sequential scan (default true in STRICT, false in BALANCED)
  statementTimeoutMs: number; // Statement execution timeout in milliseconds (default 5000ms)
  enableMigrationGate: boolean; // Phase 3: Migration safety and schema drift gate (default true)
  enforceConcurrentIndexCreation: boolean; // Require CREATE INDEX CONCURRENTLY in Postgres (default true in STRICT, false in BALANCED)
  disallowBreakingRenames: boolean; // Block table/column renames without zero-downtime expand-contract (default true in STRICT and BALANCED)
  enableSemanticGuard: boolean; // Phase 4: Stated intent vs SQL AST mismatch gate (default true)
  customSensitiveColumns?: string[]; // Custom sensitive column names to protect (e.g. ['kyc_status', 'discount'])
  requireIntentForSensitiveColumns: boolean; // Require explicit intent when mutating sensitive fields (default true in STRICT, false in BALANCED)
  proxyPort?: number; // Port for PostgreSQL TCP wire proxy (default 5433)
  proxyHost?: string; // Host for PostgreSQL TCP wire proxy (default "127.0.0.1")
  upstreamHost?: string; // Upstream target PostgreSQL host (default "127.0.0.1")
  upstreamPort?: number; // Upstream target PostgreSQL port (default 5432)
  mysqlProxyPort?: number; // Port for MySQL TCP wire proxy (default 3307)
  mysqlUpstreamHost?: string; // Upstream target MySQL host (default "127.0.0.1")
  mysqlUpstreamPort?: number; // Upstream target MySQL port (default 3306)
  poolSize?: number; // Connection pool capacity (default 10)
  idleTimeoutMillis?: number; // Connection idle timeout (default 30000ms)
  connectionTimeoutMillis?: number; // Connection timeout (default 5000ms)
  enableReadReplicaRouting?: boolean; // Enable automatic read/write splitting
  readReplicaHost?: string; // Target read-replica host for pure SELECT queries
  readReplicaPort?: number; // Target read-replica port
  metricsPort?: number; // Prometheus metrics & health HTTP port (default 9090)
  metricsHost?: string; // Prometheus metrics & health HTTP host (default "0.0.0.0")
  enableMetrics?: boolean; // Enable Prometheus metrics exporter (default true)
  virtualSchema?: VirtualSchemaConfig;
  enableVirtualSchema?: boolean; // Default false
  enableDashboard?: boolean; // Default false
  dashboardPort?: number; // Port for live query approval web dashboard (default 3100)
  dashboardHost?: string; // Host for dashboard (default "0.0.0.0")
  requireApprovalForMutations?: boolean; // Block sensitive mutations until approved via dashboard
  airGapped?: boolean; // 100% offline mode: zero outbound network phone-homes, strictly local telemetry & models
  sso?: SsoConfig; // SSO/OIDC/SAML authentication configuration
  chatOps?: ChatOpsConfig; // Slack & Microsoft Teams interactive mutation approval integration
  compliance?: {
    companyName?: string;
    environment?: "production" | "staging" | "sandbox";
  };
}

export interface ChatOpsConfig {
  enabled?: boolean;
  slackWebhookUrl?: string;
  slackBotToken?: string;
  slackChannel?: string; // Channel name or ID e.g. "#db-approvals"
  slackSigningSecret?: string; // For verifying X-Slack-Signature
  teamsWebhookUrl?: string; // Microsoft Teams connector webhook URL
  callbackBaseUrl?: string; // Public or internal URL where Slack sends interaction payloads
  notifyOnPending?: boolean; // default true
  notifyOnDecision?: boolean; // default true
}

export type SsoProvider = "okta" | "azure-ad" | "ping-identity" | "google" | "oidc" | "saml";

export interface SsoUser {
  id: string;
  email: string;
  name?: string;
  roles: string[];
  provider: SsoProvider;
  tenantId?: string;
  issuedAt: number;
  expiresAt: number;
}

export interface SsoConfig {
  enabled: boolean;
  provider: SsoProvider;
  issuer?: string; // OIDC Issuer e.g. "https://login.microsoftonline.com/{tenant}/v2.0"
  clientId?: string;
  clientSecret?: string;
  redirectUri?: string;
  allowedDomains?: string[]; // Allowed email domains e.g. ["ritual.dev", "enterprise.com"]
  allowedRoles?: string[]; // RBAC roles allowed to access dashboard/approvals
  samlEntrypoint?: string;
  samlCert?: string;
  jwtSecret?: string; // Secret for signing local session JWTs / cookies
  enforceMfa?: boolean;
}

export interface ComplianceProof {
  controlId: string;
  controlTitle: string;
  status: "COMPLIANT" | "PARTIAL" | "NON_COMPLIANT";
  description: string;
  cryptographicProof?: {
    merkleRoot?: string;
    entryCount: number;
    hashChainVerified: boolean;
    chainHeadHash: string;
    chainTailHash: string;
  };
  piiMaskingProof?: {
    totalEvaluatedRows: number;
    redactedFieldCount: number;
    zeroLeakageVerified: boolean;
    activeRuleCount: number;
  };
  dryRunAuditProof?: {
    simulatedMutations: number;
    blockedHighRiskQueries: number;
    rollbackIntegrityVerified: boolean;
    approvedMutations: number;
  };
}

export interface ComplianceReportOptions {
  framework: "soc2" | "iso27001" | "hipaa";
  format?: "pdf" | "html" | "json";
  outputPath?: string;
  startDate?: string;
  endDate?: string;
  includeProofs?: boolean;
  companyName?: string;
  environment?: string;
}

export interface ComplianceReportResult {
  framework: "soc2" | "iso27001" | "hipaa";
  generatedAt: string;
  reportId: string;
  auditorSignature: string; // HMAC SHA-256 seal of the report payload
  status: "PASS" | "NEEDS_REVIEW" | "FAIL";
  score: number; // percentage compliant e.g. 100
  summary: string;
  proofs: ComplianceProof[];
  outputPath?: string;
  rawReport?: string;
}

export interface DatabaseAdapter {
  dialect: DatabaseDialect;
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  query(
    sql: string,
    params?: unknown[],
    options?: { maxRows?: number; maxMutationRows?: number; timeoutMs?: number },
  ): Promise<QueryResult>;
  executeDryRun(sql: string, params?: unknown[]): Promise<DryRunResult>;
  executeCommit(
    sql: string,
    params?: unknown[],
    options?: { maxRows?: number; expectedRows?: number; timeoutMs?: number },
  ): Promise<QueryResult>;
  getSchema(): Promise<TableSchema[]>;
  getTableSchema(tableName: string): Promise<TableSchema | null>;
}
