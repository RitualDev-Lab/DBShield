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
  auditLogPath?: string;
  enableCostGate: boolean; // Phase 2: Runaway query and cost gate (default true)
  maxEstimatedCost: number; // Maximum query planner cost allowed (default 50000 in BALANCED, 10000 in STRICT)
  warnEstimatedCost?: number; // Soft warning cost threshold (default 10000)
  maxEstimatedRows: number; // Maximum planner estimated rows scanned (default 100000 in BALANCED, 20000 in STRICT)
  warnEstimatedRows?: number; // Soft warning row scan threshold (default 20000)
  blockUnindexedSeqScan: boolean; // Disallows full table sequential scan (default true in STRICT, false in BALANCED)
  statementTimeoutMs: number; // Statement execution timeout in milliseconds (default 5000ms)
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
