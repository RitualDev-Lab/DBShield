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
}

export interface DatabaseAdapter {
  dialect: DatabaseDialect;
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  query(
    sql: string,
    params?: unknown[],
    options?: { maxRows?: number; maxMutationRows?: number },
  ): Promise<QueryResult>;
  executeDryRun(sql: string, params?: unknown[]): Promise<DryRunResult>;
  executeCommit(
    sql: string,
    params?: unknown[],
    options?: { maxRows?: number; expectedRows?: number },
  ): Promise<QueryResult>;
  getSchema(): Promise<TableSchema[]>;
  getTableSchema(tableName: string): Promise<TableSchema | null>;
}
