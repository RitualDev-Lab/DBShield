import { parseSql, stripSqlComments } from "../guard/ast.js";
import type {
  DBShieldConfig,
  DatabaseDialect,
  RiskLevel,
  SemanticEvaluationResult,
} from "../types/index.js";

export interface SensitiveColumnRule {
  pattern: RegExp;
  category: "PRIVILEGE" | "FINANCIAL" | "SECURITY" | "STATUS";
  keywords: string[];
}

export const BUILT_IN_SENSITIVE_RULES: SensitiveColumnRule[] = [
  // 1. Privilege & Roles
  {
    pattern:
      /^(is_admin|admin|role|roles|is_superuser|permissions?|is_staff|account_type|privileges?|access_level|group_id)$/i,
    category: "PRIVILEGE",
    keywords: [
      "role",
      "admin",
      "permission",
      "permissions",
      "privilege",
      "privileges",
      "promote",
      "demote",
      "access",
      "superuser",
      "staff",
      "group",
      "grant",
      "revoke",
      "authorize",
    ],
  },
  // 2. Financial, Credits & Quotas
  {
    pattern:
      /^(balance|credits?|funds?|wallet|quota|subscription(_status)?|tier|plan|discounts?|max_tokens)$/i,
    category: "FINANCIAL",
    keywords: [
      "balance",
      "credit",
      "credits",
      "fund",
      "funds",
      "wallet",
      "pay",
      "payment",
      "charge",
      "refund",
      "deposit",
      "withdraw",
      "subscription",
      "tier",
      "plan",
      "quota",
      "discount",
      "billing",
      "pricing",
    ],
  },
  // 3. Security, Auth & Credentials
  {
    pattern:
      /^(passwords?(_hash)?|secrets?|api_keys?|tokens?|auth_tokens?|refresh_tokens?|mfa_enabled|two_factors?|email_verified|is_verified)$/i,
    category: "SECURITY",
    keywords: [
      "password",
      "secret",
      "api_key",
      "api key",
      "key",
      "token",
      "auth",
      "mfa",
      "2fa",
      "two_factor",
      "two factor",
      "verify",
      "verification",
      "verified",
      "credential",
      "reset",
    ],
  },
  // 4. Account Restrictions & Status
  {
    pattern: /^(banned|is_banned|is_suspended|suspended|locked|is_locked|is_active)$/i,
    category: "STATUS",
    keywords: [
      "ban",
      "unban",
      "suspend",
      "unsuspend",
      "lock",
      "unlock",
      "deactivate",
      "activate",
      "freeze",
      "unfreeze",
      "status",
    ],
  },
];

export class SemanticIntentGuard {
  private config: DBShieldConfig;

  constructor(config: DBShieldConfig) {
    this.config = config;
  }

  public updateConfig(newConfig: Partial<DBShieldConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  /**
   * Evaluate a SQL mutation against an optional stated English intent.
   */
  public evaluate(sql: string, intent?: string): SemanticEvaluationResult {
    const trimmed = sql.trim();
    const stripped = stripSqlComments(trimmed);
    const upper = stripped.toUpperCase();

    if (!this.config.enableSemanticGuard) {
      return {
        allowed: true,
        blocked: false,
        riskLevel: "SAFE",
        modifiedColumns: [],
        sensitiveColumnsTouched: [],
        unauthorizedColumns: [],
        warnings: [],
      };
    }

    // Only INSERT and UPDATE mutate column values
    const isMutation = upper.startsWith("UPDATE") || upper.startsWith("INSERT");
    if (!isMutation) {
      return {
        allowed: true,
        blocked: false,
        riskLevel: "SAFE",
        modifiedColumns: [],
        sensitiveColumnsTouched: [],
        unauthorizedColumns: [],
        warnings: [],
      };
    }

    const modifiedColumns = this.extractModifiedColumns(stripped, this.config.dialect);
    if (modifiedColumns.length === 0) {
      return {
        allowed: true,
        blocked: false,
        riskLevel: "SAFE",
        modifiedColumns: [],
        sensitiveColumnsTouched: [],
        unauthorizedColumns: [],
        warnings: [],
      };
    }

    // Identify which modified columns are sensitive
    const sensitiveColumnsTouched = modifiedColumns.filter((col) => this.isColumnSensitive(col));

    if (sensitiveColumnsTouched.length === 0) {
      return {
        allowed: true,
        blocked: false,
        riskLevel: "SAFE",
        modifiedColumns,
        sensitiveColumnsTouched: [],
        unauthorizedColumns: [],
        warnings: [],
      };
    }

    // Sensitive column(s) are being touched!
    const normalizedIntent = intent?.trim().toLowerCase();

    // Case 1: Intent is provided -> verify that stated intent authorizes these sensitive columns
    if (normalizedIntent && normalizedIntent.length > 0) {
      const unauthorizedColumns: string[] = [];

      for (const col of sensitiveColumnsTouched) {
        if (!this.isIntentAuthorizingColumn(normalizedIntent, col)) {
          unauthorizedColumns.push(col);
        }
      }

      if (unauthorizedColumns.length > 0) {
        return {
          allowed: false,
          blocked: true,
          code: "SEMANTIC_INTENT_MISMATCH",
          riskLevel: "CRITICAL",
          modifiedColumns,
          sensitiveColumnsTouched,
          unauthorizedColumns,
          statedIntent: intent,
          warnings: [
            `Stated intent ('${intent}') does not justify modifying sensitive column(s): [${unauthorizedColumns.join(", ")}].`,
          ],
          suggestion: `The stated intent ('${intent}') did not authorize modification of sensitive column(s): [${unauthorizedColumns.join(", ")}]. If this modification was intentional, update the prompt/intent to explicitly describe the change.`,
        };
      }

      // Stated intent authoritatively aligns with the sensitive modifications
      return {
        allowed: true,
        blocked: false,
        riskLevel: "SAFE",
        modifiedColumns,
        sensitiveColumnsTouched,
        unauthorizedColumns: [],
        statedIntent: intent,
        warnings: [
          `Authorized modification of sensitive column(s) [${sensitiveColumnsTouched.join(", ")}] aligned with stated intent: '${intent}'.`,
        ],
      };
    }

    // Case 2: Intent is NOT provided
    if (this.config.requireIntentForSensitiveColumns) {
      return {
        allowed: false,
        blocked: true,
        code: "INTENT_REQUIRED_FOR_SENSITIVE_COLUMNS",
        riskLevel: "BLOCKED",
        modifiedColumns,
        sensitiveColumnsTouched,
        unauthorizedColumns: sensitiveColumnsTouched,
        warnings: [
          `Modifying sensitive column(s) [${sensitiveColumnsTouched.join(", ")}] requires an explicit 'intent' parameter under '${this.config.safetyTier}' safety tier.`,
        ],
        suggestion: `Provide an 'intent' parameter (e.g. 'Promote user to administrator') explaining the business requirement for modifying sensitive column(s) [${sensitiveColumnsTouched.join(", ")}].`,
      };
    }

    // In BALANCED or PERMISSIVE, permit with strong audit warning
    return {
      allowed: true,
      blocked: false,
      riskLevel: "CAUTION",
      modifiedColumns,
      sensitiveColumnsTouched,
      unauthorizedColumns: [],
      warnings: [
        `Warning: Query modifies sensitive column(s) [${sensitiveColumnsTouched.join(", ")}] without providing an 'intent' parameter. Specify 'intent' to ensure AI prompt alignment.`,
      ],
    };
  }

  /**
   * Check if a column name matches any built-in sensitive rules or custom sensitive columns.
   */
  public isColumnSensitive(columnName: string): boolean {
    const clean = columnName.trim().toLowerCase();

    // Check custom sensitive columns
    if (this.config.customSensitiveColumns && this.config.customSensitiveColumns.length > 0) {
      if (this.config.customSensitiveColumns.some((c) => c.toLowerCase() === clean)) {
        return true;
      }
    }

    // Check built-in sensitive rules
    return BUILT_IN_SENSITIVE_RULES.some((rule) => rule.pattern.test(clean));
  }

  /**
   * Check if a normalized intent string justifies modifying a sensitive column.
   */
  public isIntentAuthorizingColumn(normalizedIntent: string, columnName: string): boolean {
    const clean = columnName.trim().toLowerCase();

    // Check exact column name in intent (e.g., "set is_admin to true" or "update role")
    if (normalizedIntent.includes(clean) || normalizedIntent.includes(clean.replace(/_/g, " "))) {
      return true;
    }

    // Check custom sensitive columns
    if (this.config.customSensitiveColumns?.some((c) => c.toLowerCase() === clean)) {
      const parts = clean.split("_");
      return parts.some((p) => p.length > 2 && normalizedIntent.includes(p));
    }

    // Check matching rule keywords
    for (const rule of BUILT_IN_SENSITIVE_RULES) {
      if (rule.pattern.test(clean)) {
        const hasKeyword = rule.keywords.some((kw) => {
          // Word boundary check in normalized intent
          const regex = new RegExp(`\\b${kw}\\b`, "i");
          return regex.test(normalizedIntent);
        });
        if (hasKeyword) return true;
      }
    }

    return false;
  }

  /**
   * Extract modified column names from an UPDATE or INSERT statement.
   */
  public extractModifiedColumns(sql: string, dialect: DatabaseDialect = "sqlite"): string[] {
    const columns = new Set<string>();

    try {
      const parsed = parseSql(sql, dialect);
      if (parsed.statements.length > 0) {
        for (const stmt of parsed.statements) {
          const ast = stmt.ast as {
            type?: string;
            set?: Array<{ column?: string }>;
            columns?: string[];
          };

          const type = (ast.type || "").toLowerCase();

          // UPDATE set columns
          if (type === "update" && Array.isArray(ast.set)) {
            for (const s of ast.set) {
              if (s?.column) {
                columns.add(s.column.toLowerCase());
              }
            }
          }

          // INSERT target columns
          if (type === "insert" && Array.isArray(ast.columns)) {
            for (const c of ast.columns) {
              if (typeof c === "string") {
                columns.add(c.toLowerCase());
              }
            }
          }
        }
      }
    } catch {
      // Fallback to robust regex parsing if AST parser encounters non-standard dialect syntax
    }

    // Regex fallback if AST returned 0 columns
    if (columns.size === 0) {
      const upper = sql.toUpperCase();
      if (upper.includes("UPDATE ") && upper.includes(" SET ")) {
        const setMatch = sql.match(/SET\s+([\s\S]+?)(?:\s+WHERE|\s+ORDER|\s+LIMIT|;|\s*$)/i);
        if (setMatch) {
          const setClause = setMatch[1];
          const assignments = setClause.split(",");
          for (const assign of assignments) {
            const colMatch = assign.match(/([a-zA-Z0-9_]+)\s*=/);
            if (colMatch) {
              columns.add(colMatch[1].toLowerCase());
            }
          }
        }
      } else if (upper.includes("INSERT INTO")) {
        const insertMatch = sql.match(/INSERT\s+INTO\s+[a-zA-Z0-9_."`]+\s*\(([^)]+)\)/i);
        if (insertMatch) {
          const colList = insertMatch[1].split(",");
          for (const c of colList) {
            const clean = c.trim().replace(/["`]/g, "").toLowerCase();
            if (clean) columns.add(clean);
          }
        }
      }
    }

    return Array.from(columns);
  }
}
