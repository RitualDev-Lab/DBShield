import type {
  DBShieldConfig,
  GuardrailEvaluation,
  GuardrailViolation,
  RiskLevel,
  SqlOperationType,
} from "../types/index.js";
import { type ParsedStatement, parseSql } from "./ast.js";
import { evaluateWhereClause } from "./tautology.js";

export class SqlGuardEngine {
  private config: DBShieldConfig;

  constructor(config: DBShieldConfig) {
    this.config = config;
  }

  public updateConfig(newConfig: Partial<DBShieldConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  public evaluate(sql: string): GuardrailEvaluation {
    const trimmed = sql.trim();
    if (!trimmed) {
      return {
        allowed: false,
        riskLevel: "BLOCKED",
        riskScore: 60,
        operation: "UNKNOWN",
        targetTables: [],
        violations: [
          {
            code: "EMPTY_QUERY",
            message: "SQL statement is empty.",
            severity: "BLOCKED",
          },
        ],
        warnings: [],
        requiresDryRun: false,
      };
    }

    const parseResult = parseSql(trimmed, this.config.dialect);

    if (parseResult.parseError) {
      return this.handleParseError(trimmed, parseResult.parseError);
    }

    const { statements, isMultiStatement } = parseResult;

    // Check multi-statement security
    if (isMultiStatement) {
      return this.evaluateMultiStatement(statements);
    }

    const statement = statements[0];
    return this.evaluateStatement(statement);
  }

  private evaluateStatement(stmt: ParsedStatement): GuardrailEvaluation {
    const violations: GuardrailViolation[] = [];
    const warnings: string[] = [];
    let riskScore = 0;
    let requiresDryRun = false;

    const op = stmt.operation;
    const ast = stmt.ast as {
      limit?: unknown;
      where?: unknown;
      expr?: Array<{ action?: string }>;
    };
    const targetTables = stmt.targetTables;

    switch (op) {
      case "SELECT": {
        riskScore = 5;
        if (!ast.limit && this.config.safetyTier === "STRICT") {
          warnings.push(
            "SELECT query has no LIMIT clause. In STRICT tier, adding a LIMIT protects against large payload memory exhaustion.",
          );
        }
        break;
      }

      case "DDL_DROP":
      case "DDL_TRUNCATE": {
        if (!this.config.allowDestructiveDDL) {
          riskScore = 95;
          violations.push({
            code: "DESTRUCTIVE_DDL_BLOCKED",
            message: `Destructive operation '${op}' on table(s) [${targetTables.join(", ")}] is prohibited.`,
            severity: "CRITICAL",
            suggestion:
              "Destructive DDL is blocked by DBShield. Set allowDestructiveDDL: true in dbshield.config.json if explicitly required.",
          });
        } else {
          riskScore = 65;
          warnings.push(`Executing destructive DDL '${op}' under allowDestructiveDDL override.`);
        }
        break;
      }

      case "DDL_ALTER": {
        const hasDropColumn =
          Array.isArray(ast.expr) && ast.expr.some((e) => e.action?.toLowerCase() === "drop");

        if (hasDropColumn && !this.config.allowDestructiveDDL) {
          riskScore = 85;
          violations.push({
            code: "DESTRUCTIVE_ALTER_BLOCKED",
            message: `Destructive column dropping via ALTER TABLE on [${targetTables.join(", ")}] is prohibited.`,
            severity: "BLOCKED",
            suggestion:
              "Destructive ALTER is blocked by default to prevent irreversible schema data loss.",
          });
        } else {
          riskScore = 30;
          if (this.config.safetyTier === "STRICT") {
            requiresDryRun = true;
          }
        }
        break;
      }

      case "DELETE":
      case "UPDATE": {
        const tautologyResult = evaluateWhereClause(ast.where);

        if (tautologyResult.isTautology) {
          riskScore = 90;
          violations.push({
            code: "UNCONSTRAINED_MUTATION",
            message: `Unconstrained ${op} query detected: ${tautologyResult.reason}`,
            severity: "CRITICAL",
            suggestion:
              "Specify a concrete, targeted WHERE predicate (e.g. 'WHERE id = ?' or 'WHERE status = ?') to prevent bulk table destruction.",
          });
        } else {
          // Valid targeted mutation
          if (this.config.safetyTier === "STRICT") {
            riskScore = 45;
            requiresDryRun = true;
            warnings.push(`${op} mutations in STRICT tier require a dry-run pre-flight check.`);
          } else if (this.config.safetyTier === "BALANCED") {
            riskScore = 25;
          } else {
            riskScore = 15;
          }
        }
        break;
      }

      case "INSERT": {
        if (this.config.safetyTier === "STRICT") {
          riskScore = 35;
          requiresDryRun = true;
        } else {
          riskScore = 15;
        }
        break;
      }

      default: {
        riskScore = 20;
        warnings.push(`Unrecognized or non-standard SQL statement type: ${op}`);
      }
    }

    const riskLevel = this.calculateRiskLevel(riskScore, violations);
    const allowed = this.isAllowedUnderTier(riskLevel, violations);

    return {
      allowed,
      riskLevel,
      riskScore,
      operation: op,
      targetTables,
      violations,
      warnings,
      requiresDryRun,
    };
  }

  private evaluateMultiStatement(statements: ParsedStatement[]): GuardrailEvaluation {
    const allViolations: GuardrailViolation[] = [];
    const allWarnings: string[] = ["Multi-statement batch execution detected."];
    let maxRiskScore = 40;
    const allTables = new Set<string>();

    for (const stmt of statements) {
      const evalRes = this.evaluateStatement(stmt);
      if (evalRes.riskScore > maxRiskScore) {
        maxRiskScore = evalRes.riskScore;
      }
      for (const t of evalRes.targetTables) allTables.add(t);
      allViolations.push(...evalRes.violations);
      allWarnings.push(...evalRes.warnings);
    }

    // In STRICT and BALANCED mode, chained queries containing mutations or DDL receive elevated scrutiny
    if (this.config.safetyTier !== "PERMISSIVE" && maxRiskScore >= 50) {
      allViolations.push({
        code: "MULTI_STATEMENT_RISK",
        message: "Multi-statement batch contains high-risk operations.",
        severity: "BLOCKED",
        suggestion:
          "Execute individual statements separately to allow granular blast-radius isolation.",
      });
    }

    const riskLevel = this.calculateRiskLevel(maxRiskScore, allViolations);
    const allowed = this.isAllowedUnderTier(riskLevel, allViolations);

    return {
      allowed,
      riskLevel,
      riskScore: maxRiskScore,
      operation: statements[0]?.operation || "UNKNOWN",
      targetTables: Array.from(allTables),
      violations: allViolations,
      warnings: allWarnings,
      requiresDryRun: maxRiskScore >= 40,
    };
  }

  private handleParseError(rawSql: string, parseError: string): GuardrailEvaluation {
    const upper = rawSql.toUpperCase();
    const hasDestructiveKeywords =
      upper.includes("DROP ") ||
      upper.includes("TRUNCATE ") ||
      upper.includes("DELETE ") ||
      upper.includes("UPDATE ");

    if (this.config.safetyTier === "STRICT" || hasDestructiveKeywords) {
      return {
        allowed: false,
        riskLevel: "BLOCKED",
        riskScore: 75,
        operation: "UNKNOWN",
        targetTables: [],
        violations: [
          {
            code: "UNPARSABLE_SQL_QUERY",
            message: `Could not safely parse SQL query: ${parseError}`,
            severity: "BLOCKED",
            suggestion: "Check SQL syntax for standard compliance with the active dialect.",
          },
        ],
        warnings: [],
        requiresDryRun: false,
      };
    }

    // Non-destructive benign query fallback in BALANCED/PERMISSIVE
    return {
      allowed: true,
      riskLevel: "CAUTION",
      riskScore: 30,
      operation: "UNKNOWN",
      targetTables: [],
      violations: [],
      warnings: [`Query executed with fallback inspection (AST parser warning: ${parseError}).`],
      requiresDryRun: false,
    };
  }

  private calculateRiskLevel(score: number, violations: GuardrailViolation[]): RiskLevel {
    if (violations.some((v) => v.severity === "CRITICAL")) return "CRITICAL";
    if (violations.some((v) => v.severity === "BLOCKED")) return "BLOCKED";
    if (score >= 80) return "CRITICAL";
    if (score >= 50) return "BLOCKED";
    if (score >= 25) return "CAUTION";
    return "SAFE";
  }

  private isAllowedUnderTier(level: RiskLevel, violations: GuardrailViolation[]): boolean {
    if (level === "CRITICAL" || level === "BLOCKED") {
      return false;
    }

    if (this.config.safetyTier === "STRICT") {
      // In STRICT, CAUTION requires dry-run first
      return level === "SAFE";
    }

    return true;
  }
}
