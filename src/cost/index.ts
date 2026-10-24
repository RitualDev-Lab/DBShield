import { QueryExplainer } from "../explain/index.js";
import { stripSqlComments } from "../guard/ast.js";
import type {
  CostGateResult,
  DBShieldConfig,
  DatabaseAdapter,
  ExplainReport,
  RiskLevel,
} from "../types/index.js";

export class CostGateEngine {
  private config: DBShieldConfig;
  private readonly explainer: QueryExplainer;

  constructor(config: DBShieldConfig, adapterOrExplainer: DatabaseAdapter | QueryExplainer) {
    this.config = config;
    if (adapterOrExplainer instanceof QueryExplainer) {
      this.explainer = adapterOrExplainer;
    } else {
      this.explainer = new QueryExplainer(adapterOrExplainer);
    }
  }

  public updateConfig(newConfig: Partial<DBShieldConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  public async evaluate(sql: string, params: unknown[] = []): Promise<CostGateResult> {
    const trimmed = sql.trim();
    const stripped = stripSqlComments(trimmed);
    const upper = stripped.toUpperCase();

    // If cost gate is disabled, allow immediately
    if (!this.config.enableCostGate) {
      return {
        allowed: true,
        blocked: false,
        riskLevel: "SAFE",
        bottlenecks: [],
        suggestions: [],
        warnings: [],
      };
    }

    // Only SELECT, CTE, and queries starting with WITH/SELECT are evaluated by cost gate
    const isQueryPlanTarget = upper.startsWith("SELECT") || upper.startsWith("WITH");
    if (!isQueryPlanTarget) {
      return {
        allowed: true,
        blocked: false,
        riskLevel: "SAFE",
        bottlenecks: [],
        suggestions: [],
        warnings: [],
      };
    }

    const explainReport: ExplainReport = await this.explainer.explainQuery(trimmed, params);

    let blocked = false;
    let code: CostGateResult["code"];
    let riskLevel: RiskLevel = "SAFE";
    const bottlenecks = [...explainReport.bottlenecks];
    const suggestions = [...explainReport.suggestions];
    const warnings: string[] = [];

    // Check 1: Estimated Query Planner Cost (e.g. Postgres)
    if (explainReport.estimatedCost !== undefined) {
      if (explainReport.estimatedCost > this.config.maxEstimatedCost) {
        if (this.config.safetyTier !== "PERMISSIVE") {
          blocked = true;
          code = "EXCESSIVE_QUERY_COST";
          riskLevel = "BLOCKED";
          bottlenecks.push(
            `Estimated planner execution cost of ${explainReport.estimatedCost} exceeds safety limit of ${this.config.maxEstimatedCost}.`,
          );
          suggestions.push(
            "Add indexing, filter by partitioned keys, or narrow JOIN criteria to reduce the estimated planner cost.",
          );
        } else {
          warnings.push(
            `Estimated planner cost (${explainReport.estimatedCost}) exceeds recommended threshold (${this.config.maxEstimatedCost}).`,
          );
        }
      } else if (
        this.config.warnEstimatedCost &&
        explainReport.estimatedCost > this.config.warnEstimatedCost
      ) {
        warnings.push(
          `Estimated planner execution cost (${explainReport.estimatedCost}) exceeds soft warning threshold (${this.config.warnEstimatedCost}).`,
        );
      }
    }

    // Check 2: Estimated Rows Scanned
    if (explainReport.estimatedRows !== undefined) {
      if (explainReport.estimatedRows > this.config.maxEstimatedRows) {
        if (this.config.safetyTier !== "PERMISSIVE") {
          blocked = true;
          code = "EXCESSIVE_QUERY_COST";
          riskLevel = "BLOCKED";
          bottlenecks.push(
            `Estimated rows scanned (${explainReport.estimatedRows}) exceeds safety ceiling of ${this.config.maxEstimatedRows} rows.`,
          );
          suggestions.push(
            "Add a targeted WHERE clause with indexed columns to restrict the scanned row count.",
          );
        } else {
          warnings.push(
            `Estimated scanned rows (${explainReport.estimatedRows}) exceeds recommended limit (${this.config.maxEstimatedRows}).`,
          );
        }
      } else if (
        this.config.warnEstimatedRows &&
        explainReport.estimatedRows > this.config.warnEstimatedRows
      ) {
        warnings.push(
          `Estimated scanned rows (${explainReport.estimatedRows}) exceeds soft warning threshold (${this.config.warnEstimatedRows}).`,
        );
      }
    }

    // Check 3: Full Table Sequential Scan Protection
    if (explainReport.hasSeqScan) {
      if (this.config.blockUnindexedSeqScan) {
        blocked = true;
        code = "UNINDEXED_SCAN_DISALLOWED";
        riskLevel = "BLOCKED";
        bottlenecks.push(
          "Sequential scan on an unindexed table is strictly prohibited under the active safety tier.",
        );
        suggestions.push(
          "Create an appropriate index or use an indexed column in the query filter.",
        );
      } else {
        warnings.push("Sequential scan detected on unindexed table; consider adding indexes.");
      }
    }

    // Check 4: Unbounded Scan without LIMIT in STRICT Tier
    if (
      this.config.safetyTier === "STRICT" &&
      !isIndexedAndBounded(explainReport, upper) &&
      !blocked
    ) {
      blocked = true;
      code = "UNBOUNDED_SCAN_DISALLOWED";
      riskLevel = "BLOCKED";
      bottlenecks.push(
        "Unbounded query on unindexed table without a LIMIT clause is blocked under STRICT tier.",
      );
      suggestions.push(
        "Add a LIMIT clause (e.g., LIMIT 50) to restrict execution and protect connection stability.",
      );
    }

    if (!blocked && warnings.length > 0) {
      riskLevel = "CAUTION";
    }

    return {
      allowed: !blocked,
      blocked,
      code,
      riskLevel,
      estimatedCost: explainReport.estimatedCost,
      maxAllowedCost: this.config.maxEstimatedCost,
      estimatedRows: explainReport.estimatedRows,
      maxAllowedRows: this.config.maxEstimatedRows,
      bottlenecks,
      suggestions,
      warnings,
      explainReport,
    };
  }
}

function isIndexedAndBounded(report: ExplainReport, upperSql: string): boolean {
  if (report.isIndexed) return true;
  return upperSql.includes("LIMIT ");
}
