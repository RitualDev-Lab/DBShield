import { PII_RULES, type PiiCategoryRule } from "./patterns.js";

export interface PiiRedactionReport {
  sanitizedRows: Record<string, unknown>[];
  redactedColumns: string[];
  categoriesDetected: string[];
  totalFieldsRedacted: number;
}

export class PiiRedactor {
  private readonly customColumns: Set<string>;

  constructor(customColumns: string[] = []) {
    this.customColumns = new Set(customColumns.map((c) => c.toLowerCase().trim()));
  }

  public redactRows(
    rows: Record<string, unknown>[],
    customOverrideColumns: string[] = [],
  ): PiiRedactionReport {
    const activeCustom = new Set([
      ...Array.from(this.customColumns),
      ...customOverrideColumns.map((c) => c.toLowerCase().trim()),
    ]);

    const redactedColsSet = new Set<string>();
    const categoriesSet = new Set<string>();
    let totalFieldsRedacted = 0;

    const sanitizedRows = rows.map((row) => {
      const sanitizedRow: Record<string, unknown> = {};

      for (const [col, val] of Object.entries(row)) {
        const result = this.redactCell(col, val, activeCustom);
        sanitizedRow[col] = result.value;

        if (result.redacted) {
          redactedColsSet.add(col);
          if (result.category) categoriesSet.add(result.category);
          totalFieldsRedacted++;
        }
      }

      return sanitizedRow;
    });

    return {
      sanitizedRows,
      redactedColumns: Array.from(redactedColsSet),
      categoriesDetected: Array.from(categoriesSet),
      totalFieldsRedacted,
    };
  }

  public redactCell(
    columnName: string,
    value: unknown,
    customColumns: Set<string>,
  ): { value: unknown; redacted: boolean; category?: string } {
    if (value === null || value === undefined) {
      return { value, redacted: false };
    }

    const colLower = columnName.toLowerCase();

    // Check custom configured PII columns
    if (customColumns.has(colLower)) {
      return {
        value: "[REDACTED_CUSTOM]",
        redacted: true,
        category: "CUSTOM",
      };
    }

    const strVal = typeof value === "string" ? value : String(value);

    // Check column name heuristics
    for (const rule of PII_RULES) {
      if (rule.columnRegex.test(colLower)) {
        return {
          value: rule.mask(strVal),
          redacted: true,
          category: rule.category,
        };
      }
    }

    // If column name didn't match, inspect string content for inline PII
    if (typeof value === "string" && value.length > 3) {
      let currentVal = value;
      let matchedCategory: string | undefined;
      let modified = false;

      for (const rule of PII_RULES) {
        if (rule.valueRegex) {
          const globalRegex = new RegExp(rule.valueRegex.source, "gi");
          if (globalRegex.test(currentVal)) {
            currentVal = currentVal.replace(globalRegex, (match) => rule.mask(match));
            matchedCategory = rule.category;
            modified = true;
          }
        }
      }

      if (modified) {
        return {
          value: currentVal,
          redacted: true,
          category: matchedCategory,
        };
      }
    }

    return { value, redacted: false };
  }
}
