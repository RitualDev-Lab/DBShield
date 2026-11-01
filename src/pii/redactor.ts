import crypto from "node:crypto";
import type { CustomPiiRule } from "../types/index.js";
import { PII_RULES, type PiiCategoryRule } from "./patterns.js";

export interface PiiRedactionReport {
  sanitizedRows: Record<string, unknown>[];
  redactedColumns: string[];
  categoriesDetected: string[];
  totalFieldsRedacted: number;
}

export interface PiiRedactorOptions {
  customColumns?: string[];
  customRules?: CustomPiiRule[];
  enableFormatPreserving?: boolean;
  salt?: string;
}

/**
 * Deterministic, keyed format-preserving pseudonymization.
 * Preserves referential integrity across relational tables during AI agent test runs.
 */
export function formatPreservingPseudonym(
  value: string,
  category: string,
  salt = "dbshield-default-salt",
): string {
  const hash = crypto.createHmac("sha256", salt).update(value).digest("hex");
  const shortHash = hash.slice(0, 8);

  switch (category.toUpperCase()) {
    case "EMAIL": {
      const atIdx = value.indexOf("@");
      const domain = atIdx > 0 ? value.slice(atIdx) : "@masked.local";
      return `user_${shortHash}${domain}`;
    }
    case "PHONE": {
      const digits = value.replace(/\D/g, "");
      const last4 = digits.slice(-4) || "0000";
      return `+***-***-${last4}`;
    }
    case "CREDIT_CARD": {
      const digits = value.replace(/\D/g, "");
      const last4 = digits.slice(-4) || "0000";
      return `****-****-****-${last4}`;
    }
    case "SSN_OR_NATIONAL_ID": {
      const digits = value.replace(/\D/g, "");
      const last4 = digits.slice(-4) || "0000";
      return `***-**-${last4}`;
    }
    case "UUID":
    case "ID": {
      const p1 = hash.slice(0, 8);
      const p2 = hash.slice(8, 12);
      const p3 = `4${hash.slice(13, 16)}`;
      const p4 = `8${hash.slice(17, 20)}`;
      const p5 = hash.slice(20, 32);
      return `${p1}-${p2}-${p3}-${p4}-${p5}`;
    }
    default: {
      return `[MASKED_${category}_${shortHash}]`;
    }
  }
}

export class PiiRedactor {
  private readonly customColumns: Set<string>;
  private readonly customRules: CustomPiiRule[];
  private readonly enableFormatPreserving: boolean;
  private readonly salt: string;

  constructor(
    customColumnsOrOptions: string[] | PiiRedactorOptions = [],
    customRules: CustomPiiRule[] = [],
    enableFormatPreserving = false,
    salt = "dbshield-default-salt",
  ) {
    if (Array.isArray(customColumnsOrOptions)) {
      this.customColumns = new Set(customColumnsOrOptions.map((c) => c.toLowerCase().trim()));
      this.customRules = customRules;
      this.enableFormatPreserving = enableFormatPreserving;
      this.salt = salt;
    } else {
      this.customColumns = new Set(
        (customColumnsOrOptions.customColumns || []).map((c) => c.toLowerCase().trim()),
      );
      this.customRules = customColumnsOrOptions.customRules || [];
      this.enableFormatPreserving = customColumnsOrOptions.enableFormatPreserving ?? false;
      this.salt = customColumnsOrOptions.salt || "dbshield-default-salt";
    }
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
    customColumns: Set<string> = this.customColumns,
  ): { value: unknown; redacted: boolean; category?: string } {
    if (value === null || value === undefined) {
      return { value, redacted: false };
    }

    const colLower = columnName.toLowerCase();
    const strVal = typeof value === "string" ? value : String(value);

    // Check custom configured PII rules (patterns and column regex)
    for (const rule of this.customRules) {
      if (rule.columnPattern && new RegExp(rule.columnPattern, "i").test(colLower)) {
        const masked =
          rule.formatPreserving || this.enableFormatPreserving
            ? formatPreservingPseudonym(strVal, rule.name, this.salt)
            : rule.replacement || `[REDACTED_${rule.name.toUpperCase()}]`;
        return {
          value: masked,
          redacted: true,
          category: rule.name,
        };
      }
      if (rule.pattern) {
        const rx = new RegExp(rule.pattern, "gi");
        if (rx.test(strVal)) {
          const replacement =
            rule.formatPreserving || this.enableFormatPreserving
              ? formatPreservingPseudonym(strVal, rule.name, this.salt)
              : rule.replacement || `[REDACTED_${rule.name.toUpperCase()}]`;
          const replaced = strVal.replace(rx, replacement);
          return {
            value: replaced,
            redacted: true,
            category: rule.name,
          };
        }
      }
    }

    // Check custom configured PII columns
    if (customColumns.has(colLower)) {
      return {
        value: this.enableFormatPreserving
          ? formatPreservingPseudonym(strVal, "CUSTOM", this.salt)
          : "[REDACTED_CUSTOM]",
        redacted: true,
        category: "CUSTOM",
      };
    }

    // Check column name heuristics
    for (const rule of PII_RULES) {
      if (rule.columnRegex.test(colLower)) {
        return {
          value: this.enableFormatPreserving
            ? formatPreservingPseudonym(strVal, rule.category, this.salt)
            : rule.mask(strVal),
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
            currentVal = currentVal.replace(globalRegex, (match) =>
              this.enableFormatPreserving
                ? formatPreservingPseudonym(match, rule.category, this.salt)
                : rule.mask(match),
            );
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

  /**
   * Redacts inline PII from arbitrary text (emails, phones, credit cards, SSNs, tokens).
   */
  public redactText(text: string): string {
    if (!text || typeof text !== "string") return text;
    let result = text;

    for (const rule of PII_RULES) {
      if (rule.valueRegex) {
        const globalRegex = new RegExp(rule.valueRegex.source, "gi");
        result = result.replace(globalRegex, (match) => rule.mask(match));
      }
    }
    return result;
  }

  /**
   * Sanitizes sensitive SQL literals (in INSERT, UPDATE, WHERE, SET) and embedded credentials before storage or retrieval.
   */
  public redactSql(sql: string): string {
    if (!sql || typeof sql !== "string") return sql;

    let sanitized = sql;

    // 1. Redact values in INSERT INTO table (cols) VALUES (vals)
    sanitized = redactInsertValues(sanitized, this.customColumns);

    // 2. Redact assignment / equality / comparison literals for sensitive column names
    const sensitiveKeyPattern =
      /\b(password|passwd|pwd|password_hash|passwd_hash|secret|secret_key|private_key|token|access_token|auth_token|api_key|apikey|salt|hash|ssn|credit_card|card_number|card|cvv|cvc)\s*(=|!=|<>|:|:=|\bLIKE\b|\bILIKE\b|\bIS\b)\s*('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")/gi;
    sanitized = sanitized.replace(sensitiveKeyPattern, (_match, col, op, val) => {
      const { maskFn } = getColumnRule(col, this.customColumns);
      const cleanVal = val.replace(/^['"]|['"]$/g, "");
      const masked = maskFn ? maskFn(cleanVal) : "[REDACTED_SECRET]";
      return `${col} ${op} '${masked}'`;
    });

    // 3. Redact custom PII column assignments
    for (const customCol of this.customColumns) {
      const escaped = customCol.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const customPattern = new RegExp(
        `\\b(${escaped})\\s*(=|!=|<>|:|:=|\\bLIKE\\b|\\bILIKE\\b|\\bIS\\b)\\s*('(?:[^'\\\\]|\\\\.)*'|"(?:[^"\\\\]|\\\\.)*")`,
        "gi",
      );
      sanitized = sanitized.replace(customPattern, (_match, col, op) => {
        return `${col} ${op} '[REDACTED_CUSTOM]'`;
      });
    }

    // 4. Redact inline values matching PII value regexes (emails, phones, credit cards, SSNs, JWTs)
    sanitized = this.redactText(sanitized);

    return sanitized;
  }

  /**
   * Redacts database error messages before returning them to clients or recording in audit logs.
   */
  public redactErrorMessage(error: string): string {
    if (!error || typeof error !== "string") return error;
    return this.redactText(this.redactSql(error));
  }
}

function splitSqlTuples(tupleStr: string): string[] {
  const items: string[] = [];
  let current = "";
  let inSingleQuote = false;
  let inDoubleQuote = false;

  for (let i = 0; i < tupleStr.length; i++) {
    const char = tupleStr[i];
    const next = tupleStr[i + 1];

    if (inSingleQuote) {
      current += char;
      if (char === "'" && next === "'") {
        current += next;
        i++;
      } else if (char === "'") {
        inSingleQuote = false;
      }
    } else if (inDoubleQuote) {
      current += char;
      if (char === '"' && next === '"') {
        current += next;
        i++;
      } else if (char === '"') {
        inDoubleQuote = false;
      }
    } else if (char === "'") {
      inSingleQuote = true;
      current += char;
    } else if (char === '"') {
      inDoubleQuote = true;
      current += char;
    } else if (char === ",") {
      items.push(current.trim());
      current = "";
    } else {
      current += char;
    }
  }
  if (current.trim().length > 0) {
    items.push(current.trim());
  }
  return items;
}

function getColumnRule(
  col: string,
  customCols: Set<string>,
): { isSensitive: boolean; maskFn?: (val: string) => string } {
  const cleanCol = col
    .replace(/[`"'\[\]]/g, "")
    .trim()
    .toLowerCase();
  if (customCols.has(cleanCol)) {
    return { isSensitive: true, maskFn: () => "[REDACTED_CUSTOM]" };
  }
  for (const rule of PII_RULES) {
    if (rule.columnRegex.test(cleanCol)) {
      return { isSensitive: true, maskFn: rule.mask };
    }
  }
  return { isSensitive: false };
}

function redactInsertValues(sql: string, customCols: Set<string>): string {
  const insertPattern = /\bINSERT\s+INTO\s+[^(]+\(([^)]+)\)\s*VALUES\s*([\s\S]+)$/i;
  const match = sql.match(insertPattern);
  if (!match) return sql;

  const colsPart = match[1];
  const valuesPart = match[2];
  const columns = splitSqlTuples(colsPart);

  const redactionMaskFnsByIndex = new Map<number, (val: string) => string>();
  columns.forEach((col, idx) => {
    const { isSensitive, maskFn } = getColumnRule(col, customCols);
    if (isSensitive && maskFn) {
      redactionMaskFnsByIndex.set(idx, maskFn);
    }
  });

  if (redactionMaskFnsByIndex.size === 0) {
    return sql;
  }

  const tuplePattern = /\(([^)]+)\)/g;
  const newValuesPart = valuesPart.replace(tuplePattern, (_tupleMatch, innerTuple) => {
    const values = splitSqlTuples(innerTuple);
    const maskedValues = values.map((val, idx) => {
      const maskFn = redactionMaskFnsByIndex.get(idx);
      if (maskFn) {
        const cleanVal = val.replace(/^['"]|['"]$/g, "");
        return `'${maskFn(cleanVal)}'`;
      }
      return val;
    });
    return `(${maskedValues.join(", ")})`;
  });

  return sql.slice(0, match.index! + match[0].length - valuesPart.length) + newValuesPart;
}
