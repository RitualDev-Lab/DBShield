import crypto from "node:crypto";
import { formatPreservingPseudonym } from "../pii/redactor.js";

/**
 * Protocol-Level Dynamic PII Masking and Format-Preserving Pseudonymization.
 * Intercepts query results and masks sensitive columns before emitting them to LLM context.
 */

export interface WireMaskerConfig {
  salt?: string;
  maskedColumns?: string[];
  enableFormatPreserving?: boolean;
}

export class ProtocolWireMasker {
  private readonly salt: string;
  private readonly maskedColumns: Set<string>;
  private readonly enableFormatPreserving: boolean;

  constructor(config: WireMaskerConfig = {}) {
    this.salt = config.salt ?? "dbshield-wire-salt";
    this.enableFormatPreserving = config.enableFormatPreserving ?? true;
    this.maskedColumns = new Set(
      (
        config.maskedColumns ?? [
          "email",
          "phone",
          "ssn",
          "national_id",
          "credit_card",
          "card_number",
          "api_key",
          "secret",
          "password",
          "access_token",
          "jwt",
        ]
      ).map((c) => c.toLowerCase()),
    );
  }

  /**
   * Masks sensitive fields in a row dictionary before serialization
   */
  public maskRow(row: Record<string, unknown>): Record<string, unknown> {
    const masked: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(row)) {
      const lowerKey = key.toLowerCase();
      if (value === null || value === undefined) {
        masked[key] = value;
        continue;
      }

      if (this.maskedColumns.has(lowerKey)) {
        masked[key] = this.maskValue(String(value), lowerKey);
      } else {
        masked[key] = value;
      }
    }

    return masked;
  }

  public maskValue(value: string, columnOrCategory: string): string {
    const col = columnOrCategory.toLowerCase();
    let category = "SENSITIVE";

    if (col.includes("email")) category = "EMAIL";
    else if (col.includes("phone")) category = "PHONE";
    else if (col.includes("card")) category = "CREDIT_CARD";
    else if (col.includes("ssn") || col.includes("id")) category = "SSN_OR_NATIONAL_ID";

    if (this.enableFormatPreserving) {
      return formatPreservingPseudonym(value, category, this.salt);
    }

    const hash = crypto.createHmac("sha256", this.salt).update(value).digest("hex").slice(0, 8);
    return `[MASKED_${category}_${hash}]`;
  }

  /**
   * Batch masks an array of rows
   */
  public maskRows(rows: Record<string, unknown>[]): Record<string, unknown>[] {
    return rows.map((r) => this.maskRow(r));
  }
}
