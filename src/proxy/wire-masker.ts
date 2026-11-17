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

  /**
   * Masks a raw PostgreSQL 'D' (DataRow) wire protocol buffer directly.
   * Format: 'D' (1B) + Length (4B BE) + Column Count (2B BE) + [ColLen (4B BE) + ColData (NB)]*
   */
  public maskPostgresDataRow(buf: Buffer, columnNames: string[] = []): Buffer {
    if (buf.length < 7 || buf[0] !== 0x44) {
      return buf;
    }

    const colCount = buf.readInt16BE(5);
    const newColBuffers: Buffer[] = [];
    let offset = 7;

    for (let i = 0; i < colCount && offset < buf.length; i++) {
      const colLen = buf.readInt32BE(offset);
      offset += 4;

      if (colLen === -1) {
        // NULL column
        const nullBuf = Buffer.alloc(4);
        nullBuf.writeInt32BE(-1, 0);
        newColBuffers.push(nullBuf);
      } else {
        const rawVal = buf.subarray(offset, offset + colLen).toString("utf8");
        offset += colLen;

        const colName = (columnNames[i] || `col_${i}`).toLowerCase();
        let valToEncode = rawVal;

        if (this.maskedColumns.has(colName)) {
          valToEncode = this.maskValue(rawVal, colName);
        }

        const valBuf = Buffer.from(valToEncode, "utf8");
        const lenBuf = Buffer.alloc(4);
        lenBuf.writeInt32BE(valBuf.length, 0);
        newColBuffers.push(Buffer.concat([lenBuf, valBuf]));
      }
    }

    const dataPayload = Buffer.concat(newColBuffers);
    const totalLen = 4 + 2 + dataPayload.length;
    const header = Buffer.alloc(7);
    header[0] = 0x44; // 'D'
    header.writeInt32BE(totalLen, 1);
    header.writeInt16BE(colCount, 5);

    return Buffer.concat([header, dataPayload]);
  }

  /**
   * Masks a raw MySQL text resultset row packet buffer.
   * Format: 3B Payload Length (LE) + 1B Sequence ID + Length-Encoded Strings
   */
  public maskMysqlRowPacket(buf: Buffer, columnNames: string[] = []): Buffer {
    if (buf.length < 5) return buf;

    const seqId = buf[3];
    let offset = 4;
    const maskedColParts: Buffer[] = [];
    let colIndex = 0;

    while (offset < buf.length) {
      const firstByte = buf[offset++];
      if (firstByte === 0xfb) {
        // NULL field in MySQL
        maskedColParts.push(Buffer.from([0xfb]));
        colIndex++;
        continue;
      }

      let strLen = 0;
      if (firstByte < 0xfb) {
        strLen = firstByte;
      } else if (firstByte === 0xfc) {
        strLen = buf.readUInt16LE(offset);
        offset += 2;
      } else if (firstByte === 0xfd) {
        strLen = buf[offset] | (buf[offset + 1] << 8) | (buf[offset + 2] << 16);
        offset += 3;
      }

      const rawVal = buf.subarray(offset, offset + strLen).toString("utf8");
      offset += strLen;

      const colName = (columnNames[colIndex] || `col_${colIndex}`).toLowerCase();
      let finalVal = rawVal;

      if (this.maskedColumns.has(colName)) {
        finalVal = this.maskValue(rawVal, colName);
      }

      const strBuf = Buffer.from(finalVal, "utf8");
      // Encode length-encoded string
      let lenHeader: Buffer;
      if (strBuf.length < 251) {
        lenHeader = Buffer.from([strBuf.length]);
      } else if (strBuf.length <= 0xffff) {
        lenHeader = Buffer.alloc(3);
        lenHeader[0] = 0xfc;
        lenHeader.writeUInt16LE(strBuf.length, 1);
      } else {
        lenHeader = Buffer.alloc(4);
        lenHeader[0] = 0xfd;
        lenHeader[1] = strBuf.length & 0xff;
        lenHeader[2] = (strBuf.length >> 8) & 0xff;
        lenHeader[3] = (strBuf.length >> 16) & 0xff;
      }

      maskedColParts.push(Buffer.concat([lenHeader, strBuf]));
      colIndex++;
    }

    const payload = Buffer.concat(maskedColParts);
    const packetHeader = Buffer.alloc(4);
    packetHeader[0] = payload.length & 0xff;
    packetHeader[1] = (payload.length >> 8) & 0xff;
    packetHeader[2] = (payload.length >> 16) & 0xff;
    packetHeader[3] = seqId;

    return Buffer.concat([packetHeader, payload]);
  }

  /**
   * Transparently masks streaming chunks based on protocol frame identification.
   */
  public maskStreamingChunk(chunk: Buffer, columnNames: string[] = []): Buffer {
    if (chunk.length >= 7 && chunk[0] === 0x44) {
      return this.maskPostgresDataRow(chunk, columnNames);
    }
    return chunk;
  }
}
