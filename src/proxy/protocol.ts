/**
 * PostgreSQL Wire Protocol Version 3.0 Parser & Encoder.
 * Zero-dependency implementation using Node.js Buffer utilities.
 */

export const PG_PROTOCOL_V3 = 196608; // (3 << 16) | 0
export const PG_SSL_REQUEST = 80877103; // (1234 << 16) | 5679
export const PG_CANCEL_REQUEST = 80877104; // (1234 << 16) | 5680

export type MessageType =
  | "Query"
  | "Parse"
  | "Bind"
  | "Describe"
  | "Execute"
  | "Sync"
  | "Terminate"
  | "PasswordMessage"
  | "StartupMessage"
  | "SSLRequest"
  | "CancelRequest"
  | "Unknown";

export interface DecodedFrontendMessage {
  type: MessageType;
  typeChar?: string;
  length: number;
  payload: Buffer;
  raw: Buffer;
}

export interface ErrorResponseFields {
  severity?: string;
  code?: string;
  message: string;
  detail?: string;
  hint?: string;
}

/**
 * Check if buffer starts with an SSLRequest packet (8 bytes: length=8, code=80877103).
 */
export function isSslRequest(buffer: Buffer): boolean {
  if (buffer.length < 8) return false;
  const length = buffer.readInt32BE(0);
  const code = buffer.readInt32BE(4);
  return length === 8 && code === PG_SSL_REQUEST;
}

/**
 * Check if buffer is a PostgreSQL StartupMessage.
 */
export function isStartupMessage(buffer: Buffer): boolean {
  if (buffer.length < 8) return false;
  const length = buffer.readInt32BE(0);
  const version = buffer.readInt32BE(4);
  return length >= 8 && version === PG_PROTOCOL_V3;
}

/**
 * Parses key-value parameters from a PostgreSQL StartupMessage body.
 */
export function parseStartupParams(buffer: Buffer): Record<string, string> {
  const params: Record<string, string> = {};
  if (buffer.length <= 8) return params;

  // Parameters start after the 4-byte length and 4-byte version
  let offset = 8;
  const totalLength = Math.min(buffer.length, buffer.readInt32BE(0));

  while (offset < totalLength) {
    // Find next null terminator for key
    const keyEnd = buffer.indexOf(0, offset);
    if (keyEnd === -1 || keyEnd >= totalLength) break;
    const key = buffer.toString("utf8", offset, keyEnd);
    offset = keyEnd + 1;
    if (key === "") break; // End of parameters

    // Find next null terminator for value
    const valEnd = buffer.indexOf(0, offset);
    if (valEnd === -1 || valEnd > totalLength) break;
    const val = buffer.toString("utf8", offset, valEnd);
    offset = valEnd + 1;

    params[key] = val;
  }

  return params;
}

/**
 * Parse one frontend message from the buffer if complete.
 * Returns null if buffer does not yet contain a complete message frame.
 */
export function parseFrontendFrame(
  buffer: Buffer,
  expectingStartup = false,
): { message: DecodedFrontendMessage; bytesConsumed: number } | null {
  if (buffer.length < 4) return null;

  if (expectingStartup) {
    if (isSslRequest(buffer)) {
      return {
        message: {
          type: "SSLRequest",
          length: 8,
          payload: buffer.subarray(4, 8),
          raw: buffer.subarray(0, 8),
        },
        bytesConsumed: 8,
      };
    }

    const length = buffer.readInt32BE(0);
    if (length < 8 || length > 10000) {
      // Invalid startup packet
      return null;
    }
    if (buffer.length < length) {
      return null; // Need more data
    }

    const version = buffer.readInt32BE(4);
    let type: MessageType = "StartupMessage";
    if (version === PG_CANCEL_REQUEST) {
      type = "CancelRequest";
    }

    return {
      message: {
        type,
        length,
        payload: buffer.subarray(4, length),
        raw: buffer.subarray(0, length),
      },
      bytesConsumed: length,
    };
  }

  // Standard frontend message: 1 byte char type, 4 bytes length
  if (buffer.length < 5) return null;

  const typeChar = String.fromCharCode(buffer[0]);
  const length = buffer.readInt32BE(1);
  const totalFrameSize = 1 + length;

  if (buffer.length < totalFrameSize) {
    return null; // Need more data
  }

  let type: MessageType = "Unknown";
  switch (typeChar) {
    case "Q":
      type = "Query";
      break;
    case "P":
      type = "Parse";
      break;
    case "B":
      type = "Bind";
      break;
    case "D":
      type = "Describe";
      break;
    case "E":
      type = "Execute";
      break;
    case "S":
      type = "Sync";
      break;
    case "X":
      type = "Terminate";
      break;
    case "p":
      type = "PasswordMessage";
      break;
  }

  return {
    message: {
      type,
      typeChar,
      length,
      payload: buffer.subarray(5, totalFrameSize),
      raw: buffer.subarray(0, totalFrameSize),
    },
    bytesConsumed: totalFrameSize,
  };
}

/**
 * Extract SQL query string from a Query ('Q') or Parse ('P') packet payload.
 */
export function extractSqlFromPayload(type: MessageType, payload: Buffer): string | null {
  if (type === "Query") {
    // Null-terminated string
    const nullIdx = payload.indexOf(0);
    if (nullIdx !== -1) {
      return payload.toString("utf8", 0, nullIdx);
    }
    return payload.toString("utf8");
  }

  if (type === "Parse") {
    // Format: statementName\0 query\0 numParams (int16) paramOids...
    const stmtEnd = payload.indexOf(0);
    if (stmtEnd === -1) return null;
    const queryStart = stmtEnd + 1;
    const queryEnd = payload.indexOf(0, queryStart);
    if (queryEnd === -1) return null;
    return payload.toString("utf8", queryStart, queryEnd);
  }

  return null;
}

/**
 * Encode an ErrorResponse ('E') packet according to Postgres Wire Protocol v3.
 */
export function encodeErrorResponse(fields: ErrorResponseFields): Buffer {
  const parts: Buffer[] = [];

  const addField = (code: string, value: string) => {
    parts.push(Buffer.from(code, "ascii"));
    parts.push(Buffer.from(value, "utf8"));
    parts.push(Buffer.from([0]));
  };

  addField("S", fields.severity || "ERROR");
  addField("V", fields.severity || "ERROR");
  addField("C", fields.code || "42501"); // Default: 42501 (insufficient_privilege)
  addField("M", fields.message);
  if (fields.detail) addField("D", fields.detail);
  if (fields.hint) addField("H", fields.hint);
  parts.push(Buffer.from([0])); // Final terminator null byte

  const body = Buffer.concat(parts);
  const header = Buffer.alloc(5);
  header.writeUInt8(0x45, 0); // 'E'
  header.writeInt32BE(body.length + 4, 1);

  return Buffer.concat([header, body]);
}

/**
 * Encode a ReadyForQuery ('Z') packet according to Postgres Wire Protocol v3.
 * Status: 'I' (idle), 'T' (in transaction), 'E' (in failed transaction).
 */
export function encodeReadyForQuery(status: "I" | "T" | "E" = "I"): Buffer {
  const buf = Buffer.alloc(6);
  buf.writeUInt8(0x5a, 0); // 'Z'
  buf.writeInt32BE(5, 1); // length = 5
  buf.writeUInt8(status.charCodeAt(0), 5);
  return buf;
}

/**
 * Encode a NoticeResponse ('N') packet.
 */
export function encodeNoticeResponse(message: string, detail?: string): Buffer {
  const parts: Buffer[] = [];
  const addField = (code: string, value: string) => {
    parts.push(Buffer.from(code, "ascii"));
    parts.push(Buffer.from(value, "utf8"));
    parts.push(Buffer.from([0]));
  };

  addField("S", "NOTICE");
  addField("V", "NOTICE");
  addField("C", "00000");
  addField("M", message);
  if (detail) addField("D", detail);
  parts.push(Buffer.from([0]));

  const body = Buffer.concat(parts);
  const header = Buffer.alloc(5);
  header.writeUInt8(0x4e, 0); // 'N'
  header.writeInt32BE(body.length + 4, 1);

  return Buffer.concat([header, body]);
}

/**
 * Encode an SSL negation response ('N', 1 byte) refusing SSL so client negotiates plaintext.
 */
export function encodeSslDenial(): Buffer {
  return Buffer.from([0x4e]); // 'N'
}
