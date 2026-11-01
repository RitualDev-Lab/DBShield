/**
 * MySQL Wire Protocol Packet Parser & Serializer.
 * Lightweight zero-dependency implementation using Node.js Buffer utilities.
 */

export const MYSQL_COM_QUIT = 0x01;
export const MYSQL_COM_INIT_DB = 0x02;
export const MYSQL_COM_QUERY = 0x03;
export const MYSQL_COM_FIELD_LIST = 0x04;
export const MYSQL_COM_PING = 0x0e;
export const MYSQL_COM_STMT_PREPARE = 0x16;
export const MYSQL_COM_STMT_EXECUTE = 0x17;

export interface DecodedMysqlPacket {
  length: number;
  sequenceId: number;
  command?: number;
  payload: Buffer;
  raw: Buffer;
}

/**
 * Checks if buffer contains a complete MySQL packet (4-byte header + payload).
 */
export function hasCompleteMysqlPacket(buffer: Buffer): boolean {
  if (buffer.length < 4) return false;
  const payloadLength = buffer[0] | (buffer[1] << 8) | (buffer[2] << 16);
  return buffer.length >= 4 + payloadLength;
}

/**
 * Decodes the first MySQL packet from an incoming stream buffer.
 */
export function decodeMysqlPacket(buffer: Buffer): DecodedMysqlPacket | null {
  if (buffer.length < 4) return null;

  const length = buffer[0] | (buffer[1] << 8) | (buffer[2] << 16);
  const sequenceId = buffer[3];

  if (buffer.length < 4 + length) return null;

  const payload = buffer.subarray(4, 4 + length);
  const raw = buffer.subarray(0, 4 + length);
  const command = payload.length > 0 ? payload[0] : undefined;

  return {
    length,
    sequenceId,
    command,
    payload,
    raw,
  };
}

/**
 * Checks whether the packet contains an executable SQL query (COM_QUERY or COM_STMT_PREPARE).
 */
export function isMysqlQueryPacket(packet: DecodedMysqlPacket): boolean {
  return packet.command === MYSQL_COM_QUERY || packet.command === MYSQL_COM_STMT_PREPARE;
}

/**
 * Extracts SQL text string from a COM_QUERY or COM_STMT_PREPARE packet.
 */
export function extractSqlFromMysqlPacket(packet: DecodedMysqlPacket): string | null {
  if (!isMysqlQueryPacket(packet) || packet.payload.length <= 1) {
    return null;
  }
  return packet.payload.subarray(1).toString("utf-8");
}

/**
 * Encodes a standard MySQL Error Packet (0xFF).
 */
export function encodeMysqlErrorPacket(options: {
  sequenceId?: number;
  errorCode?: number;
  sqlState?: string;
  message: string;
}): Buffer {
  const sequenceId = options.sequenceId ?? 1;
  const errorCode = options.errorCode ?? 1105; // ER_UNKNOWN_ERROR / generic
  const sqlState = (options.sqlState ?? "HY000").slice(0, 5);
  const msgBuf = Buffer.from(options.message, "utf-8");

  // Payload: 1 byte (0xFF) + 2 bytes errorCode + 1 byte ('#') + 5 bytes sqlState + msgBuf
  const payloadLength = 1 + 2 + 1 + 5 + msgBuf.length;
  const packet = Buffer.alloc(4 + payloadLength);

  // 3-byte payload length (little-endian)
  packet[0] = payloadLength & 0xff;
  packet[1] = (payloadLength >> 8) & 0xff;
  packet[2] = (payloadLength >> 16) & 0xff;
  // 1-byte sequence ID
  packet[3] = sequenceId & 0xff;

  // 0xFF error marker
  packet[4] = 0xff;
  // Error code (uint16 LE)
  packet.writeUInt16LE(errorCode, 5);
  // SQL state marker '#'
  packet[7] = 0x23;
  // 5-byte SQL state
  packet.write(sqlState, 8, 5, "ascii");
  // Error message
  msgBuf.copy(packet, 13);

  return packet;
}

/**
 * Encodes a standard MySQL OK Packet (0x00).
 */
export function encodeMysqlOkPacket(options: {
  sequenceId?: number;
  affectedRows?: number;
  lastInsertId?: number;
  serverStatus?: number;
  warnings?: number;
}): Buffer {
  const sequenceId = options.sequenceId ?? 1;
  const affectedRows = options.affectedRows ?? 0;
  const lastInsertId = options.lastInsertId ?? 0;
  const serverStatus = options.serverStatus ?? 0x0002; // AUTOCOMMIT
  const warnings = options.warnings ?? 0;

  // Simple OK packet: 0x00 + affectedRows (1 byte) + lastInsertId (1 byte) + status (2 bytes) + warnings (2 bytes)
  const payloadLength = 1 + 1 + 1 + 2 + 2;
  const packet = Buffer.alloc(4 + payloadLength);

  packet[0] = payloadLength & 0xff;
  packet[1] = (payloadLength >> 8) & 0xff;
  packet[2] = (payloadLength >> 16) & 0xff;
  packet[3] = sequenceId & 0xff;

  packet[4] = 0x00; // OK marker
  packet[5] = affectedRows & 0xff;
  packet[6] = lastInsertId & 0xff;
  packet.writeUInt16LE(serverStatus, 7);
  packet.writeUInt16LE(warnings, 9);

  return packet;
}
