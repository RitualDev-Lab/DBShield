//! MySQL Wire-Level Packet Parser & Encoder.
//!
//! Handles MySQL packet framing, COM_QUERY interception, and error packet synthesis.

use bytes::{Buf, BufMut, Bytes, BytesMut};

pub const COM_SLEEP: u8 = 0x00;
pub const COM_QUIT: u8 = 0x01;
pub const COM_INIT_DB: u8 = 0x02;
pub const COM_QUERY: u8 = 0x03;
pub const COM_PING: u8 = 0x0E;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MySqlCommand {
    Query(String),
    InitDb(String),
    Ping,
    Quit,
    Other { command_id: u8, payload: Vec<u8> },
}

pub struct MySqlPacket {
    pub sequence_id: u8,
    pub command: MySqlCommand,
}

pub struct MySqlWireParser;

impl MySqlWireParser {
    pub fn parse_packet(buf: &mut BytesMut) -> Option<MySqlPacket> {
        if buf.len() < 4 {
            return None;
        }

        // MySQL packet header: 3-byte payload length (little endian) + 1-byte sequence ID
        let payload_len = (buf[0] as usize) | ((buf[1] as usize) << 8) | ((buf[2] as usize) << 16);
        let seq_id = buf[3];
        let total_len = 4 + payload_len;

        if buf.len() < total_len {
            return None;
        }

        let payload = &buf[4..total_len];
        if payload.is_empty() {
            buf.advance(total_len);
            return None;
        }

        let cmd_byte = payload[0];
        let cmd = match cmd_byte {
            COM_QUERY => {
                let query_str = String::from_utf8_lossy(&payload[1..]).to_string();
                MySqlCommand::Query(query_str)
            }
            COM_INIT_DB => {
                let db_name = String::from_utf8_lossy(&payload[1..]).to_string();
                MySqlCommand::InitDb(db_name)
            }
            COM_PING => MySqlCommand::Ping,
            COM_QUIT => MySqlCommand::Quit,
            other => MySqlCommand::Other {
                command_id: other,
                payload: payload[1..].to_vec(),
            },
        };

        buf.advance(total_len);
        Some(MySqlPacket {
            sequence_id: seq_id,
            command: cmd,
        })
    }

    pub fn encode_error_packet(seq_id: u8, error_code: u16, sql_state: &str, message: &str) -> Bytes {
        let mut body = BytesMut::new();
        body.put_u8(0xFF); // Error indicator
        body.put_u16_le(error_code);
        body.put_u8(b'#'); // SQL state marker
        let state_bytes = sql_state.as_bytes();
        let state_5 = if state_bytes.len() >= 5 {
            &state_bytes[..5]
        } else {
            b"HY000"
        };
        body.put_slice(state_5);
        body.put_slice(message.as_bytes());

        let payload_len = body.len();
        let mut packet = BytesMut::with_capacity(4 + payload_len);
        packet.put_u8((payload_len & 0xFF) as u8);
        packet.put_u8(((payload_len >> 8) & 0xFF) as u8);
        packet.put_u8(((payload_len >> 16) & 0xFF) as u8);
        packet.put_u8(seq_id);
        packet.put(body);
        packet.freeze()
    }

    pub fn encode_ok_packet(seq_id: u8, affected_rows: u64, last_insert_id: u64) -> Bytes {
        let mut body = BytesMut::new();
        body.put_u8(0x00); // OK header
        body.put_u8(affected_rows as u8);
        body.put_u8(last_insert_id as u8);
        body.put_u16_le(0x0002); // Autocommit flag
        body.put_u16_le(0); // Warnings count

        let payload_len = body.len();
        let mut packet = BytesMut::with_capacity(4 + payload_len);
        packet.put_u8((payload_len & 0xFF) as u8);
        packet.put_u8(((payload_len >> 8) & 0xFF) as u8);
        packet.put_u8(((payload_len >> 16) & 0xFF) as u8);
        packet.put_u8(seq_id);
        packet.put(body);
        packet.freeze()
    }
}
