//! PostgreSQL Frontend/Backend Protocol 3.0 Wire Parser & Encoder.
//!
//! Provides zero-copy parsing of PostgreSQL framing directly from byte buffers.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashMap;

pub const PG_PROTOCOL_V3: i32 = (3 << 16) | 0;
pub const PG_SSL_REQUEST: i32 = (1234 << 16) | 5679;
pub const PG_CANCEL_REQUEST: i32 = (1234 << 16) | 5680;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrontendMessage {
    Query(String),
    Parse { statement: String, query: String },
    Bind { portal: String, statement: String },
    Describe { kind: u8, name: String },
    Execute { portal: String, max_rows: i32 },
    Sync,
    Terminate,
    StartupMessage(HashMap<String, String>),
    SslRequest,
    CancelRequest { pid: i32, key: i32 },
    Unknown(u8),
}

/// Zero-copy PostgreSQL wire packet decoder
pub struct PgWireParser;

impl PgWireParser {
    pub fn is_ssl_request(buf: &[u8]) -> bool {
        if buf.len() < 8 {
            return false;
        }
        let len = i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let code = i32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        len == 8 && code == PG_SSL_REQUEST
    }

    pub fn is_startup_message(buf: &[u8]) -> bool {
        if buf.len() < 8 {
            return false;
        }
        let len = i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let version = i32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        len >= 8 && version == PG_PROTOCOL_V3
    }

    pub fn parse_startup_params(buf: &[u8]) -> HashMap<String, String> {
        let mut params = HashMap::new();
        if buf.len() <= 8 {
            return params;
        }

        let total_len = std::cmp::min(
            buf.len(),
            i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize,
        );
        let mut offset = 8;

        while offset < total_len {
            if let Some(key_end) = buf[offset..total_len].iter().position(|&b| b == 0) {
                let key_slice = &buf[offset..offset + key_end];
                offset += key_end + 1;
                if key_slice.is_empty() {
                    break;
                }
                let key = String::from_utf8_lossy(key_slice).to_string();

                if let Some(val_end) = buf[offset..total_len].iter().position(|&b| b == 0) {
                    let val_slice = &buf[offset..offset + val_end];
                    offset += val_end + 1;
                    let val = String::from_utf8_lossy(val_slice).to_string();
                    params.insert(key, val);
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        params
    }

    pub fn parse_frontend_frame(
        buf: &mut BytesMut,
        expecting_startup: bool,
    ) -> Option<FrontendMessage> {
        if expecting_startup {
            if buf.len() < 8 {
                return None;
            }
            let len = i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            if buf.len() < len {
                return None;
            }

            let code = i32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
            if code == PG_SSL_REQUEST {
                buf.advance(8);
                return Some(FrontendMessage::SslRequest);
            }
            if code == PG_CANCEL_REQUEST {
                let pid = i32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
                let key = i32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
                buf.advance(len);
                return Some(FrontendMessage::CancelRequest { pid, key });
            }
            if code == PG_PROTOCOL_V3 {
                let params = Self::parse_startup_params(&buf[..len]);
                buf.advance(len);
                return Some(FrontendMessage::StartupMessage(params));
            }
        }

        if buf.len() < 5 {
            return None;
        }

        let type_char = buf[0];
        let length = i32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        let total_frame_len = 1 + length;

        if buf.len() < total_frame_len {
            return None;
        }

        let payload = &buf[5..total_frame_len];

        let msg = match type_char {
            b'Q' => {
                let query_str = if let Some(end) = payload.iter().position(|&b| b == 0) {
                    String::from_utf8_lossy(&payload[..end]).to_string()
                } else {
                    String::from_utf8_lossy(payload).to_string()
                };
                FrontendMessage::Query(query_str)
            }
            b'S' => FrontendMessage::Sync,
            b'X' => FrontendMessage::Terminate,
            other => FrontendMessage::Unknown(other),
        };

        buf.advance(total_frame_len);
        Some(msg)
    }

    pub fn encode_error_response(severity: &str, code: &str, message: &str) -> Bytes {
        let mut body = BytesMut::new();
        // Severity
        body.put_u8(b'S');
        body.put_slice(severity.as_bytes());
        body.put_u8(0);
        // Code
        body.put_u8(b'C');
        body.put_slice(code.as_bytes());
        body.put_u8(0);
        // Message
        body.put_u8(b'M');
        body.put_slice(message.as_bytes());
        body.put_u8(0);
        body.put_u8(0); // Null terminator

        let mut packet = BytesMut::new();
        packet.put_u8(b'E');
        packet.put_i32((body.len() + 4) as i32);
        packet.put(body);
        packet.freeze()
    }

    pub fn encode_ready_for_query(status: u8) -> Bytes {
        let mut packet = BytesMut::with_capacity(6);
        packet.put_u8(b'Z');
        packet.put_i32(5);
        packet.put_u8(status);
        packet.freeze()
    }

    pub fn encode_command_complete(tag: &str) -> Bytes {
        let mut packet = BytesMut::new();
        packet.put_u8(b'C');
        packet.put_i32((tag.len() + 1 + 4) as i32);
        packet.put_slice(tag.as_bytes());
        packet.put_u8(0);
        packet.freeze()
    }
}
