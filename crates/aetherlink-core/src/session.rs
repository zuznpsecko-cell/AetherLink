//! Session management: AUTH handshake + key schedule over TLS.
//!
//! Wire (inside the TLS stream, which already gives confidentiality):
//! `PREFACE[PROTOCOL_VERSION]` + plaintext AUTH frame
//! (`Frame::auth(client_nonce, token)` with a 24B header), then the server
//! replies `server_nonce[32] + status u8` (`0` = ok). Both sides derive
//! traffic keys via HKDF over `client_nonce || server_nonce` with the PSK
//! as master; the server swaps tx/rx to its own perspective.
//!
//! PSK, nonces and keys never appear in errors or logs.

use std::io::{Read, Write};

use aetherlink_crypto::auth::{self, ClientNonce, NonceCache};
use aetherlink_crypto::keys::SessionKeys;
use aetherlink_frame::codec::FrameHeader;
use aetherlink_frame::types::{Frame, FramePayload};
use aetherlink_mux::manager::MuxManager;
use aetherlink_protocol::{FrameType, PROTOCOL_VERSION};
use bytes::{Buf, BufMut, BytesMut};

use crate::tls::{ClientTlsStream, ServerTlsStream};
use crate::{CoreError, Result};

/// Handshake status byte meaning "authenticated".
pub const AUTH_OK: u8 = 0;

/// Established client session: fresh mux + traffic keys.
///
/// The TLS stream stays with the caller (borrowed mutably during the
/// handshake), so a failed handshake still leaves the transport open —
/// the server needs it to serve the G2 static fallback on the same
/// connection.
pub struct ClientSession {
    /// Fresh multiplexer for this session.
    pub mux: MuxManager,
    /// Traffic keys (`tx` = client→server).
    pub keys: SessionKeys,
}

/// Established server session: fresh mux + traffic keys.
///
/// The TLS stream stays with the caller, see [`ClientSession`].
pub struct ServerSession {
    /// Fresh multiplexer for this session.
    pub mux: MuxManager,
    /// Traffic keys (`tx` = server→client).
    pub keys: SessionKeys,
}

/// KDF salt: `client_nonce || server_nonce` (64 bytes).
fn session_salt(client_nonce: &ClientNonce, server_nonce: &ClientNonce) -> Vec<u8> {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(client_nonce);
    salt.extend_from_slice(server_nonce);
    salt
}

/// Client side: send PREFACE + AUTH, read server nonce, derive keys.
///
/// Borrows the stream so the caller keeps driving it afterwards.
pub fn handshake_client(
    stream: &mut ClientTlsStream,
    psk: &[u8],
    nonce: &ClientNonce,
) -> Result<ClientSession> {
    if psk.is_empty() {
        return Err(CoreError::AuthError("empty psk".to_string()));
    }
    let token = auth::generate_auth_token(psk, nonce);
    let frame = Frame::auth(*nonce, token);
    let plaintext = frame.serialize_payload();
    let header = FrameHeader {
        length: plaintext.len() as u32,
        frame_type: FrameType::Auth,
        flags: 0,
        stream_id: 0,
        sequence: 0,
    };
    stream.write_all(&[PROTOCOL_VERSION])?;
    let mut hb = BytesMut::new();
    header.encode(&mut hb);
    stream.write_all(&hb)?;
    stream.write_all(&plaintext)?;
    stream.flush()?;

    let mut reply = [0u8; 33];
    stream.read_exact(&mut reply)?;
    if reply[32] != AUTH_OK {
        return Err(CoreError::AuthError("server rejected auth".to_string()));
    }
    let mut server_nonce = [0u8; 32];
    server_nonce.copy_from_slice(&reply[..32]);
    let keys = SessionKeys::new_with_salt(psk, &session_salt(nonce, &server_nonce));
    Ok(ClientSession {
        mux: MuxManager::new(),
        keys,
    })
}

/// Server side: check PREFACE + AUTH, verify token, enforce nonce
/// uniqueness, reply with server nonce, derive (swapped) keys.
///
/// Borrows the stream so the caller can serve the static fallback on it
/// when authentication fails (G2).
pub fn handshake_server(
    stream: &mut ServerTlsStream,
    psk: &[u8],
    cache: &NonceCache,
) -> Result<ServerSession> {
    if psk.is_empty() {
        return Err(CoreError::AuthError("empty psk".to_string()));
    }
    let mut version = [0u8; 1];
    stream.read_exact(&mut version)?;
    if version[0] != PROTOCOL_VERSION {
        return Err(CoreError::SessionError(format!(
            "bad preface version {}",
            version[0]
        )));
    }
    let mut hb = [0u8; aetherlink_frame::FRAME_HEADER_SIZE];
    stream.read_exact(&mut hb)?;
    let mut hbuf = BytesMut::from(&hb[..]);
    let header = FrameHeader::decode(&mut hbuf)?;
    if header.frame_type != FrameType::Auth {
        return Err(CoreError::SessionError("expected AUTH frame".to_string()));
    }
    let mut body = vec![0u8; header.length as usize];
    stream.read_exact(&mut body)?;
    let frame = Frame::deserialize_payload(
        FrameType::Auth,
        &body,
        header.stream_id,
        header.sequence,
        header.flags,
    )?;
    let (client_nonce, token) = match frame.payload {
        FramePayload::Auth {
            client_nonce,
            token,
        } => (client_nonce, token),
        _ => return Err(CoreError::SessionError("expected AUTH payload".to_string())),
    };
    auth::verify_auth_token(psk, &client_nonce, &token)
        .map_err(|_| CoreError::AuthError("bad token".to_string()))?;
    cache
        .check_and_insert(client_nonce)
        .map_err(|_| CoreError::AuthError("nonce replay".to_string()))?;

    let server_nonce = auth::generate_nonce();
    stream.write_all(&server_nonce)?;
    stream.write_all(&[AUTH_OK])?;
    stream.flush()?;

    let mut keys = SessionKeys::new_with_salt(psk, &session_salt(&client_nonce, &server_nonce));
    keys.swap();
    Ok(ServerSession {
        mux: MuxManager::new(),
        keys,
    })
}
