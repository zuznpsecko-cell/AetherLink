//! Server accept-loop: TLS accept → AUTH gate → tunnel / static / closed.
//!
//! * TLS handshake fails (plaintext probe) → [`Path::Closed`], nothing served;
//! * AUTH fails → [`Path::Static`]: minimal static HTTP over the same TLS
//!   connection, with no tunnel/proxy/vpn banner (G2);
//! * AUTH ok → [`Path::Tunnel`]: mux frames routed to pre-registered dial
//!   targets (test harness passes them in; OPEN-frame-driven registration
//!   is a follow-up).
//!
//! Scope note: each DATA/DATAGRAM frame is one request→one reply exchange
//! (fits DNS and proxied request/response). Bidirectional streaming relay
//! is a follow-up once OPEN-frame negotiation lands.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use aetherlink_core::{session, tls};
use aetherlink_crypto::auth::NonceCache;
use aetherlink_frame::codec::FrameHeader;
use aetherlink_frame::FRAME_HEADER_SIZE;
use aetherlink_mux::manager::MuxManager;
use aetherlink_protocol::FrameType;
use bytes::BytesMut;

use crate::relay;

/// How one accepted connection was served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    /// Authenticated: mux inside TLS.
    Tunnel,
    /// Bad/missing auth: static web fallback (G2).
    Static,
    /// Not TLS at all: closed silently.
    Closed,
}

/// Per-listener server context (shared across connections).
pub struct ServerCtx {
    /// TLS1.3-only config with ALPN.
    pub tls: Arc<rustls::ServerConfig>,
    /// Pre-shared key for AUTH.
    pub psk: Vec<u8>,
    /// Nonce replay cache (TTL enforced inside).
    pub cache: NonceCache,
    /// Static response body (must carry no tunnel banner).
    pub static_body: Vec<u8>,
}

/// Relay read timeout: a silent target must not stall the loop forever.
const RELAY_TIMEOUT: Duration = Duration::from_secs(5);

/// Serve one static HTTP response over an open TLS stream.
fn serve_static(stream: &mut tls::ServerTlsStream, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body);
    close_quietly(stream);
}

/// TLS close_notify + flush, ignoring errors (peer may be gone).
fn close_quietly(stream: &mut tls::ServerTlsStream) {
    let _ = stream.conn.send_close_notify();
    let _ = stream.flush();
}

/// Serve one accepted TCP connection to a path decision.
pub fn serve_connection(
    sock: TcpStream,
    ctx: &ServerCtx,
    routes: &HashMap<u16, SocketAddr>,
) -> Path {
    let mut stream = match tls::accept_tls(sock, &ctx.tls) {
        Ok(s) => s,
        Err(_) => return Path::Closed,
    };
    let sess = match session::handshake_server(&mut stream, &ctx.psk, &ctx.cache) {
        Ok(s) => s,
        Err(_) => {
            serve_static(&mut stream, &ctx.static_body);
            return Path::Static;
        }
    };
    tunnel_loop(&mut stream, sess, routes);
    close_quietly(&mut stream);
    Path::Tunnel
}

/// Pump mux frames until EOF, protocol error, or GOAWAY/RST.
fn tunnel_loop(
    stream: &mut tls::ServerTlsStream,
    mut sess: session::ServerSession,
    routes: &HashMap<u16, SocketAddr>,
) {
    let mut relays: HashMap<u16, TcpStream> = HashMap::new();
    loop {
        let mut hb = [0u8; FRAME_HEADER_SIZE];
        if stream.read_exact(&mut hb).is_err() {
            break; // EOF or transport error: fail closed.
        }
        let mut hbuf = BytesMut::from(&hb[..]);
        let header = match FrameHeader::decode(&mut hbuf) {
            Ok(h) => h,
            Err(_) => break,
        };
        if header.length as usize > 65535 + 1024 {
            break; // Absurd length: fail closed.
        }
        let mut ct = vec![0u8; header.length as usize];
        if stream.read_exact(&mut ct).is_err() {
            break;
        }
        match header.frame_type {
            FrameType::Data => {
                let Some(target) = routes.get(&header.stream_id) else {
                    break; // No route for this stream: fail closed.
                };
                if sess
                    .mux
                    .register_inbound(
                        header.stream_id,
                        &target.ip().to_string(),
                        target.port(),
                        false,
                    )
                    .is_err()
                {
                    break;
                }
                let pt = match sess.mux.open_data(sess.keys.rx_key(), &header, &ct) {
                    Ok(pt) => pt,
                    Err(_) => break,
                };
                let reply = match relay_exchange(&mut relays, header.stream_id, *target, &pt) {
                    Ok(reply) => reply,
                    Err(_) => break,
                };
                if !send_data(&mut sess, stream, header.stream_id, &reply) {
                    break;
                }
            }
            FrameType::UdpDatagram => {
                let Some(target) = routes.get(&header.stream_id) else {
                    break;
                };
                if sess
                    .mux
                    .register_inbound(
                        header.stream_id,
                        &target.ip().to_string(),
                        target.port(),
                        true,
                    )
                    .is_err()
                {
                    break;
                }
                let pt = match sess.mux.open_datagram(sess.keys.rx_key(), &header, &ct) {
                    Ok(pt) => pt,
                    Err(_) => break,
                };
                let reply = match relay::relay_udp(
                    &target.ip().to_string(),
                    target.port(),
                    &pt,
                    RELAY_TIMEOUT,
                ) {
                    Ok(reply) => reply,
                    Err(_) => break,
                };
                let sealed =
                    match sess
                        .mux
                        .seal_datagram(sess.keys.tx_key(), header.stream_id, &reply, 128)
                    {
                        Ok(sealed) => sealed,
                        Err(_) => break,
                    };
                if write_sealed(stream, &sealed.header, &sealed.ciphertext).is_err() {
                    break;
                }
            }
            FrameType::Ping => continue,
            FrameType::GoAway | FrameType::Rst => break,
            _ => break, // OPEN/WINDOW/AUTH post-handshake: unsupported yet.
        }
    }
}

/// One request→reply exchange with a cached TCP relay connection.
fn relay_exchange(
    relays: &mut HashMap<u16, TcpStream>,
    id: u16,
    target: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, ()> {
    let sock = match relays.get_mut(&id) {
        Some(sock) => sock,
        None => {
            let sock = relay::dial_tcp(&target.ip().to_string(), target.port()).map_err(|_| ())?;
            sock.set_read_timeout(Some(RELAY_TIMEOUT)).map_err(|_| ())?;
            relays.insert(id, sock);
            relays.get_mut(&id).ok_or(())?
        }
    };
    sock.write_all(payload).map_err(|_| ())?;
    let mut buf = vec![0u8; 65535];
    let n = sock.read(&mut buf).map_err(|_| ())?;
    buf.truncate(n);
    Ok(buf)
}

/// Seal + write one DATA reply; false on any failure.
fn send_data(
    sess: &mut session::ServerSession,
    stream: &mut tls::ServerTlsStream,
    id: u16,
    payload: &[u8],
) -> bool {
    let sealed = match sess.mux.seal_data(sess.keys.tx_key(), id, payload, 128) {
        Ok(sealed) => sealed,
        Err(_) => return false,
    };
    write_sealed(stream, &sealed.header, &sealed.ciphertext).is_ok()
}

/// Write one sealed frame; Err on transport failure.
fn write_sealed(
    stream: &mut tls::ServerTlsStream,
    header: &FrameHeader,
    ct: &[u8],
) -> std::io::Result<()> {
    let mut buf = BytesMut::new();
    header.encode(&mut buf);
    stream.write_all(&buf)?;
    stream.write_all(ct)?;
    stream.flush()
}
