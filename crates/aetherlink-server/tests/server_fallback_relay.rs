//! TDD RED: server static fallback + AUTH gate + TCP relay + DNS upstream.
//!
//! Given/When/Then per test. Must FAIL until GREEN implements the
//! server modules. Spec: §4.5 (valid AUTH → TUNNEL, else STATIC),
//! G2 (no/bad auth → static web fallback, no tunnel banner).

use aetherlink_crypto::auth as crypto_auth;
use aetherlink_server::{auth, config, dns, fallback, relay};

// ---------- fallback decision ----------

#[test]
fn fallback_no_auth_goes_static() {
    // Given: unauthenticated probe (browser HTTPS look-alike)
    // When: deciding the path
    let path = fallback::decide(false).expect("decision must succeed");
    // Then: static web fallback only, never tunnel
    assert_eq!(path, "static");
}

#[test]
fn fallback_valid_auth_goes_tunnel() {
    // Given: authenticated session
    // When: deciding the path
    let path = fallback::decide(true).expect("decision must succeed");
    // Then: mux inside TLS
    assert_eq!(path, "tunnel");
}

// ---------- AUTH gate ----------

#[test]
fn auth_verify_valid_token() {
    // Given: canonical token for psk+nonce
    let psk = b"change-me-high-entropy-test-psk-32b!";
    let nonce = [0x07u8; 32];
    let token = crypto_auth::generate_auth_token(psk, &nonce);
    // When: server verifies
    // Then: accepted
    auth::verify(psk, &nonce, &token).expect("valid token must verify");
}

#[test]
fn auth_verify_rejects_bad_token() {
    // Given: token for another nonce
    let psk = b"change-me-high-entropy-test-psk-32b!";
    let nonce = [0x07u8; 32];
    let other = [0x08u8; 32];
    let token = crypto_auth::generate_auth_token(psk, &other);
    // When: server verifies against the presented nonce
    // Then: rejected
    assert!(auth::verify(psk, &nonce, &token).is_err());
}

// ---------- TCP relay ----------

#[test]
fn relay_dial_tcp_echo_roundtrip() {
    // Given: local echo target (no external network)
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 5];
        use std::io::{Read, Write};
        sock.read_exact(&mut buf).expect("read");
        sock.write_all(&buf).expect("echo");
    });
    // When: server relay dials the target
    let mut stream = relay::dial_tcp("127.0.0.1", port).expect("dial");
    // Then: bytes relayed transparently
    use std::io::{Read, Write};
    stream.write_all(b"hello").expect("write");
    let mut back = [0u8; 5];
    stream.read_exact(&mut back).expect("read");
    assert_eq!(&back, b"hello");
}

// ---------- DNS upstream ----------

#[test]
fn dns_upstream_is_canonical() {
    // Given: server DNS policy
    // When: reading upstream
    // Then: primary 1.1.1.1:53
    assert_eq!(dns::upstream(), "1.1.1.1:53");
}

// ---------- config ----------

#[test]
fn config_parse_minimal_valid() {
    // Given: minimal server config document
    let raw = r#"{"listen":"0.0.0.0:443","psk":"abc","local_static_root":"./fallback"}"#;
    // When: parsing
    // Then: accepted
    config::parse(raw).expect("valid config must parse");
}

#[test]
fn config_rejects_missing_psk() {
    // Given: config without psk
    let raw = r#"{"listen":"0.0.0.0:443","local_static_root":"./fallback"}"#;
    // When: parsing
    // Then: rejected, never default to empty secret
    assert!(config::parse(raw).is_err());
}

#[test]
fn relay_dial_refused_fails_fast() {
    // Given: localhost порт, который точно закрыт (bind -> drop даёт
    // минимальную гонку, ок; DPI сюда не вмешивается)
    // When: dialing a refused port -> Then: Err быстро, без подвисаний.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = probe.local_addr().expect("addr").port();
    drop(probe);
    let started = std::time::Instant::now();
    assert!(relay::dial_tcp("127.0.0.1", port).is_err());
    assert!(
        started.elapsed() < std::time::Duration::from_secs(15),
        "dial errors must stay bounded"
    );
}
