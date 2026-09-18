# AetherLink v1.5 — TDD Development Plan

## Общая стратегия TDD

**Red → Green → Refactor:**
1. **Red**: Пишем failing test (определяет спецификацию)
2. **Green**: Минимальная реализация для прохождения теста
3. **Refactor**: Улучшение кода без изменения поведения

**Приоритеты:**
- Golden tests для протокола (canonical, immutable)
- Unit tests для каждого модуля (Rust)
- Integration tests для FFI
- End-to-end tests для полного туннеля

---

## Phase 0: Bootstrap (Day 1)

### 0.1 Структура проекта
```
aetherlink/
├── crates/
│   ├── aetherlink-core/        # main protocol lib
│   ├── aetherlink-crypto/      # crypto primitives
│   ├── aetherlink-frame/       # frame codec
│   ├── aetherlink-mux/         # multiplexing
│   ├── aetherlink-netstack/    # userspace network stack
│   ├── aetherlink-ffi/         # C ABI exports
│   ├── aetherlink-server/      # server lib
│   └── aetherlink-client/      # client lib
├── dotnet/
│   ├── AetherLink.Server/
│   └── AetherLink.Client/
├── apps/android/
├── protocol/                   # canonical specs + golden tests
├── testdata/                   # golden vectors
├── configs/
├── scripts/
├── docs/
├── deploy/
└── Cargo.toml                  # workspace root
```

**Tasks:**
- [ ] Create Cargo workspace structure
- [ ] Setup `protocol/` with golden test harness
- [ ] Create DECISIONS.md, STATUS.md templates
- [ ] Basic README (10-20 lines)

**TDD: No tests yet** (structure only)

---

## Phase 1: Crypto + Auth (Days 2-3)

### 1.1 HMAC-SHA256 Token Generation (TDD)

**Test First (`aetherlink-crypto/tests/auth_test.rs`):**
```rust
#[test]
fn test_generate_auth_token_rfc_vector() {
    let psk = b"test-psk-256-bits-hex-encoded...";
    let nonce = [0u8; 32]; // known nonce
    let token = generate_auth_token(psk, &nonce);
    // Expected from manual HMAC-SHA256 calculation
    assert_eq!(token, hex::decode("...").unwrap());
}

#[test]
fn test_token_different_for_different_nonce() {
    let psk = b"same-psk";
    let nonce1 = [1u8; 32];
    let nonce2 = [2u8; 32];
    assert_ne!(
        generate_auth_token(psk, &nonce1),
        generate_auth_token(psk, &nonce2)
    );
}
```

**Implementation:**
```rust
// aetherlink-crypto/src/auth.rs
use hmac::{Hmac, Mac};
use sha2::Sha256;

const AUTH_PREFIX: &[u8] = b"aetherlink-auth-v1";

pub fn generate_auth_token(psk: &[u8], client_nonce: &[u8; 32]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(psk)
        .expect("HMAC accepts any key size");
    mac.update(AUTH_PREFIX);
    mac.update(client_nonce);
    let result = mac.finalize();
    result.into_bytes().into()
}
```

**Tasks:**
- [ ] Write test vectors (including RFC test cases)
- [ ] Implement `generate_auth_token`
- [ ] Implement `verify_auth_token`
- [ ] Nonce replay cache with TTL (test expiry)

### 1.2 ChaCha20-Poly1305 AEAD

**Test First (`protocol/crypto_golden_test.rs`):**
```rust
#[test]
fn test_encrypt_decrypt_frame_payload() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let plaintext = b"Hello AetherLink";
    
    let ciphertext = encrypt(key, nonce, plaintext, &[]);
    assert_eq!(ciphertext.len(), plaintext.len() + 16); // +tag
    
    let decrypted = decrypt(key, nonce, &ciphertext, &[]).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_decrypt_wrong_key_fails() {
    let key1 = [1u8; 32];
    let key2 = [2u8; 32];
    let nonce = [0u8; 12];
    let ciphertext = encrypt(key1, nonce, b"secret", &[]);
    
    assert!(decrypt(key2, nonce, &ciphertext, &[]).is_err());
}
```

**Implementation:**
```rust
// aetherlink-crypto/src/aead.rs
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

pub fn encrypt(key: [u8; 32], nonce: [u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(&key.into());
    cipher.encrypt(&nonce.into(), plaintext)
        .expect("encryption should not fail")
}

pub fn decrypt(key: [u8; 32], nonce: [u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, ()> {
    let cipher = ChaCha20Poly1305::new(&key.into());
    cipher.decrypt(&nonce.into(), ciphertext).map_err(|_| ())
}
```

**Tasks:**
- [ ] Write golden test vectors (static key/nonce/plaintext → ciphertext)
- [ ] Implement AEAD encrypt/decrypt
- [ ] Anti-replay window (test duplicate sequence rejection)

### 1.3 Key Schedule (HKDF-SHA256)

**Test First:**
```rust
#[test]
fn test_derive_session_keys() {
    let master_secret = b"shared-secret";
    let salt = b"aetherlink-v1";
    let (tx_key, rx_key) = derive_keys(master_secret, salt);
    
    assert_ne!(tx_key, rx_key); // different keys
    assert_eq!(tx_key.len(), 32);
    assert_eq!(rx_key.len(), 32);
}
```

**Implementation:**
```rust
use hkdf::Hkdf;
use sha2::Sha256;

pub fn derive_keys(master: &[u8], salt: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), master);
    let mut tx_key = [0u8; 32];
    let mut rx_key = [0u8; 32];
    hkdf.expand(b"tx", &mut tx_key).unwrap();
    hkdf.expand(b"rx", &mut rx_key).unwrap();
    (tx_key, rx_key)
}
```

**Tasks:**
- [ ] HKDF derive tx/rx keys
- [ ] Test deterministic derivation
- [ ] Document key schedule in SPEC.md

---

## Phase 2: Frame Protocol (Days 4-5)

### 2.1 Frame Structure (TDD)

**Test First (`aetherlink-frame/tests/codec_test.rs`):**
```rust
#[test]
fn test_encode_decode_data_frame() {
    let frame = Frame {
        length: 0, // calculated
        frame_type: FrameType::Data,
        flags: 0,
        stream_id: 42,
        sequence: 100,
        payload: b"test data".to_vec(),
    };
    
    let encoded = encode_frame(&frame, &key, &nonce);
    let decoded = decode_frame(&encoded, &key).unwrap();
    
    assert_eq!(decoded.stream_id, 42);
    assert_eq!(decoded.sequence, 100);
    assert_eq!(decoded.payload, b"test data");
}

#[test]
fn test_reject_invalid_length() {
    let mut data = vec![0xFF, 0xFF, 0xFF]; // length > 16MB
    data.extend_from_slice(&[0; 100]);
    assert!(decode_frame(&data, &key).is_err());
}
```

**Frame Format (fixed 24-byte header + encrypted payload):**
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Length (24-bit)      | Type |  Flags  |   Stream ID   
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    (16-bit)      |         Sequence (32-bit)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Encrypted Payload + Tag                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Tasks:**
- [ ] Define `Frame` struct with all types (0-9)
- [ ] Implement `encode_frame` (with padding to `pad_multiple`)
- [ ] Implement `decode_frame` (with AEAD decrypt + replay check)
- [ ] Golden tests for each frame type
- [ ] Test max frame size (16MB limit)

### 2.2 Frame Types Implementation

**Types (p. 4.3):**
```rust
pub enum FrameType {
    Data = 0,
    OpenTcp = 1,
    Ping = 2,
    Auth = 3,
    WindowUpdate = 4,
    GoAway = 5,
    Rst = 6,
    OpenUdp = 7,
    UdpDatagram = 8,
}
```

**Test for each type:**
```rust
#[test]
fn test_open_tcp_frame_encoding() {
    let frame = Frame::open_tcp(stream_id, "example.com", 443);
    // encode/decode, verify addr_type/addr/port extracted correctly
}
```

**Tasks:**
- [ ] AUTH frame (client nonce + token)
- [ ] OPEN_TCP (addr_type: domain/ipv4/ipv6, addr, port)
- [ ] OPEN_UDP (same)
- [ ] DATA frame
- [ ] UDP_DATAGRAM frame
- [ ] Control frames (PING, WINDOW_UPDATE, GOAWAY, RST)

---

## Phase 3: Mux Layer (Days 6-7)

### 3.1 Stream Management (TDD)

**Test First:**
```rust
#[test]
fn test_open_stream_allocates_id() {
    let mut mux = Multiplexer::new();
    let stream_id = mux.open_stream().unwrap();
    assert_eq!(stream_id, 1); // first client stream
    
    let stream_id2 = mux.open_stream().unwrap();
    assert_eq!(stream_id2, 3); // odd for client
}

#[test]
fn test_send_data_on_stream() {
    let mut mux = Multiplexer::new();
    let sid = mux.open_stream().unwrap();
    
    mux.send_data(sid, b"hello").unwrap();
    let frames = mux.flush(); // get pending frames
    
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].frame_type, FrameType::Data);
    assert_eq!(frames[0].stream_id, sid);
}

#[test]
fn test_receive_data_queues_for_app() {
    let mut mux = Multiplexer::new();
    let sid = 1;
    
    let frame = Frame::data(sid, b"world");
    mux.handle_frame(frame).unwrap();
    
    let data = mux.recv_data(sid).unwrap();
    assert_eq!(data, b"world");
}
```

**Implementation:**
```rust
// aetherlink-mux/src/lib.rs
pub struct Multiplexer {
    streams: HashMap<u16, Stream>,
    next_stream_id: u16,
    send_queue: VecDeque<Frame>,
}

impl Multiplexer {
    pub fn open_stream(&mut self) -> Result<u16, Error> {
        let id = self.next_stream_id;
        self.next_stream_id += 2; // client=odd, server=even
        self.streams.insert(id, Stream::new());
        Ok(id)
    }
    
    pub fn send_data(&mut self, stream_id: u16, data: &[u8]) -> Result<(), Error> {
        let stream = self.streams.get_mut(&stream_id).ok_or(Error::InvalidStream)?;
        let frame = Frame::data(stream_id, data);
        self.send_queue.push_back(frame);
        Ok(())
    }
    
    pub fn handle_frame(&mut self, frame: Frame) -> Result<(), Error> {
        match frame.frame_type {
            FrameType::Data => {
                let stream = self.streams.entry(frame.stream_id).or_insert_with(Stream::new);
                stream.recv_buffer.extend_from_slice(&frame.payload);
                Ok(())
            }
            // ... other types
        }
    }
}
```

**Tasks:**
- [ ] Stream state machine (Idle → Open → Closed)
- [ ] Flow control (WINDOW_UPDATE)
- [ ] Backpressure handling
- [ ] Stream closure (RST, FIN equivalent)
- [ ] Test concurrent streams (multiple open)

---

## Phase 4: UDP Flows + DNS (Days 8-9)

### 4.1 UDP Flow Handling (TDD)

**Design Decision (to DECISIONS.md):**
```markdown
### UDP Frame Layout
- Type 7 (OPEN_UDP): addr_type, addr, port — opens UDP "flow" (association)
- Type 8 (UDP_DATAGRAM): stream_id maps to flow, payload = raw UDP data
- No DNS-specific frames (type 9) — DNS is UDP flow to virtual resolver IP
```

**Test First:**
```rust
#[test]
fn test_open_udp_flow() {
    let mut mux = Multiplexer::new();
    let flow_id = mux.open_udp_flow("8.8.8.8", 53).unwrap();
    
    let frames = mux.flush();
    assert_eq!(frames[0].frame_type, FrameType::OpenUdp);
}

#[test]
fn test_send_udp_datagram() {
    let mut mux = Multiplexer::new();
    let flow_id = mux.open_udp_flow("1.1.1.1", 53).unwrap();
    
    let dns_query = b"\x12\x34..."; // raw DNS query
    mux.send_udp_datagram(flow_id, dns_query).unwrap();
    
    let frames = mux.flush();
    assert_eq!(frames.last().unwrap().frame_type, FrameType::UdpDatagram);
}
```

**Tasks:**
- [ ] UDP flow state (similar to streams but stateless)
- [ ] Implement OPEN_UDP frame
- [ ] Implement UDP_DATAGRAM frame
- [ ] Flow timeout (idle flows expire after N seconds)
- [ ] Test UDP echo (send → receive response)

### 4.2 Virtual DNS Resolver

**Test First:**
```rust
#[test]
fn test_dns_query_through_tunnel() {
    let mut client = Client::new(config);
    
    // Simulate DNS query to virtual DNS IP (10.255.0.1:53)
    let query = dns::build_query("example.com", RecordType::A);
    client.send_to_tunnel("10.255.0.1:53", &query).unwrap();
    
    // Server should relay to upstream (1.1.1.1:53)
    let response = client.recv_from_tunnel().unwrap();
    let answer = dns::parse_response(&response);
    assert!(answer.answers.len() > 0);
}
```

**Tasks:**
- [ ] Define virtual DNS IP (e.g., `10.255.0.1` in TUN subnet)
- [ ] Client intercepts DNS queries to this IP
- [ ] Server relays to `dns_upstream` (1.1.1.1, 8.8.8.8)
- [ ] Test no system DNS leak (integration test later)

---

## Phase 5: TLS Transport (Days 10-11)

### 5.1 TLS 1.3 with rustls (TDD)

**Test First:**
```rust
#[test]
fn test_tls_handshake() {
    let server = start_test_server(tls_config);
    let mut client = TlsClient::connect("localhost:8443", "localhost").unwrap();
    
    assert!(client.is_connected());
    client.write(b"ping").unwrap();
    let response = client.read().unwrap();
    assert_eq!(response, b"pong");
}

#[test]
fn test_alpn_negotiation() {
    let client = TlsClient::connect_with_alpn(addr, sni, &["h2", "http/1.1"]).unwrap();
    assert_eq!(client.negotiated_alpn(), Some("h2"));
}
```

**Implementation:**
```rust
// aetherlink-core/src/tls.rs
use rustls::{ClientConfig, ServerConfig};

pub struct TlsClient {
    conn: rustls::ClientConnection,
    // ...
}

impl TlsClient {
    pub fn connect(addr: &str, sni: &str) -> Result<Self, Error> {
        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(/* ... */)
            .with_no_client_auth();
        
        // Set ALPN h2, http/1.1
        let mut conn = rustls::ClientConnection::new(
            Arc::new(config),
            sni.try_into().unwrap()
        )?;
        
        // Connect TCP socket, do handshake...
        Ok(Self { conn })
    }
}
```

**Tasks:**
- [ ] TLS 1.3-only config
- [ ] ALPN h2, http/1.1
- [ ] SNI support
- [ ] Certificate validation
- [ ] Test self-signed cert (for dev)
- [ ] ClientHello fingerprint best-effort (rustls defaults acceptable for MVP)

### 5.2 Mux over TLS

**Test First:**
```rust
#[test]
fn test_send_frames_over_tls() {
    let (client, server) = setup_tls_pair();
    
    let frame = Frame::auth(nonce, token);
    client.send_frame(&frame).unwrap();
    
    let received = server.recv_frame().unwrap();
    assert_eq!(received.frame_type, FrameType::Auth);
}
```

**Tasks:**
- [ ] Frame framing over TLS stream (length prefix or HTTP/2 DATA frames)
- [ ] Buffering strategy
- [ ] Test bidirectional frame exchange

---

## Phase 6: Server Core (Days 12-14)

### 6.1 Server Authentication (TDD)

**Test First:**
```rust
#[test]
fn test_server_accepts_valid_auth() {
    let server = Server::new(server_config);
    let auth_frame = Frame::auth(nonce, valid_token);
    
    let result = server.handle_auth(&auth_frame).unwrap();
    assert_eq!(result, AuthResult::Accepted);
}

#[test]
fn test_server_rejects_replay_nonce() {
    let server = Server::new(server_config);
    let auth_frame = Frame::auth(nonce, token);
    
    server.handle_auth(&auth_frame).unwrap();
    let result = server.handle_auth(&auth_frame); // replay
    assert_eq!(result, Err(Error::ReplayAttack));
}

#[test]
fn test_server_expires_old_nonce() {
    let server = Server::new(server_config_with_ttl(10)); // 10s TTL
    let auth_frame = Frame::auth(old_nonce, token);
    
    // Advance time 11s
    sleep(Duration::from_secs(11));
    
    let result = server.handle_auth(&auth_frame);
    assert_eq!(result, Err(Error::NonceExpired));
}
```

**Implementation:**
```rust
// aetherlink-server/src/auth.rs
pub struct NonceCache {
    seen: HashMap<[u8; 32], Instant>,
    ttl: Duration,
}

impl NonceCache {
    pub fn check_and_insert(&mut self, nonce: [u8; 32]) -> Result<(), Error> {
        // Clean expired
        self.seen.retain(|_, time| time.elapsed() < self.ttl);
        
        // Check replay
        if self.seen.contains_key(&nonce) {
            return Err(Error::ReplayAttack);
        }
        
        self.seen.insert(nonce, Instant::now());
        Ok(())
    }
}
```

**Tasks:**
- [ ] Nonce replay cache with TTL (default 5 min)
- [ ] HMAC verification
- [ ] Test concurrent auth requests
- [ ] Document nonce TTL in DECISIONS.md

### 6.2 Static Fallback (G2 - No Proxy Surface)

**Test First:**
```rust
#[test]
fn test_no_auth_returns_static_page() {
    let server = Server::new_with_fallback("./testdata/fallback");
    let client = TlsClient::connect_without_auth(server.addr());
    
    // Send GET / HTTP/1.1
    client.write(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n").unwrap();
    let response = client.read_http_response().unwrap();
    
    assert_eq!(response.status, 200);
    assert!(response.body.contains("<html>")); // static page
    assert!(!response.body.contains("proxy")); // no proxy banner
}

#[test]
fn test_invalid_auth_returns_static_not_error() {
    let server = Server::new_with_fallback("./testdata/fallback");
    let mut client = TlsClient::connect(server.addr());
    
    let bad_frame = Frame::auth(nonce, b"wrong-token");
    client.send_frame(&bad_frame).unwrap();
    
    // Should fallback to HTTP, not close connection
    let response = client.read_http_response().unwrap();
    assert_eq!(response.status, 200);
}
```

**Tasks:**
- [ ] Static file server (simple, no directory traversal)
- [ ] Serve on invalid/missing AUTH
- [ ] Test various HTTP requests (GET, POST ignored)
- [ ] Default index.html

### 6.3 TCP Relay

**Test First:**
```rust
#[test]
fn test_server_relays_tcp_to_target() {
    let echo_server = start_tcp_echo_server("127.0.0.1:9999");
    let server = Server::new(config);
    let mut client = authenticated_client(server.addr());
    
    // Client opens TCP stream to echo server
    let stream_id = client.open_tcp("127.0.0.1", 9999).unwrap();
    client.send_data(stream_id, b"hello").unwrap();
    
    // Should receive echo back
    let data = client.recv_data(stream_id).unwrap();
    assert_eq!(data, b"hello");
}

#[test]
fn test_server_handles_connection_refused() {
    let server = Server::new(config);
    let mut client = authenticated_client(server.addr());
    
    // Try to connect to non-existent service
    let result = client.open_tcp("127.0.0.1", 1).unwrap();
    
    // Should receive RST frame
    let frame = client.recv_frame().unwrap();
    assert_eq!(frame.frame_type, FrameType::Rst);
}
```

**Implementation:**
```rust
// aetherlink-server/src/relay.rs
pub async fn handle_open_tcp(
    stream_id: u16,
    addr: &str,
    port: u16,
    mux: Arc<Mutex<Multiplexer>>,
) -> Result<(), Error> {
    // Dial target
    let target = TcpStream::connect((addr, port)).await?;
    
    // Spawn bidirectional relay
    tokio::spawn(async move {
        relay_tcp_stream(stream_id, target, mux).await;
    });
    
    Ok(())
}
```

**Tasks:**
- [ ] TCP dial to target
- [ ] Bidirectional relay (target ↔ mux stream)
- [ ] Handle connection errors (RST frame)
- [ ] Close stream on EOF
- [ ] Test concurrent connections

### 6.4 UDP Relay + DNS Upstream

**Test First:**
```rust
#[test]
fn test_server_relays_udp_datagram() {
    let server = Server::new(config);
    let mut client = authenticated_client(server.addr());
    
    let flow_id = client.open_udp("8.8.8.8", 53).unwrap();
    let dns_query = build_dns_query("example.com");
    client.send_udp(flow_id, &dns_query).unwrap();
    
    let response = client.recv_udp(flow_id).unwrap();
    let answer = parse_dns_response(&response);
    assert!(!answer.is_empty());
}

#[test]
fn test_dns_upstream_configured() {
    let config = ServerConfig {
        dns_upstream: vec!["1.1.1.1:53".parse().unwrap()],
        ..Default::default()
    };
    let server = Server::new(config);
    
    // DNS query should go to 1.1.1.1, not arbitrary upstream
}
```

**Tasks:**
- [ ] UDP socket per flow (or shared with demux)
- [ ] Relay datagrams bidirectionally
- [ ] DNS upstream list (1.1.1.1, 8.8.8.8)
- [ ] Flow timeout cleanup
- [ ] Test UDP echo

---

## Phase 7: Netstack Selection & Integration (Days 15-17)

### 7.1 Netstack Evaluation & Decision

**Candidates:**
1. **smoltcp** — Pure Rust, mature, lwIP-like
   - ✅ IPv4/IPv6 TCP/UDP/ICMP
   - ✅ Well-tested, used in embedded
   - ⚠️ No application-level API (need manual socket management)

2. **tun2socks5-rs / tokio-tun** — High-level, tokio-based
   - ✅ Easy integration with tokio
   - ✅ Handles TUN I/O + TCP/UDP proxying
   - ⚠️ Less control over packet details

3. **netstack-smoltcp** (custom wrapper) — smoltcp + async runtime
   - ✅ Full control
   - ⚠️ More code to write

**Decision (to DECISIONS.md):**
```markdown
### Netstack Choice: smoltcp + custom async wrapper
**Rationale:**
- Full control over TCP/UDP state machines
- No GPL/copyleft issues (MIT/0BSD)
- Proven in production (embedded, VPN projects)
- Aligns with "userspace netstack like gVisor" requirement
- Can evolve to support custom protocols if needed

**Implementation:**
- `smoltcp::iface::Interface` manages L3 routing
- `smoltcp::socket::TcpSocket` for TCP connections
- `smoltcp::socket::UdpSocket` for UDP flows
- `tokio` runtime for async I/O
- Custom `NetstackManager` bridges smoltcp ↔ multiplexer
```

### 7.2 TUN Device (Linux first, Windows later)

**Test First (integration test):**
```rust
#[test]
#[ignore] // requires root/CAP_NET_ADMIN
fn test_create_tun_device() {
    let tun = TunDevice::create("aether0").unwrap();
    assert_eq!(tun.name(), "aether0");
    
    // Verify interface exists
    let output = Command::new("ip").args(&["link", "show", "aether0"]).output().unwrap();
    assert!(output.status.success());
}

#[test]
#[ignore]
fn test_read_write_tun_packets() {
    let mut tun = TunDevice::create("aether0").unwrap();
    
    // Write IPv4 packet
    let icmp_packet = build_icmp_echo_request("10.255.0.2");
    tun.write(&icmp_packet).unwrap();
    
    // Should be able to read it back (loopback or from kernel)
    let mut buf = [0u8; 1500];
    let n = tun.read(&mut buf).unwrap();
    assert!(n > 0);
}
```

**Implementation:**
```rust
// aetherlink-netstack/src/tun_linux.rs
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;

pub struct TunDevice {
    fd: File,
    name: String,
}

impl TunDevice {
    pub fn create(name: &str) -> Result<Self, Error> {
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;
        
        // ioctl TUNSETIFF
        // Set IFF_TUN | IFF_NO_PI
        
        Ok(Self { fd, name: name.into() })
    }
    
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        // Read IP packet from TUN
        self.fd.read(buf).map_err(Into::into)
    }
    
    pub fn write(&mut self, packet: &[u8]) -> Result<(), Error> {
        self.fd.write_all(packet).map_err(Into::into)
    }
}
```

**Tasks:**
- [ ] Linux TUN creation (`/dev/net/tun` + ioctl)
- [ ] Configure IP address (`ip addr add`)
- [ ] Set interface UP (`ip link set up`)
- [ ] Test packet I/O
- [ ] Windows Wintun stub (defer full implementation)

### 7.3 Netstack Integration

**Test First:**
```rust
#[tokio::test]
async fn test_netstack_handles_tcp_syn() {
    let mut netstack = NetstackManager::new();
    
    // Simulate SYN packet to 10.255.0.1:80
    let syn_packet = build_tcp_syn("10.255.0.2", 12345, "93.184.216.34", 80);
    netstack.handle_packet(&syn_packet).await.unwrap();
    
    // Should open stream in mux
    let streams = netstack.get_active_streams();
    assert_eq!(streams.len(), 1);
}

#[tokio::test]
async fn test_netstack_routes_dns_to_virtual_ip() {
    let mut netstack = NetstackManager::new();
    
    // DNS query to 10.255.0.1:53 (virtual resolver)
    let dns_query_packet = build_udp_packet(
        "10.255.0.2", 54321,
        "10.255.0.1", 53,
        &dns_query_bytes
    );
    
    netstack.handle_packet(&dns_query_packet).await.unwrap();
    
    // Should create UDP flow in mux
    let flows = netstack.get_active_udp_flows();
    assert_eq!(flows.len(), 1);
}
```

**Implementation:**
```rust
// aetherlink-netstack/src/manager.rs
use smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket, UdpPacket};
use smoltcp::iface::{Interface, InterfaceBuilder};
use smoltcp::socket::{SocketSet, TcpSocket, UdpSocket};

pub struct NetstackManager {
    iface: Interface<'static>,
    sockets: SocketSet<'static>,
    mux: Arc<Mutex<Multiplexer>>,
}

impl NetstackManager {
    pub async fn handle_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        // Parse IP packet
        let ip_packet = Ipv4Packet::new_checked(packet)?;
        
        match ip_packet.protocol() {
            IpProtocol::Tcp => self.handle_tcp(&ip_packet).await?,
            IpProtocol::Udp => self.handle_udp(&ip_packet).await?,
            IpProtocol::Icmp => self.handle_icmp(&ip_packet).await?,
            _ => return Err(Error::UnsupportedProtocol),
        }
        
        Ok(())
    }
    
    async fn handle_tcp(&mut self, ip_packet: &Ipv4Packet) -> Result<(), Error> {
        let tcp_packet = TcpPacket::new_checked(ip_packet.payload())?;
        
        if tcp_packet.syn() && !tcp_packet.ack() {
            // New connection: SYN
            let stream_id = self.mux.lock().await.open_stream()?;
            // Create smoltcp TCP socket
            // Map socket ↔ stream_id
            // Send OPEN_TCP frame
        }
        
        // ... handle data, FIN, RST
        
        Ok(())
    }
}
```

**Tasks:**
- [ ] Parse IP/TCP/UDP packets (smoltcp wire types)
- [ ] TCP connection tracking (SYN → stream, data → mux)
- [ ] UDP flow tracking (src/dst tuple → flow)
- [ ] ICMP echo (optional, nice-to-have)
- [ ] Response packets: mux data → IP packets → TUN
- [ ] Test end-to-end: app → TUN → netstack → mux → server → target

---

## Phase 8: Full Tunnel + Routing (Days 18-20)

### 8.1 Routing Table Management (TDD)

**Test First:**
```rust
#[test]
fn test_add_route() {
    let mut rt = RoutingTable::new();
    rt.add_route("0.0.0.0/0", "10.255.0.1", "aether0").unwrap(); // default via TUN
    
    let route = rt.lookup("8.8.8.8").unwrap();
    assert_eq!(route.gateway, "10.255.0.1");
    assert_eq!(route.interface, "aether0");
}

#[test]
fn test_route_precedence() {
    let mut rt = RoutingTable::new();
    rt.add_route("0.0.0.0/0", "10.255.0.1", "aether0").unwrap(); // default
    rt.add_route("192.168.0.0/16", "192.168.1.1", "eth0").unwrap(); // LAN direct
    
    assert_eq!(rt.lookup("192.168.1.10").unwrap().interface, "eth0");
    assert_eq!(rt.lookup("8.8.8.8").unwrap().interface, "aether0");
}

#[test]
fn test_pin_server_route() {
    let mut rt = RoutingTable::new();
    let server_ip = "203.0.113.10";
    let old_gw = "192.168.1.1";
    
    rt.pin_route(server_ip, old_gw, "eth0").unwrap();
    
    // Even after default → TUN, server IP goes direct
    rt.add_route("0.0.0.0/0", "10.255.0.1", "aether0").unwrap();
    assert_eq!(rt.lookup(server_ip).unwrap().gateway, old_gw);
}
```

**Implementation (Linux):**
```rust
// aetherlink-client/src/routing_linux.rs
use std::process::Command;

pub struct RoutingTable {
    // In-memory representation
    routes: Vec<Route>,
}

impl RoutingTable {
    pub fn add_route(&mut self, cidr: &str, gateway: &str, iface: &str) -> Result<(), Error> {
        // ip route add <cidr> via <gateway> dev <iface>
        Command::new("ip")
            .args(&["route", "add", cidr, "via", gateway, "dev", iface])
            .status()?;
        
        self.routes.push(Route { cidr: cidr.into(), gateway: gateway.into(), iface: iface.into() });
        Ok(())
    }
    
    pub fn snapshot(&self) -> Vec<Route> {
        // ip route save > snapshot.txt
        // Parse current routes for restore
        todo!()
    }
    
    pub fn restore(&self, snapshot: &[Route]) -> Result<(), Error> {
        // Delete all custom routes
        // Restore from snapshot
        todo()
    }
}
```

**Tasks:**
- [ ] Parse existing routes (`ip route show`)
- [ ] Add/delete routes
- [ ] Snapshot before tunnel up
- [ ] Restore on tunnel down
- [ ] Test idempotent up/down
- [ ] Windows version (defer, use stub)

### 8.2 DNS Override (TDD)

**Test First:**
```rust
#[test]
#[ignore] // integration
fn test_dns_override_on_tunnel_up() {
    let client = Client::new(config);
    
    let original_dns = get_system_dns();
    client.up().unwrap();
    
    let tunnel_dns = get_system_dns();
    assert_eq!(tunnel_dns, vec!["10.255.0.1"]); // virtual DNS
    
    client.down().unwrap();
    assert_eq!(get_system_dns(), original_dns); // restored
}

#[test]
fn test_no_dns_leak_when_up() {
    let client = Client::new(config);
    client.up().unwrap();
    
    // Capture DNS queries (e.g., with tcpdump or mock resolver)
    let resolver = MockResolver::capture_queries();
    
    // Trigger DNS lookup
    resolve_hostname("example.com").unwrap();
    
    // All queries should go to TUN, not ISP DNS
    assert_eq!(resolver.leaked_queries(), 0);
    assert!(resolver.tunnel_queries() > 0);
}
```

**Implementation (Linux):**
```rust
// aetherlink-client/src/dns_linux.rs
pub fn override_dns(dns_servers: &[&str]) -> Result<DnsSnapshot, Error> {
    // Save current /etc/resolv.conf
    let snapshot = std::fs::read_to_string("/etc/resolv.conf")?;
    
    // Write new resolv.conf with tunnel DNS
    let mut new_conf = String::new();
    for server in dns_servers {
        new_conf.push_str(&format!("nameserver {}\n", server));
    }
    std::fs::write("/etc/resolv.conf", new_conf)?;
    
    Ok(DnsSnapshot { original: snapshot })
}

pub fn restore_dns(snapshot: DnsSnapshot) -> Result<(), Error> {
    std::fs::write("/etc/resolv.conf", snapshot.original)?;
    Ok(())
}
```

**Tasks:**
- [ ] Linux: Override `/etc/resolv.conf` or `systemd-resolved`
- [ ] Windows: NRPT (defer, stub)
- [ ] Snapshot DNS before override
- [ ] Restore on down
- [ ] Test no leak (integration with packet capture)

### 8.3 Routing Rules Engine

**Test First:**
```rust
#[test]
fn test_domain_rule_resolve_via_tunnel() {
    let rules = RoutingRules::from_yaml(r#"
        rules:
          - name: example-direct
            action: direct
            priority: 50
            when: { domain: "example.com" }
    "#).unwrap();
    
    let client = Client::new_with_rules(config, rules);
    client.up().unwrap();
    
    // Resolve example.com
    let ip = client.resolve("example.com").unwrap();
    
    // Should resolve via tunnel DNS first
    assert!(client.dns_queries_via_tunnel.contains(&"example.com"));
    
    // Then install direct route to resolved IP
    let route = client.get_route_for_ip(&ip).unwrap();
    assert_eq!(route.action, RouteAction::Direct);
}

#[test]
fn test_cidr_rule_direct() {
    let rules = RoutingRules::from_yaml(r#"
        rules:
          - name: lan
            action: direct
            priority: 10
            when: { cidr: "192.168.0.0/16" }
    "#).unwrap();
    
    let action = rules.match_ip("192.168.1.10");
    assert_eq!(action, RouteAction::Direct);
    
    let action = rules.match_ip("8.8.8.8");
    assert_eq!(action, RouteAction::Tunnel); // default
}
```

**Implementation:**
```rust
// aetherlink-client/src/routing_rules.rs
pub struct RoutingRules {
    rules: Vec<Rule>,
}

pub struct Rule {
    name: String,
    action: RouteAction,
    priority: u32,
    matcher: Matcher,
}

pub enum Matcher {
    Ip(IpAddr),
    Cidr(IpNetwork),
    IpRange(IpAddr, IpAddr),
    Domain(String),
    Suffix(String),
}

impl RoutingRules {
    pub fn match_ip(&self, ip: &IpAddr) -> RouteAction {
        // Sort by priority (lower = higher precedence)
        // Match longest prefix first for CIDR
        // Return action or default (tunnel)
        todo!()
    }
    
    pub async fn materialize_domain(&self, domain: &str, resolver: &DnsClient) -> Result<Vec<IpAddr>, Error> {
        // Resolve domain via tunnel DNS
        let ips = resolver.resolve(domain).await?;
        
        // Install host routes for each IP with action=direct
        for ip in &ips {
            self.install_host_route(ip, RouteAction::Direct)?;
        }
        
        Ok(ips)
    }
}
```

**Tasks:**
- [ ] Parse YAML rules config
- [ ] Implement matchers (IP, CIDR, range, domain, suffix)
- [ ] Priority sorting
- [ ] Domain materialization (resolve → install routes)
- [ ] Re-resolve with TTL/debounce (30s min)
- [ ] Test all rule types

---

## Phase 9: FFI API (Days 21-22)

### 9.1 C ABI Exports (TDD)

**Test First (C caller):**
```c
// tests/ffi_test.c
#include <aetherlink_ffi.h>
#include <assert.h>
#include <stdio.h>

void test_version() {
    const char* version = aether_version();
    printf("Version: %s\n", version);
    assert(version != NULL);
}

void test_client_lifecycle() {
    const char* config = "{\"server_addr\": \"localhost:8443\", \"psk\": \"test\"}";
    
    AetherHandle handle = aether_client_create(config);
    assert(handle != 0);
    
    int err = aether_client_up(handle);
    assert(err == 0);
    
    char status[1024];
    aether_client_status(handle, status, sizeof(status));
    printf("Status: %s\n", status);
    
    aether_client_down(handle);
    assert(err == 0);
}

int main() {
    test_version();
    test_client_lifecycle();
    return 0;
}
```

**FFI Implementation:**
```rust
// aetherlink-ffi/src/lib.rs
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use aetherlink_client::Client;

type AetherHandle = usize;
static mut HANDLES: Option<HashMap<usize, Client>> = None;

#[no_mangle]
pub extern "C" fn aether_version() -> *const c_char {
    static VERSION: &str = "AetherLink 1.5.0\0";
    VERSION.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn aether_client_create(config_json: *const c_char) -> AetherHandle {
    let config_str = unsafe { CStr::from_ptr(config_json).to_str().unwrap() };
    let config = serde_json::from_str(config_str).unwrap();
    
    let client = Client::new(config);
    let handle = client.as_ptr() as usize;
    
    unsafe {
        HANDLES.get_or_insert_with(HashMap::new).insert(handle, client);
    }
    
    handle
}

#[no_mangle]
pub extern "C" fn aether_client_up(handle: AetherHandle) -> i32 {
    let client = unsafe { HANDLES.as_mut().unwrap().get_mut(&handle).unwrap() };
    match client.up() {
        Ok(_) => 0,
        Err(e) => {
            set_last_error(&format!("{:?}", e));
            -1
        }
    }
}

// ... other functions
```

**Tasks:**
- [ ] Define C header (`aetherlink_ffi.h`)
- [ ] Implement all FFI functions (p.3 list)
- [ ] Handle lifecycle (create/up/down/destroy)
- [ ] Error handling (codes + last_error_message)
- [ ] Test from C (gcc/clang)
- [ ] Build cdylib (`aetherlink_core.dll`/`.so`)

### 9.2 .NET P/Invoke Wrapper (TDD)

**Test First (C#):**
```csharp
// dotnet/AetherLink.Client.Tests/FfiTests.cs
using Xunit;
using AetherLink.Client;

public class FfiTests
{
    [Fact]
    public void TestVersion()
    {
        var version = NativeMethods.GetVersion();
        Assert.NotNull(version);
        Assert.Contains("AetherLink", version);
    }
    
    [Fact]
    public void TestClientLifecycle()
    {
        var config = new ClientConfig
        {
            ServerAddr = "localhost:8443",
            Psk = "test-psk"
        };
        
        var handle = NativeMethods.ClientCreate(JsonSerializer.Serialize(config));
        Assert.NotEqual(IntPtr.Zero, handle);
        
        var err = NativeMethods.ClientUp(handle);
        Assert.Equal(0, err);
        
        var status = NativeMethods.ClientGetStatus(handle);
        Assert.NotNull(status);
        
        NativeMethods.ClientDown(handle);
    }
}
```

**Implementation:**
```csharp
// dotnet/AetherLink.Client/NativeMethods.cs
using System.Runtime.InteropServices;

internal static class NativeMethods
{
    const string DllName = "aetherlink_core";
    
    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr aether_version();
    
    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr aether_client_create(
        [MarshalAs(UnmanagedType.LPStr)] string config_json
    );
    
    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int aether_client_up(IntPtr handle);
    
    // ... other imports
    
    public static string GetVersion()
    {
        var ptr = aether_version();
        return Marshal.PtrToStringAnsi(ptr) ?? "";
    }
}
```

**Tasks:**
- [ ] P/Invoke declarations
- [ ] Safe wrapper classes (dispose pattern)
- [ ] Test .NET → FFI calls
- [ ] Build self-contained .NET app

---

## Phase 10: Client Integration (Days 23-25)

### 10.1 Full Client Assembly (TDD)

**Test First (end-to-end):**
```rust
#[tokio::test]
#[ignore] // requires server + root
async fn test_full_tunnel_end_to_end() {
    // Start server
    let server = start_test_server(server_config).await;
    
    // Start client
    let mut client = Client::new(client_config);
    client.up().await.unwrap();
    
    // Verify tunnel is up
    assert_eq!(client.status(), ClientStatus::Connected);
    
    // Make HTTP request through tunnel
    let response = reqwest::get("http://example.com").await.unwrap();
    assert_eq!(response.status(), 200);
    
    // Verify DNS went through tunnel (check logs or counters)
    assert!(client.stats().dns_queries_via_tunnel > 0);
    
    client.down().await.unwrap();
}

#[tokio::test]
#[ignore]
async fn test_direct_rule_bypasses_tunnel() {
    let rules = RoutingRules::from_yaml(r#"
        rules:
          - name: example-direct
            action: direct
            priority: 50
            when: { domain: "example.com" }
    "#).unwrap();
    
    let mut client = Client::new_with_rules(config, rules);
    client.up().await.unwrap();
    
    // Request to example.com should go direct (not through tunnel)
    let response = reqwest::get("http://example.com").await.unwrap();
    
    // Verify it didn't count in tunnel stats
    assert_eq!(client.stats().tunneled_connections.iter().find(|c| c.host == "example.com"), None);
}
```

**Tasks:**
- [ ] Wire all components: TUN → netstack → mux → TLS → server
- [ ] Full lifecycle: resolve server → snapshot → TUN up → routes → DNS → connect
- [ ] Rollback on failure
- [ ] force_cleanup (idempotent restore from persistent state)
- [ ] Status reporting (connected, bytes sent/recv, active streams)

### 10.2 Crash Recovery

**Test First:**
```rust
#[test]
fn test_force_cleanup_restores_network() {
    let mut client = Client::new(config);
    client.up().unwrap();
    
    // Simulate crash (drop client without down)
    drop(client);
    
    // Network should be broken now (default route → dead TUN)
    // Run cleanup
    Client::force_cleanup().unwrap();
    
    // Verify network restored
    let ping = Command::new("ping").args(&["-c", "1", "8.8.8.8"]).status().unwrap();
    assert!(ping.success());
}
```

**Implementation:**
```rust
// aetherlink-client/src/cleanup.rs
pub fn force_cleanup() -> Result<(), Error> {
    // Load state from persistent file
    let state_path = "/var/lib/aetherlink/state.json"; // or %ProgramData%
    if !Path::new(state_path).exists() {
        return Ok(()); // nothing to clean
    }
    
    let state: NetworkState = serde_json::from_str(&std::fs::read_to_string(state_path)?)?;
    
    // Restore routes
    restore_routes(&state.route_snapshot)?;
    
    // Restore DNS
    restore_dns(&state.dns_snapshot)?;
    
    // Delete TUN interface
    delete_tun_interface(&state.tun_name)?;
    
    // Delete state file
    std::fs::remove_file(state_path)?;
    
    Ok(())
}
```

**Tasks:**
- [ ] Persistent state file (routes, DNS, TUN name)
- [ ] Write state on successful `up`
- [ ] `force_cleanup` reads and restores
- [ ] Test crash → cleanup → network OK
- [ ] Idempotent (calling twice is safe)

---

## Phase 11: Testing & Documentation (Days 26-28)

### 11.1 DoD Checklist Tests

Each item from p.11 DoD gets a test:

```rust
// tests/dod_checklist.rs

#[test]
fn dod_01_single_rust_core() {
    // Verify no protocol stack in .NET/Kotlin
    // All crypto/frame/mux code is in Rust crates
    assert!(!Path::new("dotnet/AetherLink.Client/Crypto.cs").exists());
}

#[test]
fn dod_02_ffi_works() {
    // Test from C / .NET
    // (covered in Phase 9 tests)
}

#[tokio::test]
async fn dod_03_tcp_udp_through_tunnel() {
    // (covered in Phase 10 E2E test)
}

#[tokio::test]
async fn dod_04_dns_only_via_tunnel() {
    // Capture DNS packets, verify none leak to ISP
}

#[tokio::test]
async fn dod_05_domain_direct_rule() {
    // Verify resolve via tunnel, connect direct
}

// ... other DoD items
```

### 11.2 Documentation

**Files to create:**
- `docs/SPEC.md` — Full protocol specification (frames, crypto, auth)
- `docs/DECISIONS.md` — All design decisions (netstack choice, DNS virtual IP, etc.)
- `docs/STATUS.md` — Current implementation status
- `docs/FULL_TUNNEL.md` — Full tunnel lifecycle, safety, rollback
- `docs/ROUTING.md` — Routing rules, precedence, domain materialization
- `docs/DNS.md` — DNS no-leak design, virtual resolver
- `docs/BUILD.md` — Build instructions (Rust, .NET, Android)
- `docs/DEPLOY_LINUX.md` — Linux deployment (systemd service, etc.)
- `docs/DEPLOY_WINDOWS.md` — Windows deployment (Windows Service, Wintun)
- `README.md` — Quick start (10-20 lines)

**README Example:**
```markdown
# AetherLink

VPN with userspace netstack. Single Rust core + FFI for .NET/Android.

## Quick Start

### Build
```bash
cargo build --release
cd dotnet/AetherLink.Server && dotnet publish -c Release
```

### Run Server
```bash
./target/release/aetherlink-server --config server.yaml
```

### Run Client
```bash
sudo ./target/release/aetherlink-client --config client.yaml up
```

See `docs/` for details.
```

---

## Phase 12: Windows Wintun (Days 29-31)

### 12.1 Wintun Integration (TDD on Windows)

**Test First:**
```rust
#[test]
#[cfg(windows)]
fn test_wintun_create_adapter() {
    let wintun = WintunDevice::create("AetherLink").unwrap();
    assert_eq!(wintun.name(), "AetherLink");
}

#[test]
#[cfg(windows)]
fn test_wintun_read_write_packets() {
    let mut wintun = WintunDevice::create("AetherLink").unwrap();
    
    // Write packet
    let icmp_packet = build_icmp_echo();
    wintun.write(&icmp_packet).unwrap();
    
    // Read packet (may be looped back or from kernel)
    let mut buf = [0u8; 1500];
    let n = wintun.read(&mut buf).unwrap();
    assert!(n > 0);
}
```

**Implementation:**
```rust
// aetherlink-netstack/src/tun_windows.rs
use wintun::Adapter;

pub struct WintunDevice {
    adapter: Adapter,
    session: Session,
}

impl WintunDevice {
    pub fn create(name: &str) -> Result<Self, Error> {
        // Load wintun.dll from current directory (like v2rayN)
        let wintun_path = std::env::current_exe()?.parent().unwrap().join("wintun.dll");
        let wintun = unsafe { wintun::load_from_path(&wintun_path)? };
        
        // Create adapter
        let adapter = wintun::Adapter::create(&wintun, name, "AetherLink", None)?;
        let session = adapter.start_session(wintun::MAX_RING_CAPACITY)?;
        
        Ok(Self { adapter, session })
    }
    
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let packet = self.session.receive_blocking()?;
        let len = packet.bytes().len();
        buf[..len].copy_from_slice(packet.bytes());
        Ok(len)
    }
    
    pub fn write(&mut self, packet: &[u8]) -> Result<(), Error> {
        let mut write_pack = self.session.allocate_send_packet(packet.len() as u16)?;
        write_pack.bytes_mut().copy_from_slice(packet);
        self.session.send_packet(write_pack);
        Ok(())
    }
}
```

**Tasks:**
- [ ] Load wintun.dll (bundle or download)
- [ ] Create adapter with name "AetherLink"
- [ ] Start session (ring buffers)
- [ ] Read/write packets
- [ ] Configure IP with netsh or Win32 API
- [ ] Test on Windows (requires Admin)

### 12.2 Windows Routing

**Tasks:**
- [ ] Parse routes (`route print`)
- [ ] Add routes (`route add`)
- [ ] Snapshot/restore
- [ ] Test idempotent up/down

### 12.3 Windows DNS (NRPT)

**Tasks:**
- [ ] Set interface DNS (netsh or API)
- [ ] NRPT for split DNS (optional, defer if complex)
- [ ] Test no DNS leak on Windows

---

## Phase 13: .NET Hosts (Days 32-33)

### 13.1 .NET Server Host

**Structure:**
```
dotnet/AetherLink.Server/
├── Program.cs          # Entry point
├── ServerService.cs    # Windows Service / systemd wrapper
├── Config.cs           # Load YAML config
└── NativeMethods.cs    # FFI to Rust core
```

**Implementation:**
```csharp
// Program.cs
using AetherLink.Server;

var config = Config.Load("server.yaml");
var handle = NativeMethods.ServerStart(JsonSerializer.Serialize(config));

if (handle == IntPtr.Zero)
{
    Console.Error.WriteLine("Failed to start server");
    return 1;
}

Console.WriteLine("Server started. Press Ctrl+C to stop.");
Console.CancelKeyPress += (s, e) =>
{
    NativeMethods.ServerStop(handle);
};

await Task.Delay(-1); // run forever
return 0;
```

**Tasks:**
- [ ] Load config from YAML
- [ ] Call FFI `server_start`
- [ ] Windows Service wrapper (optional, systemd for Linux)
- [ ] Logging (structured, no secrets)
- [ ] Publish self-contained (win-x64, linux-x64)

### 13.2 .NET Client Host

**Structure:**
```
dotnet/AetherLink.Client/
├── Program.cs          # CLI: up/down/status
├── ClientWrapper.cs    # Safe wrapper around FFI
├── TrayApp.cs          # Optional system tray (defer)
└── Config.cs
```

**Implementation:**
```csharp
// Program.cs
using AetherLink.Client;

if (args.Length < 1)
{
    Console.WriteLine("Usage: aetherlink-client <up|down|status>");
    return 1;
}

var config = Config.Load("client.yaml");
var client = new ClientWrapper(config);

switch (args[0])
{
    case "up":
        client.Up();
        Console.WriteLine("Tunnel is up");
        break;
    case "down":
        client.Down();
        Console.WriteLine("Tunnel is down");
        break;
    case "status":
        var status = client.GetStatus();
        Console.WriteLine(status);
        break;
}

return 0;
```

**Tasks:**
- [ ] CLI commands (up/down/status)
- [ ] Safe dispose pattern
- [ ] Self-contained publish
- [ ] Test on Windows/Linux

---

## Phase 14: Android (Days 34-37) — DEFER for MVP

Android requires Windows/Linux client to be stable first. Mark as PARTIAL if not in environment.

**Stub structure:**
```
apps/android/
├── app/
│   └── src/main/
│       ├── java/com/aetherlink/
│       │   ├── VpnService.kt
│       │   └── JniBridge.kt
│       └── cpp/
│           └── native-lib.cpp  # JNI → FFI
└── build.gradle
```

**Key tasks (when ready):**
- [ ] VpnService.Builder → establish() → TUN fd
- [ ] Pass fd to Rust via FFI
- [ ] Split tunnel UI (allow/deny apps)
- [ ] DNS via VpnService.Builder.addDnsServer()
- [ ] Test on Android phone/TV

---

## Phase 15: Deploy Scripts (Days 38-39)

### 15.1 Linux Deploy

**`deploy/linux/install.sh`:**
```bash
#!/bin/bash
set -e

# Install Rust core + .NET host
cp target/release/libaetherlink_core.so /usr/local/lib/
cp dotnet/AetherLink.Server/bin/Release/net8.0/linux-x64/publish/AetherLink.Server /usr/local/bin/aetherlink-server
cp dotnet/AetherLink.Client/bin/Release/net8.0/linux-x64/publish/AetherLink.Client /usr/local/bin/aetherlink-client

# Systemd service
cp deploy/linux/aetherlink-server.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable aetherlink-server

echo "AetherLink installed. Configure /etc/aetherlink/server.yaml and start service."
```

**Tasks:**
- [ ] Install script (copy binaries, systemd unit)
- [ ] Uninstall script
- [ ] Config templates (`/etc/aetherlink/`)
- [ ] Test on fresh Ubuntu/Debian VM

### 15.2 Windows Deploy

**`deploy/windows/install.ps1`:**
```powershell
# Install to C:\Program Files\AetherLink
# Copy aetherlink_core.dll, wintun.dll, .NET hosts
# Create Windows Service (optional)
# Add to PATH
```

**Tasks:**
- [ ] Install script (PowerShell)
- [ ] Bundle wintun.dll
- [ ] Config templates (`%ProgramData%\AetherLink\`)
- [ ] Test on fresh Windows VM

---

## Phase 16: Final Integration & Testing (Days 40-42)

### 16.1 E2E Tests Suite

**Scenarios:**
1. **Basic tunnel**: Client connects, makes HTTP request, disconnects
2. **DNS no leak**: Capture packets, verify no ISP DNS queries
3. **Direct rule**: Domain rule resolves via tunnel, connects direct
4. **Crash recovery**: Kill client mid-tunnel, run cleanup, verify network OK
5. **Concurrent streams**: Multiple TCP connections through tunnel
6. **UDP flows**: DNS queries, QUIC, video streaming (if possible)
7. **Server static fallback**: Connect without auth, get static page (no proxy banner)
8. **Auth replay**: Try to reuse nonce, get rejected
9. **Invalid PSK**: Wrong PSK, no tunnel (static fallback)
10. **Routing precedence**: LAN direct, server pin, tunnel default

**Test infrastructure:**
- Docker container with server
- Test client (Linux VM with root)
- Packet capture (tcpdump / Wireshark)
- Assertions on routes, DNS, connectivity

### 16.2 Performance Baseline

**Benchmarks:**
- Throughput (iperf3 through tunnel)
- Latency (ping RTT)
- CPU usage (idle vs. saturated)
- Memory (leak checks with valgrind / sanitizers)

**Goals (MVP, not optimized):**
- Throughput: >100 Mbps on modern hardware
- Latency: +5-10ms overhead vs. direct
- Memory: stable (no leaks)

### 16.3 Documentation Review

**Checklist:**
- [ ] All docs exist and are accurate
- [ ] SPEC matches implementation
- [ ] DECISIONS recorded
- [ ] STATUS up-to-date
- [ ] README has quick start
- [ ] Deploy scripts tested
- [ ] DoD items checked off

---

## Summary & Timeline

| Phase | Days | Description | TDD Focus |
|-------|------|-------------|-----------|
| 0 | 1 | Bootstrap structure | No tests (scaffolding) |
| 1 | 2-3 | Crypto + Auth | Golden vectors, unit tests |
| 2 | 4-5 | Frame protocol | Codec tests, golden frames |
| 3 | 6-7 | Mux layer | Stream management tests |
| 4 | 8-9 | UDP + DNS | Flow tests, virtual DNS |
| 5 | 10-11 | TLS transport | Handshake, ALPN tests |
| 6 | 12-14 | Server core | Auth, relay, fallback tests |
| 7 | 15-17 | Netstack (smoltcp) | Packet parsing, TCP/UDP tests |
| 8 | 18-20 | Full tunnel + routing | E2E routing, DNS override tests |
| 9 | 21-22 | FFI API | C caller, .NET P/Invoke tests |
| 10 | 23-25 | Client integration | Full lifecycle, crash recovery |
| 11 | 26-28 | Testing + docs | DoD checklist, documentation |
| 12 | 29-31 | Windows Wintun | Wintun-specific tests |
| 13 | 32-33 | .NET hosts | CLI, service tests |
| 14 | 34-37 | Android (DEFER) | VpnService tests |
| 15 | 38-39 | Deploy scripts | Install/uninstall tests |
| 16 | 40-42 | Final integration | E2E suite, perf baseline |

**Total: ~42 days** (6 weeks at full pace)

**MVP without Android: ~33 days** (mark Android as PARTIAL)

---

## TDD Principles Throughout

### 1. Red-Green-Refactor Cycle
- Write failing test first (defines contract)
- Minimal implementation to pass
- Refactor without changing behavior

### 2. Test Types
- **Golden tests**: Protocol vectors (immutable, canonical)
- **Unit tests**: Each module in isolation
- **Integration tests**: Multiple modules together
- **E2E tests**: Full system with real network

### 3. Test Coverage Goals
- Crypto: 100% (golden vectors + edge cases)
- Protocol: 100% (all frame types)
- Netstack: 80%+ (happy path + errors)
- FFI: 100% (all exported functions)
- E2E: Key scenarios from DoD

### 4. CI/CD (future)
- `cargo test` on every commit
- E2E tests in Docker on main branch
- Clippy + rustfmt enforcement
- No merge without green tests

---

## Next Steps

1. **Create project structure** (Phase 0)
2. **Write first test**: `test_generate_auth_token_rfc_vector`
3. **Implement to pass**: `generate_auth_token`
4. **Iterate**: Red → Green → Refactor

Ready to start implementation? 🚀
