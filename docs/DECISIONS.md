# AetherLink v1.5 — Design Decisions

This document records all architectural and implementation decisions for AetherLink v1.5.
Each decision includes the context, alternatives considered, and rationale.

---

## DEC-001: Netstack Choice — smoltcp + Custom Async Wrapper

**Date:** 2025-01-18  
**Status:** Accepted

### Context
Need a userspace network stack for TCP/UDP/ICMP processing in the data plane (TUN → IP packets → TCP/UDP flows).

### Alternatives Considered
1. **smoltcp** — Pure Rust, mature, MIT/0BSD, used in embedded/production
2. **tun2socks5-rs / tokio-tun** — High-level, tokio-based, easier integration
3. **gVisor netstack (Go)** — Not Rust, FFI complexity
4. **Custom from scratch** — Too much effort, reinventing wheel

### Decision
**Use smoltcp with a custom async wrapper** (`aetherlink-netstack` crate).

### Rationale
- Full control over TCP/UDP state machines
- No GPL/copyleft issues (MIT/0BSD)
- Proven in production (embedded, VPN projects like wireguard-rs)
- Aligns with "userspace netstack like gVisor" requirement
- Can evolve to support custom protocols if needed
- Pure Rust, no C dependencies

### Implementation
- `smoltcp::iface::Interface` manages L3 routing
- `smoltcp::socket::TcpSocket` for TCP connections
- `smoltcp::socket::UdpSocket` for UDP flows
- `tokio` runtime for async I/O
- Custom `NetstackManager` bridges smoltcp ↔ multiplexer

---

## DEC-002: TUN Subnet and Virtual DNS IP

**Date:** 2025-01-18  
**Status:** Accepted

### Context
Need to allocate a virtual subnet for the TUN interface and a virtual DNS resolver IP.

### Decision
- **TUN Subnet:** `10.255.0.0/30` (4 addresses: .0 network, .1 gateway/DNS, .2 client, .3 broadcast)
- **Virtual DNS IP:** `10.255.0.1:53`
- **Virtual Gateway IP:** `10.255.0.1`

### Rationale
- `/30` provides exactly 2 usable host addresses (gateway + client)
- 10.255.0.0/16 is reserved for carrier-grade NAT, unlikely to conflict
- Single IP serves as both gateway and DNS resolver (simplifies routing)
- Client gets 10.255.0.2, gateway/DNS is 10.255.0.1

---

## DEC-003: UDP Frame Layout

**Date:** 2025-01-18  
**Status:** Accepted

### Context
Need to define frame types for UDP flows (including DNS).

### Decision
| Type | Name | Purpose |
|------|------|---------|
| 7 | OPEN_UDP | Open UDP flow: addr_type, addr, port |
| 8 | UDP_DATAGRAM | UDP payload for existing flow |
| — | DNS frames | **Not used** — DNS is regular UDP flow to virtual DNS IP |

### Rationale
- DNS queries are just UDP packets to `10.255.0.1:53`
- No need for special DNS frame types
- Simplifies protocol: all UDP is uniform
- Server relays UDP flows to configured upstreams (1.1.1.1, 8.8.8.8)

---

## DEC-004: Wintun Version and License

**Date:** 2025-01-18  
**Status:** Pending (needs verification)

### Context
Windows TUN implementation requires Wintun driver.

### Decision
- Use `wintun` crate (official Rust bindings)
- Bundle `wintun.dll` alongside executable (like v2rayN)
- Load from current directory at runtime

### Rationale
- Official Rust bindings maintained by WireGuard team
- Same approach as v2rayN (proven pattern)
- No driver installation required for users (just DLL)

---

## DEC-005: DNS Upstream List

**Date:** 2025-01-18  
**Status:** Accepted

### Context
Server needs default upstream DNS resolvers for tunnel DNS queries.

### Decision
**Default upstreams:** `1.1.1.1:53` (Cloudflare), `8.8.8.8:53` (Google)
- Configurable via `server.dns_upstream` in YAML
- Round-robin or latency-based selection (TBD)

### Rationale
- Both are fast, reliable, privacy-respecting
- Geographic diversity
- Support both UDP and TCP DNS

---

## DEC-006: Nonce Replay Cache TTL

**Date:** 2025-01-18  
**Status:** Accepted

### Context
Auth protocol uses client nonce; server must reject replays.

### Decision
**Default TTL: 5 minutes (300 seconds)**
- In-memory HashMap with periodic cleanup
- Configurable via `server.auth_nonce_ttl_secs`

### Rationale
- 5 minutes covers reasonable clock skew + network latency
- Short enough to limit memory growth
- Long enough for slow clients

---

## DEC-007: TLS ClientHello Fingerprint

**Date:** 2025-01-18  
**Status:** Accepted

### Context
G1 invariant requires TLS fingerprint to look like browser HTTPS.

### Decision
- Use `rustls` defaults (best-effort)
- Configure ALPN: `h2`, `http/1.1`
- No custom fingerprinting for MVP (defer to post-MVP)

### Rationale
- rustls defaults are reasonable for Chrome-like fingerprint
- Custom fingerprinting is complex and brittle
- MVP goal: working tunnel, not perfect stealth

---

## DEC-008: Frame Padding Strategy

**Date:** 2025-01-18  
**Status:** Accepted

### Context
Frames support padding to `pad_multiple` for traffic analysis resistance.

### Decision
- Pad encrypted payload to multiple of `pad_multiple` (default 128 bytes)
- Padding bytes are random
- Length field includes padding

### Rationale
- 128 bytes balances overhead vs. privacy
- Random padding prevents length-based fingerprinting
- Configurable per connection

---

## DEC-009: Routing Rules Precedence

**Date:** 2025-01-18  
**Status:** Accepted (from AGENT_INSTRUCTIONS.md)

### Context
Need fixed precedence for routing rules.

### Decision
1. Loopback
2. Pin server IP(s) via physical GW
3. Routing rules `direct` (by priority + longest prefix)
4. Android app split (allow/deny) — Android/TV only
5. Default → tunnel

### Rationale
- Ensures server connectivity always maintained
- Explicit rules override default tunnel
- Android split tunnel only on Android

---

## DEC-010: DNS Mode — Tunnel Only When Connected

**Date:** 2025-01-18  
**Status:** Accepted

### Context
DNS must not leak when tunnel is up.

### Decision
- `dns_mode: tunnel` (only valid value when connected)
- System DNS overridden to virtual DNS IP (`10.255.0.1`)
- On `down`: full restore of original DNS
- Domain direct rules: resolve via tunnel DNS first, then install direct route to IP

### Rationale
- Prevents all DNS leaks by design
- Domain direct rules still work (resolve via tunnel, then route direct)
- Full restore on disconnect prevents broken network state

---

## DEC-011: Android minSdk 26, targetSdk 35

**Date:** 2026-09-18
**Status:** Accepted (owner pinned minSdk 26)

### Context
No minimum Android version was specified; `apps/android` had no manifest or
gradle files, so no targeting existed at all. Phone + Android TV / Google TV
must be covered with one floor.

### Decision
- **minSdk 26** (Android 8.0), **targetSdk/compileSdk 35**
- Package `link.aether.client`; `VpnService` declared with
  `BIND_VPN_SERVICE`; Leanback feature optional (TV)
- Native ABIs: `arm64-v8a`, `armeabi-v7a`, `x86_64` (Rust core `.so` per ABI
  via cargo-ndk into `jniLibs/<abi>/libaetherlink_core.so`)

### Rationale
- API 26 covers ~99% of phones and all maintained TV boxes while avoiding
  legacy branches (notification channels for the foreground VPN service,
  Java 8 APIs)
- API 21 floor imposed by `addAllowedApplication`/`addDisallowedApplication`
  is satisfied with margin; going below 26 would only buy ancient TV boxes
  at the cost of version checks throughout the Kotlin layer