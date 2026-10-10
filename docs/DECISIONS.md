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
**Status:** Accepted (open path verified; live session needs admin)

### Context
Windows TUN implementation requires Wintun driver.

### Decision
- Use `wintun` crate 0.5 (latest available; there is no 0.14)
- Bundle `wintun.dll` alongside executable (like v2rayN)
- Load order: next to the exe first, then default search rules; missing
  DLL and missing admin both fail with named errors, never silently
- API: `load_from_path`/`load` → `Adapter::open`, else `Adapter::create`
  ("AetherLink") → `start_session(MAX_RING_CAPACITY)

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
---

## DEC-012: TLS-Fidelity Hardening (G1/G2)

**Date:** 2026-09-24
**Status:** Accepted (supplements DEC-007 for the hardening phase)

### Context
DEC-007 settled TLS appearance on rustls defaults (best-effort) to unblock
MVP. Live operation on restrictive networks showed the gap explicitly:
handshakes succeed, but the connection is trivially distinguishable from
generic browser HTTPS by ClientHello composition and fallback behavior.
G1/G2 require the session to look like ordinary HTTPS traffic to both
passive observation and unsolicited connection attempts.

### Decision
- Single TLS profile for the whole data plane, owned by Rust core:
  fixed ALPN order, restricted TLS 1.3 cipher list, no unique
  extensions/values, SNI strictly from config, uniform resumption policy.
- Server fallback answers exactly like a generic static web server
  (statuses, headers, timing, close semantics); no tunnel markers anywhere,
  including error paths and timing side channels.
- ClientHello composition covered by golden vectors (protocol/tests):
  any deviation fails the build.
- No per-host TLS stacks: thin hosts keep calling core over FFI
  (enforced by `check_thin_hosts.ps1`).

### Rationale
- Compatibility framing: middleboxes, corporate proxies and antivirus TLS
  interception all treat unusual handshakes as suspicious; looking exactly
  like mainstream browsers maximizes connectivity everywhere.
- One profile in one place (core) instead of per-host tweaks: fewer
  fingerprints, single audit surface, tests stay deterministic.
- Static-only fallback (no reverse proxy) keeps the unauthenticated
  surface minimal and behaviorally identical to commodity hosting.

### Non-goals (explicitly out of scope)
- Custom per-browser ClientHello mimicry libraries; ECH; traffic decoys.
  Revisit only with measured need, as separate DECs.

---

## DEC-013: Linux Client Platform (Ubuntu 24.04)

**Date:** 2026-10-10
**Status:** Accepted

### Context
The Windows client (Wintun + `route`/`netsh` + .NET host over FFI) is
working. A Linux client is needed on the same Rust core, targeting
Ubuntu 24.04, with the same full-tunnel safety invariants (pin route,
def1 default swap, DNS-no-leak, snapshot/rollback, crash journal).

### Decision
- **Host:** native thin Rust binary `aetherlink-cli` (crate
  `aetherlink-cli`) linking `aetherlink-client` directly. No second
  protocol stack — all wire/crypto/netstack stays in the core
  (AGENT_INSTRUCTIONS §1.1; the CLI is the sanctioned "optional Rust
  CLI" host). The .NET-over-FFI path also works on Linux now (the
  platform backend is chosen at compile time), but the native binary is
  the deliverable: no .NET runtime on the client box.
- **TUN:** `/dev/net/tun` via `TUNSETIFF` (IFF_TUN | IFF_NO_PI), raw IP
  packets, non-blocking fd held for the session. The device is created
  non-persistent, so closing the last fd deletes it — a crashed client
  cannot leave a stale TUN behind.
- **Routes:** iproute2 `ip`. Server pin + direct rules via
  `ip route add ... via <prev-gw>`; default swap is the same
  OpenVPN-style **def1** pair as Windows (`0.0.0.0/1` + `128.0.0.0/1`),
  gatewayed at the virtual DNS IP `10.255.0.1` which is on-link on the
  TUN /30 (TUN is NOARP, so the kernel hands packets straight to the fd).
- **DNS:** Ubuntu 24.04 runs `systemd-resolved`. Force = `resolvectl dns
  <phys> 10.255.0.1` + `resolvectl domain <phys> '~.'` (route every name
  into the tunnel resolver); restore = `resolvectl revert <phys>`.
  Fallback for resolved-less systems: rewrite `/etc/resolv.conf` with an
  exact-restore marker (symlink vs file vs missing).
- **Crash recovery:** identical journal contract to Windows
  (`UpState` applied-change log, replayed by `down`/`force_cleanup`),
  state at `/var/lib/aetherlink/state.json`.

### Rationale
- iproute2 + resolvectl are the stock, locale-independent tooling on the
  target; parsing their keyword-shaped output is robust (parsers are pure
  and unit-tested, mirroring `platform/windows.rs`).
- def1 avoids touching/metric-warring the real default route and makes
  rollback trivial, already proven on Windows.
- A native binary keeps the client box dependency-free (Rust is only a
  build-time requirement).

---

## DEC-014: WiFi Hotspot — Sharing the Tunnel (Linux)

**Date:** 2026-10-10
**Status:** Accepted

### Context
The Linux client must be able to *share* the tunneled traffic over WiFi
(the box becomes an access point; joined devices go through the tunnel).
Ubuntu 24.04 installs differ: Desktop has NetworkManager, Server does not.

### Decision
- **Two backends, one entry point** (`aetherlink-hotspot` crate,
  `hotspot up/down/status` CLI + `hotspot:` config section):
  - `network-manager`: one `nmcli` connection, `wifi.mode ap` +
    `ipv4.method shared` (NM runs DHCP + NAT). Desktop default.
  - `hostapd` + `dnsmasq`: generated configs in `/run/aetherlink/`.
    Headless default. `auto` picks NM when it runs and manages the WiFi
    device, else hostapd. When hostapd is used on a box where
    NetworkManager runs, the WiFi device is set `managed no` for the AP's
    lifetime (NM would otherwise grab the channel and kill hostapd) and
    handed back on `down` — recorded in state so only a device we flipped
    is ever re-managed.
- **Client subnet:** default `192.168.243.0/24` (away from common home
  /24s so the LAN-direct rules rarely shadow it); gateway/DNS = `.1`,
  DHCP pool `.100-.199` (full remaining range on tiny prefixes).
- **Fail-closed guard:** a dedicated nftables table
  (`inet aetherlink_hotspot`) lets traffic from the AP interface leave
  **only** through the tunnel interface `aether0`; everything else from
  the AP is dropped, and client TCP SYN gets an MSS clamp to the tunnel
  MTU. If the tunnel is down, clients are blocked instead of leaking
  direct. The table is applied on `up`, deleted on `down` — owned
  end-to-end by the hotspot.
- **DNS:** clients receive the box's hotspot address as DNS; dnsmasq/NM
  forward upstream to the box resolver, which is tunnel-forced while up
  (DNS_NO_LEAK) — no separate leak path for hotspot clients.
- **ip_forward** is enabled on `up` and restored to its exact previous
  value on `down`; runtime state (backend, iface, subnet, prev
  ip_forward) persists in `/run/aetherlink/hotspot.json` (tmpfs: a
  reboot clears it together with the AP).

### Rationale
- Supporting both backends covers Desktop and Server 24.04 installs with
  one code path each; all config/render logic is pure and unit-tested.
- Fail-closed matches the product's no-leak posture: a half-tunnel that
  silently routes clients direct would be a privacy bug, so the guard is
  brought up *before* clients can associate.
- Keeping hotspot state in `/run` means nothing survives a reboot that
  the kernel hasn't already torn down.

### Non-goals (explicitly out of scope)
- 5 GHz / per-band steering (config knob later); client isolation toggle;
  per-client accounting; IPv6 for hotspot clients.
