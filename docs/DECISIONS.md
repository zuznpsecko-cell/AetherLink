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

## DEC-013: Endpoint Profiles in Client YAML

**Date:** 2026-10-27
**Status:** Accepted (Windows GUI; Android deferred)

### Context
The Windows GUI exposed exactly one server (`server_addr`, `outer_sni`,
`psk`). Users switching between VPS endpoints had to retype all three fields
and could not keep a named backup. The core, FFI and CLI are deliberately
single-server, and moving endpoint selection into Rust would widen the
protocol surface and break the thin-host rule.

### Decision
- A connection profile ("endpoint") is `name`, `server_addr`, `outer_sni`,
  `psk`. Full tunnel, MTU, DNS mode and routing rules stay shared and are not
  duplicated per profile.
- Profiles live in the existing `client.local.yaml` under
  `client.endpoints`, with `client.active_endpoint` naming the selection.
- The active profile is mirrored into the legacy
  `client.server_addr/outer_sni/psk` on every save. Core and CLI keep reading
  those three keys and never learn about the list; an empty `outer_sni` is
  mirrored as the host.
- A legacy single-server file is migrated on load into one profile named
  `default`. The list wins over a stale mirror when both are present.
- Switching is manual. Selecting another profile while the tunnel is up runs
  `Down → save config → Up`; while down it only saves. A failed reconnect
  leaves the tunnel down with the network restored and the profile selected
  for retry.
- `name` is the identity: unique case-insensitively, 1..64 chars. The last
  profile cannot be deleted. PSK stays plaintext in YAML as before and is
  never logged.

### Rationale
- One protocol stack (Rust) and one document (YAML): the GUI adds a list and a
  mirror, not a second config path. `gui_endpoint_list_is_ignored_by_core`
  pins the contract.
- Mirroring keeps CLI, Android and any config reader working unchanged
  during the transition.
- Down-before-up avoids two live sessions, stale routes and DNS pointing at a
  dead tunnel; explicit failures beat silent failover while transport quality
  is still being measured.

### Non-goals (explicitly out of scope)
- Automatic failover, health checks, latency probes, subscriptions, QR/import,
  PSK encryption at rest, and endpoint lists in core/FFI/CLI. Revisit with
  measured need as separate DECs.
- Android UI profiles: separate effort after live Windows testing; it can read
  the same `client.endpoints` shape later.

### Tests
- `dotnet/AetherLink.Gui.Tests`: EndpointRules (14), EndpointBook (11),
  ConfigService (8), EndpointSwitcher (4), MainViewModel (12) — 49 total.
- `crates/aetherlink-client/tests/config_schema.rs`:
  `gui_endpoint_list_is_ignored_by_core`.
- Gates: `scripts/check_gui_endpoints.ps1`, `scripts/check_thin_hosts.ps1`.
- Log: `docs/WINDOWS_GUI.md`.

---

## DEC-014: Per-frame generation in the header (protocol v2)

**Date:** 2026-11-23
**Status:** Accepted

### Context
Protocol v1 derived the AEAD nonce from `(stream_id, sequence, type)` while
`MuxManager` deliberately recycles stream ids: a session outlives the 16-bit id
space and `alloc_id` wraps after 32 768 allocations. The OPEN frame always uses
`sequence = 0`, so the first repeated nonce under the single per-session
traffic key was `(id, 0, OpenTcp)` — with the dial target inside the sealed
payload. There is no rekey mechanism anywhere in the tree.

Repeating a ChaCha20-Poly1305 nonce is catastrophic, not degrading: it repeats
the keystream (XOR of two ciphertexts recovers plaintext) and repeats the
Poly1305 one-time key (tags become forgeable).

### Alternatives Considered
1. **Per-stream key** (`HKDF(session_key, dir || id || generation)`) — stronger
   compartmentalisation, but the generation must be negotiated through the
   OPEN frame; when an OPEN is skipped server-side (blocklist hit, parse error,
   `continue` in the accept loop) the two sides desynchronise and the stream
   breaks.
2. **Full rekey epochs** — the textbook answer (QUIC/WireGuard), but it needs
   an epoch-agreement frame or a trigger both sides observe deterministically.
   Neither exists today; it is a much larger change.
3. **Random 4-byte nonce prefix** — birthday collisions after ~2^16 frames per
   session, i.e. minutes of traffic. Rejected.

### Decision
Carry a 32-bit `generation` in the frame header (offset 11, inside the 13
reserved bytes v1 already transmitted as zeros, so frames do not grow) and
derive

```
nonce12 = id(u16 BE) || generation(u32 BE) || seq(u32 BE) || type(u8) || 0
```

`generation` is monotonic per `(id, direction)` for the whole session: a
`last_generation` tombstone survives `close`, and every fresh incarnation of an
id (local `open_tcp`/`open_udp`, `register_inbound`) claims `last + 1`.
Exhausting the 32-bit space is a hard error (`MuxError::NonceSpaceExhausted`),
never a wrap.

The remaining 9 reserved bytes are filled with fresh randomness on every frame.
They carried no meaning in v1 (constant zeros, a free fingerprinting signal) and
every reader ignores them, so this costs nothing on the wire.

The layout lives once in `aetherlink_protocol::build_nonce`; the mux wraps it.

### Consequences
- **Breaking.** `PROTOCOL_VERSION` is 2. A v1 peer is refused at the preface
  byte (`handshake_server`), which is a clean, explicit failure — v1 would
  otherwise fail every AEAD open with a misleading "authentication failed".
- `open` (DATA/UDP) rejects a frame whose generation differs from the live
  incarnation, before decryption: late frames from a closed life of the id
  cannot be replayed into the new one, and a peer that re-opened an id it has
  not registered yet fails closed instead of corrupting the new stream.
- Ids are still recycled, so the id space stays as large as before; the cost is
  one `HashMap` entry per id ever used (bounded by 65 536).
- Non-goal: full per-stream keys and rekey epochs stay open (alternatives 1 and
  2); `generation` removes the immediate nonce-reuse break, it does not add
  compartmentalisation or forward secrecy.

### Tests
- `crates/aetherlink-mux/tests/nonce_generation.rs`: 600 incarnations of one
  id produce no duplicate OPEN or DATA nonce; generation advances on recycle;
  stale/newer generations are refused.
- `crates/aetherlink-frame/src/codec.rs`: generation round-trips at the
  documented offset; the reserved tail differs per frame and does not disturb
  decoding.
- `protocol/tests/golden.rs`: pinned v2 header bytes and nonce layout; a nonce
  from another generation cannot open the frame.

---

## DEC-015: Server resilience — unwind, pre-auth bounds, connection cap

**Date:** 2026-11-23
**Status:** Accepted

### Context
Three independent properties of the server made one unauthenticated peer
enough to take the process (or a slot) down:

1. `[profile.release] panic = "abort"` made every `catch_unwind` guard dead
   code in the shipped binary. The guards are the *only* containment between a
   single malformed flow and the whole host: `serve_background` spawns one
   thread per connection, `forward_tcp` one per stream, `RelayPool` one per
   relay job.
2. `session::handshake_server` read the AUTH frame length out of a clear-text
   header and did `vec![0u8; header.length]` **before** verifying the token —
   up to 16 MiB of server RAM per unauthenticated TLS connection.
3. The accept loop was unbounded (documented as "DoS hardening is a
   follow-up"), one 4 MiB-stack thread per socket, with no handshake deadline.

### Decision
1. **`panic = "unwind"` in the release profile.** Panics are contained per
   connection/stream/job; the containment function logs the event. Chosen over
   "remove the guards and accept fail-fast" because a VPN server whose entire
   client base drops when one flow misbehaves is not an acceptable failure
   mode for a process that also repairs routes and DNS on the way out.
2. **Fixed AUTH size, checked before allocating.** The AUTH payload is exactly
   `AUTH_FRAME_LEN` (64 B: nonce + token). Any other declared length fails with
   `CoreError::FrameTooLarge`. Post-auth frames are bounded the same way by
   `MAX_WIRE_BODY` (`24 B header + 64 KiB`), which is one TLS record plus
   slack — the client chunks at 16 KiB, so a larger header is a lying header.
3. **`server.max_connections`** (default `DEFAULT_MAX_CONNECTIONS = 512`,
   zero clamped to 1). Enforced twice: a cheap check in the accept loop avoids
   spawning a thread, and `serve_connection` takes an RAII `ConnectionSlot`
   so capacity is returned on drop, including on panic. Past the cap sockets
   are dropped (shed), never queued.
4. **Handshake deadline.** `tls::accept_tls_with_timeout`
   (`DEFAULT_HANDSHAKE_TIMEOUT = 10 s`) arms `SO_RCVTIMEO`/`SO_SNDTIMEO` for
   `complete_io` and **clears them afterwards** — a leftover 10 s read timeout
   would silently interact with the tunnel's own 5 ms poll.

While in the same code, `server.max_streams` is no longer ignored
(`MuxManager::set_max` is applied at session start), and `RelayPool` had two
liveness bugs fixed: `dispatch` reserved its slot only *after* the job became
visible (a fast worker could make `active` underflow to `usize::MAX`, wedging
the pool at "busy" forever), and a panicking job never posted a completion, so
its slot leaked.

### Consequences
- A panic no longer aborts the process; it costs one connection and a log
  line. Binary size grows slightly (unwind tables).
- `Vec`-free handshake: no unauthenticated allocation above 64 B.
- Capacity is now a config knob; the default 512 connections x 4 MiB stack is
  ~2 GiB of virtual address space, not resident memory, but it is the number to
  tune on small VPS instances.
- Not addressed here: per-IP rate limiting, TLS-handshake-completion
  accounting, and `max_streams` being per connection rather than per host.

### Tests
- `crates/aetherlink-server/tests/resilience.rs`: slot release on drop and on
  panic; over-cap connection shed as `Path::Closed` with no bytes served;
  handshake deadline fails closed on a silent peer; deadline does not leak into
  the served stream.
- `crates/aetherlink-server/tests/relay_pool.rs`: `fast_worker_never_underflows_the_active_counter`,
  `panicking_job_returns_its_slot`.
- `crates/aetherlink-core/tests/session_handshake.rs`:
  `oversized_auth_body_is_refused_before_allocation`,
  `truncated_auth_body_is_refused`.
- `crates/aetherlink-server/tests/config_schema.rs`: `max_connections_parses_and_defaults`.

---

## DEC-016: Frame header is AEAD associated data

**Date:** 2026-11-23
**Status:** Accepted — **breaking wire change** (release this with DEC-014)

### Context
`encode_frame`/`decode_frame` sealed the payload with `aad = &[]`. The 24-byte
header travels in clear text inside TLS, so every header field was
*unauthenticated*: an attacker positioned inside the TLS-terminating layer
(a compromised client, a hostile TLS terminator, a buggy relay, or simply a
later refactor that trusts the header) could rewrite it and the ciphertext
would still decrypt.

The consequences are concrete, not academic:

- `stream_id` selects which TUN flow the plaintext is injected into. Editing
  it moves bytes between flows — cross-stream injection with a valid AEAD tag.
- `generation` is the nonce component DEC-014 depends on. Unauthenticated, a
  peer can claim any generation and steer which key stream position is tried.
- `length` decides how many bytes are read as ciphertext (already bounded by
  DEC-015, but the bound was the only check).
- `flags` is reserved and ignored today — which is precisely why it must be
  authenticated *before* something starts trusting it.

### Decision
The AAD is the header without its random tail:

```text
length(3) || type(1) || flags(1) || stream_id(2) || sequence(4) || generation(4)
```

15 bytes, produced by `codec::header_aad(&FrameHeader)` and used by both
directions. The 9 random bytes are excluded on purpose: they carry no meaning,
and including them would make the AAD depend on bytes the sender regenerates
per frame (it would still work, but it would authenticate noise).

`encode_frame` now builds the header *before* encrypting, so the length field
(known: plaintext + fixed 16-byte tag) is part of the committed data.

### Consequences
- Any header edit fails AEAD authentication: `stream_id`, `sequence`,
  `generation`, `flags`, `type` and `length` are all protected.
- **Wires are incompatible with earlier builds of v2.** v2 was never released,
  so this rides along with it; a v2 peer built before this commit fails
  decryption, not the preface check. Ship both sides together.
- Cost: 15 extra bytes of AAD per frame in Poly1305 — no extra RAM, no extra
  packets, no extra round trip.
- `header_aad` is duplicated nowhere: both codec directions and both hosts go
  through `codec::encode_frame`/`decode_frame`, so there is one definition.

### Tests
`crates/aetherlink-frame/tests/header_auth.rs`:
`aad_covers_every_meaningful_header_field`, `untampered_frame_still_roundtrips`,
`tampered_header_is_rejected_by_the_aead`,
`tampered_reserved_tail_is_accepted`, `frame_cannot_be_moved_to_another_stream_id`.

---

## DEC-017: Replay handling is typed, and the dead `ReplayWindow` is gone

**Date:** 2026-11-23
**Status:** Accepted

### Context
Two replay mechanisms existed and neither did its job:

1. `aetherlink_frame::codec::ReplayWindow` (window 1024, `u64` bitmap) was
   **never constructed anywhere**. Its three unit tests passed against a
   struct no caller uses, which is worse than having no tests: it advertised
   replay protection the mux did not implement.
2. The real window lives in `MuxManager` and did work, but reported every
   rejection as `MuxError::Internal("replay seq")` / `("stale seq")` —
   indistinguishable from genuine state corruption, and indistinguishable from
   `StaleGeneration`. Callers could only log, so a retransmit and a tampered
   stream looked identical in the logs.

The mux anchor (`max_seen`) was also updated only for `seq > max_seen`, which
was correct, but the surrounding code made the rule easy to break because the
`seen` set and the distance check disagreed about what "old" meant.

### Decision
1. Delete `codec::ReplayWindow` and its tests. The mux owns the only window;
   a second, unused implementation is a liability. `FrameError::ReplayDetected`
   stays (published error surface) with a comment saying the mux is the owner.
2. Add `MuxError::ReplayDetected { stream_id, seq }` and
   `MuxError::StaleGeneration { stream_id, got, expected }`. Both mean "drop
   this frame, the stream is fine". `Internal` now means only what it says.
3. Keep the window semantics but state them explicitly in the code comment:
   `seen` catches duplicates inside `REPLAY_WINDOW`, the distance check rejects
   anything older, and an accepted out-of-order frame updates the anchor.
4. Client: a rejected DATAGRAM no longer propagates as a frame error. UDP is
   lossy by definition and the caller can only log, so the drop is logged and
   the flow is kept — the same policy DATA already followed.

### Consequences
- One replay implementation, exercised by real callers.
- Errors carry enough data to log the *reason* (duplicate vs stale vs old).
- Behaviour change: `open_data`/`open_datagram` now return `ReplayDetected`
  instead of `Internal` for replays. Any host matching on the variant must
  update; the practical handling (log and continue) is unchanged.
- Still not done: defending against an attacker who can *delay* frames past the
  window. That needs a rekey-based bound, not a bitmap.

### Tests
`crates/aetherlink-mux/tests/replay_window.rs`:
`duplicate_sequence_is_a_typed_replay_rejection`,
`stale_generation_is_reported_separately_from_replay`,
`out_of_order_frame_advances_the_anchor`,
`sequence_zero_data_frame_is_rejected`,
`header_that_does_not_match_the_ciphertext_fails_authentication`,
`unexpected_frame_type_is_not_a_replay`.

---

## DEC-018: Host tuning belongs to the deployment, not the library

**Date:** 2026-11-23
**Status:** Accepted

### Context
`accept::serve_connection` called `ensure_linux_wan_tuning()` on the first
accepted connection: it wrote six `/proc/sys/net/*` files (16 MiB buffers, `fq`,
`bbr`). `aetherlink-server` is a library as well as a daemon — it is linked
into the FFI `.so` that .NET hosts, tests and Android load. A library silently
rewriting host-wide kernel settings on a network event is wrong on three
counts: it changes state the embedder never asked for, it fails silently
without `CAP_NET_ADMIN` (the `let _ =` swallowed the error), and the
`Once` made the failure permanent for the process lifetime.

### Decision
Replace the writer with `warn_if_wan_tuning_missing()`: read `rmem_max` and
`wmem_max` once, and log a single hint when they are below 16 MiB, naming the
file `deploy/linux/install.sh` already installs
(`/etc/sysctl.d/99-aetherlink.conf`) and the command to apply it. The
deployment script keeps doing the tuning; the process reports the mismatch.

### Consequences
- The library no longer mutates `/proc/sys`; embedding it is side-effect free.
- Operators who never ran `install.sh` get a log line instead of silently poor
  throughput.
- `tcp_rmem`/`tcp_wmem`/`default_qdisc`/`congestion_control` are no longer
  checked: their formats are lists/modules and the diagnosis would be noisy.
  `install.sh` remains the single source of truth for all six.

---

## DEC-019: FFI handle lock is never held across network I/O

**Date:** 2026-11-23
**Status:** Accepted

### Context
The C ABI keeps every client and server handle in one process-global
`Mutex<HandleMap>`. `aether_client_up`, `aether_client_down`,
`aether_client_status` and `set_rules` held that mutex for the whole call, so a
single `aether_client_up` (TLS handshake + route repair + TUN bring-up, easily
seconds on a bad network) serialised *every* handle operation in the process:
`aether_server_stop` on an unrelated server, and the `status` poll a GUI runs on
its UI thread, both blocked behind it. A slow connect froze the whole host
application — a lock-ordering bug that only shows up under real network
conditions, which is why it survived.

### Decision
Split the map operation from the work:

1. `take_client(handle)` removes the client under the lock (O(1), microseconds).
2. The network call runs with **no** lock held.
3. `return_client(handle, client)` re-inserts under the lock.

`return_client` uses `entry(handle).or_insert(client)`: if the handle was
`aether_client_free`d while the call was in flight, the entry is gone and the
returned client is dropped, which runs exactly the teardown `free` would have
run. Re-inserting would resurrect a freed handle — worse than dropping.

`aether_client_free` removes the client and runs `down()` outside the lock too.

### Consequences
- One slow connect no longer blocks unrelated handles or the GUI thread.
- While a client is checked out, a concurrent `aether_client_free` on the same
  handle sees "invalid handle" and does nothing. The client is then dropped
  when the in-flight call returns, so no leak — but the *caller* sees a
  misleading error code in that narrow window.
- `servers` intentionally still run `request_stop`/`join` under the lock: a
  server handle is a `ServerGuard` whose stop is bounded and never re-enters
  the map, so the deadlock risk that motivated the client change is absent.
  This asymmetry is deliberate and documented at the call site.
- A per-handle lock would remove the remaining window; it is not worth a
  new dependency (or a hand-rolled `Arc<Mutex<Client>>` plumbing) until a host
  actually reports the race.

### Tests
Covered indirectly: the FFI surface is exercised by the .NET host and has no
Rust integration test for lock behaviour (the race needs a real embedding).
Upstream gate: the existing FFI compile check in CI.

---

## DEC-020: A retransmitted OPEN must not restart a live stream

**Date:** 2026-11-23
**Status:** Accepted

### Context
`accept.rs` treated every incoming `OPEN_TCP` / `OPEN_UDP` as "the peer recycled
this id": it dropped the relay worker, called `mux.close(id)` and re-dialled the
target. That is right for a genuinely recycled id, but the id and the frame
carry no evidence of recycling other than the header's `generation` — and the
accept-loop ignored it.

The peer's mux allocates a *new generation* when it reuses an id, so a
retransmitted OPEN (the ACK was lost, the client resent the same sealed frame)
arrives with the **same** generation as the incarnation already running. The
server still reset the flow, and `register_inbound` claimed the *next*
generation. From then on the two sides disagreed: the server sealed its echoes
under generation N+1 while the client's window still expected N. Every reply
failed `MuxError::StaleGeneration` on the client, the client never accumulated
the echoed bytes, and the tunnel hung until the read timeout — the
`burst_and_edge_traffic_keeps_server_alive` failure, with a duplicate OPEN on
every 10th flow.

### Decision
`MuxManager::generation(id)` exposes the live incarnation's generation, and the
accept-loop compares it with the unauthenticated header before touching any
state:

- **same generation** → retransmit: log, `continue`. The live flow, its replay
  window, its relay worker and its route are left exactly as they are.
- **different generation** (or id not open) → recycle: drop the stale worker,
  `mux.close(id)` and `register_inbound` as before, which claims the next
  generation and hands the new flow a fresh replay window.

Same rule for `OPEN_UDP`.

### Consequences
- Duplicate OPENs are now idempotent, which is what the wire format already
  claimed: OPEN is seq 0 and a duplicate is byte-identical, so it carries no
  new information.
- The generation comparison happens on an *unauthenticated* header, but that is
  safe: it only selects between "ignore" and "reset and re-dial", and the frame
  body is authenticated right after (`parse_open_*`). A forged header can at
  worst make the server ignore an OPEN (the client retries) or drop one flow.
- A reset now costs what it says it costs: only a real recycle re-dials the
  target, so retransmits no longer leak a dial or a worker thread per retry.
- Not addressed: a peer that recycles an id *without* bumping the generation
  cannot be distinguished from a retransmit. The mux allocator always bumps it
  (`claim_generation`), so this is a local invariant, not a wire assumption.

### Tests
- `server/tests/e2e_tunnel.rs::retransmitted_open_keeps_the_live_flow` — OPEN,
  payload/echo, byte-identical duplicate OPEN, payload/echo again; asserts the
  echo keeps the original generation and the target saw exactly one dial.
- `server/tests/e2e_tunnel.rs::burst_and_edge_traffic_keeps_server_alive` — the
  original soak, which is where the bug showed up.
