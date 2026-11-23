# AetherLink v1.5 — Implementation Status

_Last Updated: 2026-11-23 (Protocol v2 `generation` (DEC-014) + server resilience (DEC-015) + header authentication (DEC-016), typed replay (DEC-017), library/deploy split (DEC-018), FFI lock (DEC-019); gates NOT run yet. Previous baseline: GUI endpoint profiles 49/49 .NET tests; Rust TDD 230/230, TUNNEL WORKS live vs VPS: DNS+TCP+HTTP proven, egress=VPS; perf frontier: speedtest 235ms/20Mbps/0up — see docs/LIVE_ISSUES.md)_

> **0l (upload 0.00): фикс в дереве, гейты НЕ прогонялись.** Причины и список правок — в
> [docs/LIVE_ISSUES.md](LIVE_ISSUES.md#0l-аплоад-000-байты-терялись-молча-fin-убивал-ответ-id-кончались-в-дереве-гейты-не-прогонялись).
> В рабочей песочнице нет Rust toolchain, поэтому `cargo fmt --check` / `clippy -D warnings` /
> `cargo test --workspace` и живой замер спидтеста нужно выполнить локально.

> ⚠️ **Протокол v2 (DEC-014) — ломающее изменение, гейты НЕ прогонялись.** Заголовок кадра
> несёт `generation: u32` (offset 11..15), nonce = `id || generation || seq || type || 0`.
> Закрывает повтор AEAD nonce при переиспользовании stream id (в v1 неизбежный после
> 32 768 выдач id, начиная с `(id, 0, OpenTcp)`). `PROTOCOL_VERSION = 2`: v1-пир получает
> отказ на байе preface. Клиент и сервер нужно обновлять вместе.

## Overview

| Component | Status | Notes |
|-----------|--------|-------|
| **Phase 0: Bootstrap** | ✅ Done | Workspace, strict lints, DECISIONS/STATUS/README |
| **Phase 1: Crypto + Auth** | ✅ Done | HMAC AUTH + NonceCache, AEAD, HKDF, golden tests (33) |
| **Phase 2: Frame Protocol** | ✅ Done (v2) | 24B header + `generation` (DEC-014), len-prefix padding, random reserved tail, header authenticated as AEAD AAD (DEC-016); the unused `codec::ReplayWindow` was deleted — the only replay window lives in `mux::manager::open` (DEC-017) |
| **Phase 3: Mux Layer** | ✅ Done | TCP streams + UDP flows, per-incarnation generation + anti-replay, virtual DNS, OPEN frames (6+8, +8 nonce tests) |
| **Phase 4: Golden spec** | ✅ Done | `protocol/` canonical consts, `build_nonce`, pinned v2 header bytes + nonce layout (5+8); AAD layout pinned in `frame/tests/header_auth.rs` |
| **Phase 5: TLS Transport** | ✅ Done | rustls TLS1.3-only, ALPN h2, sync I/O (3) |
| **Phase A: Session handshake** | ✅ Done | PREFACE+AUTH → keys → mux DATA both ways (4) |
| **Phase 6: Server Core** | ✅ Done | Fallback/AUTH/relay/dial/resolve + accept-loop + bind/serve (8+4+4+1); resilience hardening in DEC-015 |
| **Phase 7: Netstack** | 🔄 Partial | Snapshot/rollback + IP pump + socket pump + wintun open + TunPackets/DataPump + pump threads tested; Windows up/down live cycle green (LIVE_W4); traffic through tunnel pending transport attach |
| **Phase T: TLS fidelity** | ⏳ Next | DEC-012 accepted; golden profile + fallback-shape tests pending (see PLAN_FINAL_TDD.md) |
| **Phase 8: Full Tunnel + Routing** | ✅ Done | Ruleset/DNS-policy/cleanup + full `up` over fake platform (8+11) |
| **Phase 9: FFI API** | ✅ Done | C ABI smoke + rules/log-cb/android-fd + JNI symbols (5+5) |
| **Phase 10: Client Integration** | ✅ Done | Typed config, lifecycle, status JSON |
| **Phase 11: Testing + Docs** | 🔄 Partial | PLAN_FINAL_TDD.md is the live plan; DoD checklist below |
| **Phase 12: Windows Wintun** | 🔄 Partial | Version pinned, host load path + deploy note; session bring-up pending privs |
| **Phase 13: .NET Hosts** | ✅ Done | Server/Client build 0/0, thin (grep-enforced), status cmd, quickstart scripts |
| **Phase 14: Android** | ✅ Done (build) | minSdk 26, APK assembles with 3 ABIs + JNI; on-device test pending |
| **Phase 15: Deploy Scripts** | ✅ Done | install/uninstall from dist + example configs + checks |
| **Phase 16: Final Integration** | 🔄 Partial | E2E over localhost green; live runbook pending privs |
| **Phase 17: GUI endpoint profiles** | ✅ Done (code) | `client.endpoints` + mirror, 49/49 .NET tests, `check_gui_endpoints.ps1`; live switching matrix pending admin/VPS |
| **Phase I: Assembly (VPN works)** | ⏳ Next | OPEN frames → bind/serve loop → client up tail → FFI threads → live E2E (see PLAN_FINAL_TDD.md) |

## Detailed Status

### Phase 0: Bootstrap
- [x] Cargo workspace structure created
- [x] Root `Cargo.toml` with workspace config
- [x] Individual crate `Cargo.toml` files
- [x] `protocol/` crate with golden test harness
- [x] `DECISIONS.md` (DEC-001..DEC-019)
- [x] `STATUS.md` (this file)
- [x] Basic `README.md`

### Phase 20: Transport authenticity & host hygiene (DEC-016..DEC-019)

- [x] **Header is AEAD associated data** (`codec::header_aad`, 15 B: length/type/flags/stream_id/sequence/generation)
- [x] `stream_id` can no longer be rewritten in flight (cross-flow injection closed)
- [x] `generation` is authenticated, so a peer cannot steer the nonce position
- [x] `encode_frame` builds the header before encrypting (length is committed)
- [x] Random tail deliberately **not** authenticated (no meaning, rewrites per frame)
- [x] `codec::ReplayWindow` deleted (was never constructed; its 3 tests were false assurance)
- [x] `MuxError::ReplayDetected` / `MuxError::StaleGeneration` replace `Internal("replay seq")`
- [x] Replay window semantics documented: `seen` = duplicates, distance = too old, anchor moves for accepted out-of-order frames
- [x] Client: rejected DATAGRAM is logged and the flow kept (UDP is lossy; was a propagated error)
- [x] **`ensure_linux_wan_tuning` → `warn_if_wan_tuning_missing`**: the library no longer writes `/proc/sys`
- [x] **FFI `HANDLES` lock not held across network I/O** (`take_client` / `return_client`)
- [x] Tests: `frame/tests/header_auth.rs` (5), `mux/tests/replay_window.rs` (6)
- [ ] **Gates not run** — no Rust toolchain in the sandbox
- [ ] Still open: per-IP rate limiting; FFI per-handle lock (narrow free-vs-call window); delayed-frame attack past the replay window

### Phase 19: Server resilience (DEC-015)

- [x] `panic = "unwind"` in `[profile.release]` — the `catch_unwind` guards are live again
- [x] Panic in a connection handler is logged, socket dropped, process survives
- [x] AUTH frame body fixed at `AUTH_FRAME_LEN` (64 B), checked **before** allocating
- [x] `MAX_WIRE_BODY` bound for authenticated frame bodies (replaces the `65535 + 1024` literal)
- [x] `server.max_connections` (default 512, zero clamped to 1) + RAII `ConnectionSlot`
- [x] Accept loop sheds over-cap sockets instead of spawning a thread
- [x] `tls::accept_tls_with_timeout` (10 s) for slowloris; timeouts cleared afterwards
- [x] `server.max_streams` finally applied (`MuxManager::set_max`)
- [x] `RelayPool`: no `active` underflow on fast workers, panicked jobs refund their slot
- [x] Tests: `tests/resilience.rs` (6), `relay_pool.rs` (+2), `session_handshake.rs` (+2), `config_schema.rs` (+1)
- [ ] **Gates not run** — no Rust toolchain in the sandbox
- [ ] Still open: per-IP rate limiting, TLS-handshake-completion accounting

### Phase 18: Protocol v2 — AEAD nonce uniqueness (DEC-014)

- [x] `FrameHeader.generation: u32` at offset 11 (inside v1's reserved bytes; frames do not grow)
- [x] Reserved tail (9 B) now fresh random per frame instead of constant zeros
- [x] Nonce layout owned by `aetherlink_protocol::build_nonce`; mux no longer defines its own
- [x] `MuxManager.last_generation` tombstone + `claim_generation`: monotonic per `(id, direction)`
- [x] Generation gate in `open` (stale/future incarnation refused before decryption)
- [x] `MuxError::NonceSpaceExhausted` instead of wrapping into a repeated nonce
- [x] `PROTOCOL_VERSION = 2`; v1 peers refused at the preface byte
- [x] Guards: `protocol_version_matches_crypto_copy`, pinned v2 header bytes + nonce layout
- [x] Tests: `crates/aetherlink-mux/tests/nonce_generation.rs` (8), codec (3), golden (1)
- [ ] **Gates not run** (`cargo fmt --check`, `clippy -D warnings`, `cargo test --workspace`) — no toolchain in the sandbox
- [ ] Live re-test against the VPS after both sides are rebuilt

### Phase 17: Windows GUI endpoint profiles

- [x] `EndpointProfile`/`EndpointRules`/`EndpointBook` (validation, unique names, last profile protected)
- [x] `ConfigService` load/save/migration + legacy mirror (`client.endpoints`, `client.active_endpoint`)
- [x] `ITunnelController` seam + `EndpointSwitcher` (Down → config → Up, cancel and failure paths)
- [x] `MainViewModel`: selection, Add/Duplicate/Delete, persistence, Connect on selected profile
- [x] Server tab: list + editor, shared full tunnel / routing settings
- [x] Core characterization: `client.endpoints` ignored, mirror is authoritative
- [x] Gates: `check_gui_endpoints.ps1`, GUI crypto guard in `check_thin_hosts.ps1`
- [x] Docs: `docs/WINDOWS_GUI.md` (usage, YAML, limitations, TDD log), DEC-013
- [ ] Live acceptance matrix (`PLAN_ENDPOINTS_WINDOWS.md` §5): needs admin + real VPS/PSK

### Crate Compilation Status
| Crate | Compiles | Tests Pass |
|-------|----------|------------|
| aetherlink-crypto | ✅ | ✅ 33 |
| aetherlink-frame | ✅ | ✅ 19 |
| aetherlink-mux | ✅ | ✅ 6 + 8 |
| aetherlink-netstack | ✅ | ✅ 1 + 11 + 6 + 4 |
| aetherlink-core | ✅ | ✅ 3 + 4 + 4 |
| aetherlink-server | ✅ | ✅ 4 + 5 + 1 + 1 + 8 + 4 |
| aetherlink-client | ✅ | ✅ 8 + 1 + 3 + 6 + 4 + 2 + 13 + 10 |
| aetherlink-ffi | ✅ | ✅ 3 + 5 + 5 (+cdylib) |
| aetherlink-protocol | ✅ | ✅ 6 + 5 |

## DoD Checklist (from AGENT_INSTRUCTIONS.md)

| Item | Description | Status |
|------|-------------|--------|
| 1 | Single Rust core; no protocol stack in C#/Kotlin | ✅ (`check_thin_hosts.ps1`) |
| 2 | FFI up/down/server works | 🔄 (contract smoke green; live wiring needs privs) |
| 3 | TCP+UDP through tunnel (netstack) | 🔄 (mux+pump green; socket pump + live need privs) |
| 4 | DNS when up only through tunnel (no leak test) | 🔄 (policy green; live capture pending privs) |
| 5 | Domain direct: resolve via tunnel, connect direct | 🔄 (engine green; live pending privs) |
| 6 | Wintun path Windows (like v2rayN) | 🔄 (crate 0.5.1 open path green; live session pending privs) |
| 7 | Linux TUN full tunnel + rollback | 🔄 (planner green; live pending privs) |
| 8 | .NET hosts self-contained win/linux | ✅ (both build 0/0) |
| 9 | Android+TV split default all | 🔄 (APK builds; on-device pending) |
| 10 | G2 static fallback | ✅ (decision + accept-loop tested) |
| 11 | force_cleanup restores network+DNS | 🔄 (idempotent core green; live pending privs) |
| 12 | DEPLOY_LINUX/WINDOWS (personal, from scratch) | ✅ (install/uninstall + checks green) |

## Known Issues / Blockers

> Рабочий журнал живых прогонов: [docs/LIVE_ISSUES.md](LIVE_ISSUES.md) — открытые и закрытые проблемы с доказательствами.

1. **Live TUN tests** — need Linux root/CAP_NET_ADMIN or Windows admin
   (run manually per PLAN_FINAL_TDD.md D5/G3)
2. **On-device Android test** — APK assembles; needs phone/TV for VpnService run
3. **Gradle JVM** — must run under Java 21 (Rider JBR); Gradle 8.10 refuses
   Java 25 from the new Studio bundle
4. **Windows GUI endpoint acceptance** — 49/49 unit tests and gates green, but
   live `Down → Up` switching, stale-state restore after kill, and PSK-free
   logs were not exercised on real servers; requires admin + VPS credentials
   (`docs/WINDOWS_GUI.md` §Ручная приёмка)

## Next Steps

1. Live traffic proof: сквозной HTTP через туннель против VPS (DNS уже ходит в обе стороны; текущий фронт — задержки серийного event-loop сервера).
2. Streaming relay (полный дуплекс TCP вместо запрос-ответ) — после пруфа.
3. Phase T: TLS-fidelity hardening (DEC-012) — после рабочего трафика.
4. Phase I6: полный live E2E чек-лист (kill -9, DNS no-leak, domain-direct).
