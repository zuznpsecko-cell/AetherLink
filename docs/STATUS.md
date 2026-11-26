# AetherLink v1.5 — Implementation Status

_Last Updated: 2026-11-26 (DEC-025: dead-peer, PSK floor, NonceCache, `--locked`; поверх `main` = `c477cc8`)._

## Сейчас

- **Гейты зелёные на `main`.** Каждый PR блокирующе проходит `cargo fmt --all --check`,
  `cargo clippy --workspace --all-targets -D warnings`, `cargo test --workspace` на Linux
  **и** Windows, `dotnet test` GUI, сборку .NET-хостов и контрактные скрипты (DEC-023).
  Android-job собирает `.so` под 3 ABI, гоняет Kotlin L1 (Robolectric) и собирает APK;
  `check_android_host.ps1` в контрактах. Не гейтится всё живое (TUN, VPS, устройство).
- **Живьём против VPS туннель работает** (Windows-клиент): DNS + TCP + HTTP, egress = VPS
  (`docs/LIVE_ISSUES.md`, §0). Открыт аплоад (§0m): фикс управления потоком в `main`,
  живой замер после него не делался.
- **Протокол v2** (DEC-014, DEC-016): ломающее изменение, клиент и сервер обновляются
  вместе; v1-пир получает отказ на байте preface.
- **Платформы:** сервер — Linux/Windows; десктоп-клиент — **только Windows** (Linux TUN
  не реализован); Android — Rust-часть и Kotlin-хост готовы, на устройстве не проверено (`docs/ANDROID.md`).
- Решения: DEC-001…DEC-025 в `docs/DECISIONS.md`.

## Overview

| Component | Status | Notes |
|-----------|--------|-------|
| **Phase 0: Bootstrap** | ✅ Done | Workspace, strict lints, DECISIONS/STATUS/README |
| **Phase 1: Crypto + Auth** | ✅ Done | HMAC AUTH + NonceCache, AEAD, HKDF, golden tests (33) |
| **Phase 2: Frame Protocol** | ✅ Done (v2) | 24B header + `generation` (DEC-014), len-prefix padding, random reserved tail, header authenticated as AEAD AAD (DEC-016); the unused `codec::ReplayWindow` was deleted — the only replay window lives in `mux::manager::open` (DEC-017) |
| **Phase 3: Mux Layer** | ✅ Done | TCP streams + UDP flows, per-incarnation generation + anti-replay, virtual DNS, OPEN frames (6+8, +8 nonce tests) |
| **Phase 4: Golden spec** | ✅ Done | `protocol/` canonical consts, `build_nonce`, pinned v2 header bytes + nonce layout (5+8); AAD layout pinned in `frame/tests/header_auth.rs` |
| **Phase 5: TLS Transport** | ✅ Done | rustls TLS1.3-only, sync I/O; ALPN: client `h2,http/1.1`, server `http/1.1` only (DEC-007 amendment); server keys PKCS#8/PKCS#1/SEC1 (DEC-024) |
| **Phase A: Session handshake** | ✅ Done | PREFACE+AUTH → keys → mux DATA both ways (4) |
| **Phase 6: Server Core** | ✅ Done | Fallback/AUTH/relay/dial/resolve + accept-loop + bind/serve; resilience (DEC-015), egress policy (DEC-021), accept loop survives `accept()` errors (DEC-024) |
| **Phase 7: Netstack** | 🔄 Partial | Snapshot/rollback + IP pump + socket pump + wintun + TunPackets/DataPump + pump threads; Windows: transport attached, live traffic through the tunnel proven. **Linux TUN (`/dev/net/tun`) not implemented** — `TunInterface::open` returns an error off Windows |
| **Phase T: TLS fidelity** | ⏳ Next | DEC-012 accepted; golden profile + fallback-shape tests pending (see PLAN_FINAL_TDD.md) |
| **Phase 8: Full Tunnel + Routing** | ✅ Done | Ruleset/DNS-policy/cleanup + full `up` over fake platform (8+11) |
| **Phase 9: FFI API** | ✅ Done | C ABI + JNI (13 functions); panic-safe exports, `Busy` slots + deferred `free`, `aether_server_is_running` (DEC-019, DEC-024) |
| **Phase 10: Client Integration** | ✅ Done | Typed config, lifecycle, status JSON |
| **Phase 11: Testing + Docs** | 🔄 Partial | PLAN_FINAL_TDD.md is the live plan; DoD checklist below |
| **Phase 12: Windows Wintun** | ✅ Done | Version pinned, host load path + deploy note; session bring-up and live up/down proven (LIVE_W4, live tunnel vs VPS) |
| **Phase 13: .NET Hosts** | ✅ Done | Server/Client build 0/0, thin (grep-enforced), status cmd, quickstart scripts |
| **Phase 14: Android** | 🔄 Partial | Rust side + Kotlin host done: Activity, app picker, foreground VpnService, `clientConnect` with `VpnService.protect()` → `establish()` → `clientAttachTun`, pump health polling; CI builds the APK and runs L1. Not yet run on a device (L2) |
| **Phase 15: Deploy Scripts** | ✅ Done | install/uninstall from dist + example configs + checks |
| **Phase 16: Final Integration** | 🔄 Partial | E2E over localhost green; live tunnel vs VPS on Windows proven; full live runbook (I6) pending |
| **Phase 17: GUI endpoint profiles** | ✅ Done (code) | `client.endpoints` + mirror, 49/49 .NET tests, `check_gui_endpoints.ps1`; live switching matrix pending admin/VPS |
| **Phase I: Assembly (VPN works)** | 🔄 Mostly done | OPEN frames, bind/serve loop, client `up` tail, FFI threads, E2E over localhost (I1–I5, I7) done; live tunnel vs VPS proven; full live checklist I6 (kill -9, DNS no-leak capture, domain-direct) pending |

## Detailed Status

### Phase 0: Bootstrap
- [x] Cargo workspace structure created
- [x] Root `Cargo.toml` with workspace config
- [x] Individual crate `Cargo.toml` files
- [x] `protocol/` crate with golden test harness
- [x] `DECISIONS.md` (DEC-001..DEC-024)
- [x] `STATUS.md` (this file)
- [x] Basic `README.md`

### Phase 23: FFI boundary & accept-loop hardening (DEC-024)

- [x] Accept loop classifies `accept()` errors: per-peer → retry, resource exhaustion → backoff 10 ms…1 s, broken listener → stop with reason
- [x] `ServerGuard::is_running/failure` + `aether_server_is_running`; .NET server host exits 1 when the listener dies (systemd restarts it)
- [x] Server TLS keys passed typed: PKCS#1 and SEC1 accepted (were relabelled as PKCS#8 and rejected)
- [x] FFI handle table keeps a `Busy` slot during a call; `free` racing a call is deferred, never resurrects the handle; new code `Busy = -12`
- [x] Every C ABI / JNI export in `catch_unwind` (panic → `InternalError` + `last_error`); poison-tolerant mutexes; invalid UTF-8 arguments are errors
- [x] Tests: `server/tests/accept_errors.rs` (12), `bind_serve.rs` (+2: SEC1 key served over TLS, PEM helper), unit tests in `ffi/src/handles.rs` (6) and `ffi/src/lib.rs` (6); CI green
- [x] ~~Still open: PKCS#1 test; GUI/Kotlin do not handle `Busy`~~ — closed: PKCS#1 fixture test (DEC-025), Kotlin handles `Busy` upstream, .NET via `dotnet/Shared/CoreRecovery.cs` (DEC-025)

### Phase 24: Review follow-ups (DEC-025)

- [x] Cargo.lock reconciled with the manifests; every cargo step in CI runs `--locked`
- [x] Dead-peer detection: server echoes PING, client interval from `keepalive_s`, "keepalive timeout" after 3 silent intervals (only once the server has echoed)
- [x] .NET hosts: shared Busy/StaleState policy (GUI retries Busy; CLI `up` recovers from StaleState)
- [x] PSK minimum 16 bytes at config parse (client + server)
- [x] `NonceCache`: O(1) `HashSet` + ordered queue, poison-tolerant lock
- [x] PKCS#1 RSA key regression test (committed throwaway fixture)
- [x] CI green on PR #22 (fmt, clippy, Rust tests Linux+Windows, .NET GUI suite, Android .so/clippy/Kotlin L1, contracts); live dead-peer check on a VPS still pending

### Phase 22: CI gates (DEC-023)

- [x] **Every gate measured before being made blocking** (probe workflow, then removed)
- [x] `cargo fmt --all --check` — was 38 hunks / 18 files, fixed by a formatting-only commit
- [x] `cargo clippy --workspace --all-targets -- -D warnings` — was already clean (0 warnings)
- [x] `cargo test --workspace` now runs **on Windows too** (was `--no-run`: compile only)
- [x] `dotnet test` for the GUI suite in CI (49 passed) — never ran before
- [x] Contract scripts (`check_thin_hosts`, `check_gui_endpoints`, `check_quickstart`)
- [x] `cargo audit` — advisory (loud), blocking once the report is clean
- [x] Android gate: `.so` for 3 ABIs (runner NDK), clippy for the Android target, Kotlin L1, APK artifact; `check_android_host.ps1`

### Phase 21: Egress control & loop hygiene (DEC-021..DEC-022)

- [x] **Egress policy on resolved addresses** (`server::egress`): `deny_private` default on blocks loopback/RFC1918/link-local/CGNAT/ULA/metadata, v4 **and** v6, plus `allow`/`deny` CIDRs
- [x] Policy applied after resolution (TCP `dial_tcp`, UDP `relay_udp`), never on the name
- [x] **`routes` stores `(String, u16)`**; `getaddrinfo` no longer runs on the tunnel event-loop
- [x] Resolution moved entirely into the stream worker / relay pool
- [x] Tests: `server/tests/egress_policy.rs`, `egress_tests.rs`, `accept_loop::unresolvable_target_does_not_stall_the_session`
- [x] Gates green in CI (were not run when this phase was written)
- [ ] Still open: per-IP rate limiting; DNS cache; IPv6 dial targets (still IPv4-only)

### Phase 20: Transport authenticity & host hygiene (DEC-016..DEC-020)

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
- [x] **FFI handle lock not held across network I/O** (DEC-019; take/return mechanics replaced by `Busy` slots in DEC-024)
- [x] Tests: `frame/tests/header_auth.rs` (5), `mux/tests/replay_window.rs` (8), `mux/tests/nonce_generation.rs` (8)
- [x] **Retransmitted OPEN is idempotent** (`MuxManager::generation` gate in `accept.rs`): a duplicate OPEN no longer resets the live flow, its replay window or its relay (DEC-020)
- [x] Gates green in CI (were not run when this phase was written)
- [ ] Still open: per-IP rate limiting; delayed-frame attack past the replay window (the free-vs-call window is closed by DEC-024)

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
- [x] Gates green in CI (were not run when this phase was written)
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
- [x] Gates green in CI (`cargo fmt --check`, `clippy -D warnings`, `cargo test --workspace`)
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

### Tests per crate

Static count of `#[test]` functions (unit + integration, including
platform-gated ones), 2026-11-25. All crates compile and their suites are
green in CI on Linux and Windows; exact per-run totals live in the CI logs.

| Crate | `#[test]` |
|-------|----------:|
| aetherlink-protocol | 13 |
| aetherlink-crypto | 33 |
| aetherlink-frame | 24 |
| aetherlink-mux | 32 |
| aetherlink-netstack | 35 |
| aetherlink-core | 17 |
| aetherlink-server | 102 |
| aetherlink-client | 115 |
| aetherlink-ffi | 38 |
| **Total** | **409** |

.NET GUI suite: 49 tests (`dotnet test`, DEC-023).

## DoD Checklist (from AGENT_INSTRUCTIONS.md)

| Item | Description | Status |
|------|-------------|--------|
| 1 | Single Rust core; no protocol stack in C#/Kotlin | ✅ (`check_thin_hosts.ps1`) |
| 2 | FFI up/down/server works | ✅ (C ABI/JNI tested; Windows client and server used live via FFI) |
| 3 | TCP+UDP through tunnel (netstack) | 🔄 (live DNS+TCP+HTTP vs VPS on Windows; upload speed open, §0m) |
| 4 | DNS when up only through tunnel (no leak test) | 🔄 (policy green; live capture pending privs) |
| 5 | Domain direct: resolve via tunnel, connect direct | 🔄 (engine green; live pending privs) |
| 6 | Wintun path Windows (like v2rayN) | ✅ (wintun 0.5.1; live session and traffic vs VPS proven) |
| 7 | Linux TUN full tunnel + rollback | ❌ (route/DNS planner exists; `/dev/net/tun` open not implemented) |
| 8 | .NET hosts self-contained win/linux | ✅ (both build 0/0) |
| 9 | Android+TV split default all | 🔄 (core + host: all/allow from the picker; device check pending) |
| 10 | G2 static fallback | ✅ (decision + accept-loop tested) |
| 11 | force_cleanup restores network+DNS | 🔄 (idempotent core green; live pending privs) |
| 12 | DEPLOY_LINUX/WINDOWS (personal, from scratch) | ✅ (install/uninstall + checks green) |

## Known Issues / Blockers

> Рабочий журнал живых прогонов: [docs/LIVE_ISSUES.md](LIVE_ISSUES.md) — открытые и закрытые проблемы с доказательствами.

1. **Live TUN tests** — need Linux root/CAP_NET_ADMIN or Windows admin
   (run manually per PLAN_FINAL_TDD.md D5/G3)
2. **Android not proven on a device** — host is wired end to end and CI-built,
   but the live tunnel (L2) needs a phone/emulator and a server
   (`docs/ANDROID.md` «Проверка на устройстве»)
3. **Linux desktop client** — TUN open not implemented; the client runs on Windows only
4. **Gradle JVM** — must run under Java 21 (Rider JBR); Gradle 8.10 refuses
   Java 25 from the new Studio bundle
5. **Windows GUI endpoint acceptance** — 49/49 unit tests and gates green, but
   live `Down → Up` switching, stale-state restore after kill, and PSK-free
   logs were not exercised on real servers; requires admin + VPS credentials
   (`docs/WINDOWS_GUI.md` §Ручная приёмка)

## Next Steps

1. Живой замер аплоада после фикса управления потоком (§0m в `docs/LIVE_ISSUES.md`).
2. Android: проверка на устройстве (L2, `docs/ANDROID.md` «Проверка на устройстве»);
   затем автопереподключение при смене сети.
3. Phase I6: полный live E2E чек-лист (kill -9, DNS no-leak захватом, domain-direct;
   `docs/LIVE_W4.md`).
4. ~~Dead-peer детекция~~ — сделано (DEC-025); остаётся живая проверка обрыва на VPS.
5. Linux TUN для десктоп-клиента.
6. Phase T: TLS-fidelity hardening (DEC-012).
