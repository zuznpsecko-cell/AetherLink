# AetherLink v1.5 — Implementation Status

_Last Updated: 2026-10-19 (TDD 254/254 green; TUNNEL WORKS live vs VPS: DNS+TCP+HTTP, egress=VPS; speedtest 288 down / 39.94 up / 93 ms — аплоад-фикс подтверждён живьём; заглушка + adblock задеплоены и проверены — see docs/LIVE_ISSUES.md)_

> **0l/0m (аплоад): подтверждено live 2026-10-19 — speedtest 288 down / 39.94 up / 93 ms (было 0.00).**
> Гейты прогнаны локально (fmt/clippy/tests — 254/254), редеплой VPS выполнен. Подробности и
> оставшийся HOL-хвост — [docs/LIVE_ISSUES.md](LIVE_ISSUES.md).

## Overview

| Component | Status | Notes |
|-----------|--------|-------|
| **Phase 0: Bootstrap** | ✅ Done | Workspace, strict lints, DECISIONS/STATUS/README |
| **Phase 1: Crypto + Auth** | ✅ Done | HMAC AUTH + NonceCache, AEAD, HKDF, golden tests (33) |
| **Phase 2: Frame Protocol** | ✅ Done | 24B header, len-prefix padding, ReplayWindow ≥1024 (19) |
| **Phase 3: Mux Layer** | ✅ Done | TCP streams + UDP flows, anti-replay, virtual DNS, OPEN frames (6+8) |
| **Phase 4: Golden spec** | ✅ Done | `protocol/` canonical consts + integration vectors (5+6) |
| **Phase 5: TLS Transport** | ✅ Done | rustls TLS1.3-only, ALPN http/1.1-only (server), sync I/O (4) |
| **Phase A: Session handshake** | ✅ Done | PREFACE+AUTH → keys → mux DATA both ways (4) |
| **Phase 6: Server Core** | ✅ Done | Fallback/AUTH/relay/dial/resolve + accept-loop + bind/serve (8+4+4+1) |
| **Phase 7: Netstack** | ✅ Done | Pump работает живьём: bulk TCP+UDP через TUN→wire, upload flow-control (0m), speedtest 288/39.94 (LIVE_ISSUES) |
| **Phase T: TLS fidelity** | 🔄 Partial | ALPN fallback-shape сделан (http/1.1-only, 668aaa5); golden profile — по PLAN_FINAL_TDD.md |
| **Phase 8: Full Tunnel + Routing** | ✅ Done | Ruleset/DNS-policy/cleanup + full `up` over fake platform (8+11) |
| **Phase 9: FFI API** | ✅ Done | C ABI smoke + rules/log-cb/android-fd + JNI symbols (5+5) |
| **Phase 10: Client Integration** | ✅ Done | Typed config, lifecycle, status JSON |
| **Phase 11: Testing + Docs** | 🔄 Partial | PLAN_FINAL_TDD.md is the live plan; гейты 254/254; DoD checklist below |
| **Phase 12: Windows Wintun** | ✅ Done | Version pinned; live: GUI bring-up/teardown, маршруты, DNS, auto-recovery (ежедневные прогоны) |
| **Phase 13: .NET Hosts** | ✅ Done | Server/Client build 0/0, thin (grep-enforced), status cmd, quickstart scripts |
| **Phase 14: Android** | ✅ Done (build) | minSdk 26, APK assembles with 3 ABIs + JNI; on-device test pending |
| **Phase 15: Deploy Scripts** | ✅ Done | install/uninstall from dist + example configs + checks |
| **Phase 16: Final Integration** | ✅ Done | Live E2E vs VPS green (DNS+TCP+HTTP+adblock+fallback); runbook = DEPLOY_UBUNTU.md |
| **Phase I: Assembly (VPN works)** | ✅ Done | VPN работает живьём против VPS: egress=VPS, speedtest 288/39.94/93ms |

## Detailed Status

### Phase 0: Bootstrap
- [x] Cargo workspace structure created
- [x] Root `Cargo.toml` with workspace config
- [x] Individual crate `Cargo.toml` files
- [x] `protocol/` crate with golden test harness
- [x] `DECISIONS.md` (DEC-001..DEC-011)
- [x] `STATUS.md` (this file)
- [x] Basic `README.md`

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
| 2 | FFI up/down/server works | ✅ (live: GUI+CLI против VPS ежедневно) |
| 3 | TCP+UDP through tunnel (netstack) | ✅ (live: speedtest 288 down / 39.94 up / 93 ms) |
| 4 | DNS when up only through tunnel (no leak test) | ✅ (live: DNS туннеля 10.255.0.1:53, блоклист-проба PASS) |
| 5 | Domain direct: resolve via tunnel, connect direct | ✅ (round-trip конфигурации правил протестирован реальным ConfigService) |
| 6 | Wintun path Windows (like v2rayN) | ✅ (live: GUI bring-up/teardown/auto-recovery) |
| 7 | Linux TUN full tunnel + rollback | 🔄 (сервер на VPS live; Linux-клиент TUN не прогонялся) |
| 8 | .NET hosts self-contained win/linux | ✅ (both build 0/0) |
| 9 | Android+TV split default all | 🔄 (APK builds; on-device pending) |
| 10 | G2 static fallback | ✅ (decision + accept-loop tested) |
| 11 | force_cleanup restores network+DNS | ✅ (кнопка «Restore network» live-tested) |
| 12 | DEPLOY_LINUX/WINDOWS (personal, from scratch) | ✅ (install/uninstall + checks green) |

## Known Issues / Blockers

> Рабочий журнал живых прогонов: [docs/LIVE_ISSUES.md](LIVE_ISSUES.md) — открытые и закрытые проблемы с доказательствами.

1. **On-device Android test** — APK assembles; needs phone/TV for VpnService run
2. **Gradle JVM** — must run under Java 21 (Rider JBR); Gradle 8.10 refuses
   Java 25 from the new Studio bundle
3. **Консольные окна (cmd/netsh) при Connect/Disconnect** — попытка скрыть их через
   CREATE_NO_WINDOW / DETACHED_PROCESS ломала туннель («Tunnel lost»); оба фикс-коммита
   откачены, main = `9c008e8` (DLL в dist = `94E7F26C…`). Пути решения — LIVE_ISSUES.md.
4. **Upload HOL** — блокирующая запись в сокет может подтормаживать соседние потоки
   при полной закачке (остаток 0m, отдельная задача).
5. **YouTube-реклама не блокируется DNS уровнем** — отдаётся с тех же доменов, что и
   сами видео (фундаментальное ограничение; пользователь принял).

## Next Steps

1. Скрыть консольные окна без поломки туннеля (SW_HIDE через собственный CreateProcess
   без флагов создания, либо `cmd /c start /min`; иначе оставить как есть) — LIVE_ISSUES.md.
2. Upload HOL: неблокирующая запись/очереди в релее (остаток 0m).
3. Phase T: golden TLS-fidelity profile (DEC-012).
4. Android: on-device VpnService прогон.
5. Phase I6: полный live E2E чек-лист (большая часть уже покрыта ежедневными GUI-прогонами).
