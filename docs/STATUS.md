# AetherLink v1.5 — Implementation Status

_Last Updated: 2026-09-18 (TDD green, fmt/clippy/checks clean)_

## Overview

| Component | Status | Notes |
|-----------|--------|-------|
| **Phase 0: Bootstrap** | ✅ Done | Workspace, strict lints, DECISIONS/STATUS/README |
| **Phase 1: Crypto + Auth** | ✅ Done | HMAC AUTH + NonceCache, AEAD, HKDF, golden tests (33) |
| **Phase 2: Frame Protocol** | ✅ Done | 24B header, len-prefix padding, ReplayWindow ≥1024 (19) |
| **Phase 3: Mux Layer** | ✅ Done | TCP streams + UDP flows, anti-replay, virtual DNS (8) |
| **Phase 4: Golden spec** | ✅ Done | `protocol/` canonical consts + integration vectors (5+6) |
| **Phase 5: TLS Transport** | ✅ Done | rustls TLS1.3-only, ALPN h2, sync I/O (3) |
| **Phase A: Session handshake** | ✅ Done | PREFACE+AUTH → keys → mux DATA both ways (4) |
| **Phase 6: Server Core** | ✅ Done | Fallback/AUTH/relay/dial/resolve + accept-loop (8+4+4) |
| **Phase 7: Netstack** | 🔄 Partial | Snapshot/rollback + IP pump tested; device ioctls + socket pump pending (needs privs) |
| **Phase 8: Full Tunnel + Routing** | ✅ Done | Ruleset/DNS-policy/cleanup + full `up` over fake platform (8+11) |
| **Phase 9: FFI API** | ✅ Done | C ABI smoke + rules/log-cb/android-fd + JNI symbols (5+5) |
| **Phase 10: Client Integration** | ✅ Done | Typed config, lifecycle, status JSON |
| **Phase 11: Testing + Docs** | 🔄 Partial | PLAN_FINAL_TDD.md is the live plan; DoD checklist below |
| **Phase 12: Windows Wintun** | 🔄 Partial | Version pinned, host load path + deploy note; session bring-up pending privs |
| **Phase 13: .NET Hosts** | ✅ Done | Server/Client build 0/0, thin (grep-enforced), status cmd, quickstart scripts |
| **Phase 14: Android** | ✅ Done (build) | minSdk 26, APK assembles with 3 ABIs + JNI; on-device test pending |
| **Phase 15: Deploy Scripts** | ✅ Done | install/uninstall from dist + example configs + checks |
| **Phase 16: Final Integration** | 🔄 Partial | E2E over localhost green; live runbook pending privs |

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
| aetherlink-mux | ✅ | ✅ 8 |
| aetherlink-netstack | ✅ | ✅ 5 + 6 |
| aetherlink-core | ✅ | ✅ 3 + 4 + 4 |
| aetherlink-server | ✅ | ✅ 8 + 4 + 4 + 1 |
| aetherlink-client | ✅ | ✅ 8 + 11 + 1 |
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
| 6 | Wintun path Windows (like v2rayN) | 🔄 (pinned + staged; session pending privs) |
| 7 | Linux TUN full tunnel + rollback | 🔄 (planner green; live pending privs) |
| 8 | .NET hosts self-contained win/linux | ✅ (both build 0/0) |
| 9 | Android+TV split default all | 🔄 (APK builds; on-device pending) |
| 10 | G2 static fallback | ✅ (decision + accept-loop tested) |
| 11 | force_cleanup restores network+DNS | 🔄 (idempotent core green; live pending privs) |
| 12 | DEPLOY_LINUX/WINDOWS (personal, from scratch) | ✅ (install/uninstall + checks green) |

## Known Issues / Blockers

1. **Live TUN tests** — need Linux root/CAP_NET_ADMIN or Windows admin
   (run manually per PLAN_FINAL_TDD.md D5/G3)
2. **On-device Android test** — APK assembles; needs phone/TV for VpnService run
3. **Gradle JVM** — must run under Java 21 (Rider JBR); Gradle 8.10 refuses
   Java 25 from the new Studio bundle

## Next Steps

1. Live run under privileges (PLAN_FINAL_TDD.md D5/G3 checklist)
2. On-device Android VpnService run
3. Socket state machines on top of the tested packet pump
