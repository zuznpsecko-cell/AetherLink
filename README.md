# AetherLink

VPN with userspace netstack. Single Rust core + thin FFI hosts (.NET/Android).

## Platform support

| Component | Windows | Linux | Android |
|-----------|---------|-------|---------|
| Server (`AetherLink.Server`) | ✅ runs | ✅ runs (systemd, `docs/DEPLOY_UBUNTU.md`) | — |
| Desktop client (CLI + GUI) | ✅ runs (Wintun, live-tested against a VPS) | ❌ not yet: `/dev/net/tun` open is not implemented | — |
| Android client | — | — | 🔄 core + JNI ready; Kotlin host is a skeleton, no tunnel on a device yet |

## Run (server + client)

Windows (client elevated): `.\scripts\run_server_windows.ps1`, `.\scripts\run_client_windows.ps1`

Ubuntu: `./scripts/run_server_ubuntu.sh` runs the server. The client script
`sudo ./scripts/run_client_ubuntu.sh` exists, but the client stops at `tun open`
on Linux (TUN is Windows-only for now), so use a Windows client.

The server reads its TLS key as PKCS#8 (`BEGIN PRIVATE KEY`), PKCS#1
(`BEGIN RSA PRIVATE KEY`) or SEC1 (`BEGIN EC PRIVATE KEY`). If the listener
dies, the host exits with code 1 so systemd restarts it (DEC-024).

## GUI client (Windows, Avalonia)

Tray icon + main window (status/egress IP, endpoint profiles, routing rules,
logs). Thin host like the console client: same `aetherlink_core.dll`
via FFI, no protocol code in C#. Requires admin at startup (TUN).

```powershell
.\scripts\run_gui_windows.ps1   # build + stage to dist/win-gui, then run AetherLink.Gui.exe
```

The Server tab keeps named endpoint profiles (name, address, SNI, PSK) with
Add / Duplicate / Delete. Full tunnel, MTU, DNS mode and routing rules are
shared. Selecting another profile while connected reconnects (`Down → Up`);
there is no automatic failover.

Config: `client.local.yaml` next to the exe (edited in the Server tab,
validated by the core on connect). The active profile is mirrored into the
legacy `server_addr`/`outer_sni`/`psk`, so core and CLI still read one server;
old single-server configs migrate to a `default` profile. Logs:
`logs/gui-<date>.log`. Details: `docs/WINDOWS_GUI.md`, decision DEC-013.

## Android client

**Status: Rust side ready, Kotlin host is a skeleton.** The core already plans
the Android interface, split tunneling, `VpnService.protect()`-ed connect and
TUN attach, all exported over JNI. The Kotlin app has no Activity yet, passes
handle `0` and calls the desktop path, so it does not tunnel. Target design
(PLAN_ANDROID Phase 3+): two screens, server settings + Connect and an app
picker (empty list = all apps in the tunnel, non-empty = allowlist). Thin host:
no crypto or frame parsing in Kotlin.

```powershell
.\scripts\build_android.ps1        # cargo-ndk for 3 ABIs + assembleDebug
.\scripts\check_android_build.ps1  # wrapper, ABI payload, JNI symbols
```

Requires Rust Android targets, `cargo-ndk`, Android SDK/NDK and JDK 17-23
(tested on 21). `libaetherlink_ffi.so` is staged as `libaetherlink_core.so`;
`.so` files are built, never committed. Details: `docs/ANDROID.md`,
plan: `PLAN_ANDROID.md`.

## Protocol

Frame header is 24 bytes; the wire layout is pinned by `protocol/tests/golden.rs`
and owned by `protocol/src/lib.rs`:

```text
 0  length (24-bit)      5  stream id (u16)
 3  frame type           7  sequence  (u32)
 4  flags               11  generation(u32)   <- protocol v2
                        15  reserved  (9 random bytes, ignored on read)
```

The AEAD nonce is derived, never transmitted:
`id(u16) || generation(u32) || seq(u32) || type(u8) || 0`.

The header itself is the AEAD **associated data** (`codec::header_aad`):
`length(3) || type(1) || flags(1) || id(2) || seq(4) || generation(4)`.
Editing any of those fields in flight fails authentication, so a frame cannot
be re-routed to another stream or replayed under a different incarnation. The
9 random tail bytes are excluded on purpose — they carry no meaning. Rationale:
DEC-016 (this makes v2 builds from before that commit wire-incompatible; ship
client and server together).

**Why `generation` matters:** stream ids are recycled (a session outlives the
16-bit id space), and v1 derived the nonce from `(id, seq, type)` alone while
OPEN always used `seq = 0`. Repeating a ChaCha20-Poly1305 nonce leaks the
keystream and makes tags forgeable, so v2 advances a per-id monotonic
generation on every re-incarnation. `PROTOCOL_VERSION` is `2`; a v1 peer is
refused at the preface byte rather than failing frame authentication. Client
and server must be updated together. Rationale: DEC-014 in `docs/DECISIONS.md`.

Because the generation rides in every header, the receiver can also tell a
**retransmitted OPEN** (same generation — the ACK was lost) from a **recycled
id** (new generation). Only the latter resets the flow: the former is ignored,
so a duplicate OPEN no longer restarts a live stream, its replay window or its
relay. Rationale: DEC-020 in `docs/DECISIONS.md`.

## FFI contract (for host authors)

Hosts (.NET, Kotlin) talk to `aetherlink_core` through a C ABI
(`crates/aetherlink-ffi/src/lib.rs`) and JNI (`jni.rs`). Rules (DEC-024):

- Every export is wrapped in a panic guard: a Rust panic returns
  `InternalError` (-8) with the message in `aether_last_error`, it never
  unwinds into the host.
- Return codes: `0` Success, `-1` InvalidHandle, `-2` InvalidConfig,
  `-3` AlreadyRunning, `-4` NotRunning, `-5` NetworkError, `-6` DnsError,
  `-7` AuthError, `-8` InternalError, `-9` InvalidArgument,
  `-10` PermissionDenied, `-11` StaleState (leftover state file: call
  `aether_client_force_cleanup`, retry once), `-12` Busy (another call on the
  same handle is in flight; the handle is valid, retry later).
- `aether_client_free` during an in-flight call is deferred: the handle is
  invalid at once, the running call tears the client down when it returns,
  and `free` still returns Success.
- `aether_server_is_running` returns `1` while serving and `0` once the
  listener has died (reason in `aether_last_error`); hosts poll it and exit
  non-zero.

## Known limitations

- **Desktop client is Windows-only.** The Linux TUN backend is not
  implemented (`TunInterface::open` returns an error off Windows).
- **TLS fingerprint is rustls defaults.** Phase T (golden TLS profile,
  fallback-shape tests, DEC-012) is not done. ALPN: the client offers
  `h2,http/1.1`, the server only `http/1.1` (DEC-007 amendment).

- **IPv4 only.** IPv6 targets are parsed but dropped: dial targets are built as
  `"{addr}:{port}"`, which is not a valid IPv6 literal.
- **No rekey / per-stream keys.** `generation` removes nonce reuse; it adds no
  forward secrecy or compartmentalisation (DEC-014 non-goals).
- **`kill_switch` and `restore_on_exit` are parsed but not enforced** by the
  core; the GUI hosts the YAML keys, the tunnel does not act on them.
- **Android host is not wired end-to-end** (`AetherVpnService` passes handle 0;
  `clientConnect`/`clientAttachTun` are not called from Kotlin; no Activity).
- **Egress policy is address-based, not a full allowlist.** `deny_private`
  (default on) keeps the server off loopback, LAN, link-local and cloud
  metadata; `allow`/`deny` CIDRs cover the exceptions. It does not restrict
  which public hosts a client may reach, and it does not filter
  `dns_upstream` (operator config). Rationale: DEC-021.
- **No per-IP rate limiting.** `server.max_connections` (default 512) bounds
  concurrent sockets and the TLS handshake has a 10 s deadline, but a single
  peer can still consume all slots.
- **No DNS cache on the server.** Each new stream resolves its target once, in
  its own worker; the tunnel loop never resolves (DEC-022), so a slow resolver
  costs one flow, not the session.
- **Replay window is sequence-based only.** A peer that can *delay* frames past
  the 1024-frame window is not detected (needs a rekey bound, not a bitmap).
- **Kernel tuning is the deployment's job.** The server only logs when
  `rmem_max`/`wmem_max` are below 16 MiB; `deploy/linux/install.sh` writes
  `/etc/sysctl.d/99-aetherlink.conf` (DEC-018). Running the binary without that
  file works, just slower.

## Checks

CI (`.github/workflows/ci.yml`) runs, cheapest first: `cargo fmt --all --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`
(Linux **and** Windows), `dotnet test` for the GUI suite, the contract scripts
and a `cargo audit` report. Rationale and the measured before/after: DEC-023.
All of these are green on `main` and block PRs; `cargo audit` is advisory.
Not covered by CI: the Android build (no NDK/SDK in the runner) and anything
live (TUN, a real VPS).

Locally: `cargo fmt --all`, `cargo clippy --workspace --all-targets`,
`scripts/check_thin_hosts.ps1`, `scripts/check_gui_endpoints.ps1`,
`scripts/check_quickstart.ps1`, `scripts/check_android_build.ps1`.

## Docs

| Document | What it is |
|----------|------------|
| `docs/STATUS.md` | Current state by phase, test counts, next steps |
| `docs/LIVE_ISSUES.md` | Live-run journal: open and closed problems with evidence |
| `docs/DECISIONS.md` | Architecture decisions DEC-001…DEC-024 |
| `docs/DEPLOY_UBUNTU.md` | Server on Ubuntu: certificate, systemd, troubleshooting |
| `docs/WINDOWS_GUI.md` | Windows GUI: usage, endpoint profiles, TDD log |
| `docs/ANDROID.md` | Android: build, current limitations, TDD log |
| `docs/LIVE_W4.md` | Live Windows runbook (W4) and its results |
| `PLAN_*.md` | Plans (status banner at the top of each); `PLAN_TDD.md` is historical |
