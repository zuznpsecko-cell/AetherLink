# AetherLink

VPN with userspace netstack. Single Rust core + thin FFI hosts (.NET/Android).

## Run (server + client)

Windows (client elevated): `.\scripts\run_server_windows.ps1`, `.\scripts\run_client_windows.ps1`
Ubuntu: `./scripts/run_server_ubuntu.sh`, `sudo ./scripts/run_client_ubuntu.sh`

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

Two screens: server settings + Connect, and an app picker (empty list = all
apps in the tunnel, non-empty = allowlist). Thin Kotlin host over the same
Rust core; no crypto or frame parsing in Kotlin.

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

## Known limitations

- **IPv4 only.** IPv6 targets are parsed but dropped: dial targets are built as
  `"{addr}:{port}"`, which is not a valid IPv6 literal.
- **No rekey / per-stream keys.** `generation` removes nonce reuse; it adds no
  forward secrecy or compartmentalisation (DEC-014 non-goals).
- **`kill_switch` and `restore_on_exit` are parsed but not enforced** by the
  core; the GUI hosts the YAML keys, the tunnel does not act on them.
- **Android host is not wired end-to-end** (`AetherVpnService` passes handle 0;
  `clientConnect`/`clientAttachTun` are not called from Kotlin).
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

`cargo test --workspace`, `cargo clippy --workspace --all-targets`,
`scripts/check_thin_hosts.ps1`, `scripts/check_gui_endpoints.ps1`,
`scripts/check_quickstart.ps1`, `scripts/check_android_build.ps1`.

Docs: `PLAN_FINAL_TDD.md` (live plan), `PLAN_ANDROID.md` (Android plan),
`PLAN_ENDPOINTS_WINDOWS.md` (Windows endpoint plan), `docs/WINDOWS_GUI.md`
(GUI + TDD log), `docs/ANDROID.md` (Android TDD log), `docs/DECISIONS.md`,
`docs/STATUS.md`.
