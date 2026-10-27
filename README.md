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

## Checks

`cargo test --workspace`, `cargo clippy --workspace --all-targets`,
`scripts/check_thin_hosts.ps1`, `scripts/check_gui_endpoints.ps1`,
`scripts/check_quickstart.ps1`, `scripts/check_android_build.ps1`.

Docs: `PLAN_FINAL_TDD.md` (live plan), `PLAN_ANDROID.md` (Android plan),
`PLAN_ENDPOINTS_WINDOWS.md` (Windows endpoint plan), `docs/WINDOWS_GUI.md`
(GUI + TDD log), `docs/ANDROID.md` (Android TDD log), `docs/DECISIONS.md`,
`docs/STATUS.md`.
