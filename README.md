# AetherLink

VPN with userspace netstack. Single Rust core + thin FFI hosts (.NET/Android).

## Run (server + client)

Windows (client elevated): `.\scripts\run_server_windows.ps1`, `.\scripts\run_client_windows.ps1`
Ubuntu: `./scripts/run_server_ubuntu.sh`, `sudo ./scripts/run_client_ubuntu.sh`

## Linux client (Ubuntu 24.04)

Native thin client `aetherlink-cli` (Rust core directly, no .NET): full
tunnel over `/dev/net/tun`, DNS-only-through-tunnel, crash-recovery
journal — plus sharing the tunneled traffic over a WiFi hotspot
(`hotspot:` config section or `aetherlink-cli hotspot up|down|status`,
NetworkManager or hostapd backend, fail-closed when the tunnel is down).
Docs: `docs/LINUX_CLIENT.md`.

## GUI client (Windows, Avalonia)

Tray icon + main window (status/egress IP, server config, routing rules,
logs). Thin host like the console client: same `aetherlink_core.dll`
via FFI, no protocol code in C#. Requires admin at startup (TUN).

```powershell
.\scripts\run_gui_windows.ps1   # build + stage to dist/win-gui, then run AetherLink.Gui.exe
```

Config: `client.local.yaml` next to the exe (edited in the Server tab,
validated by the core on connect). Logs: `logs/gui-<date>.log`.

## Checks

`cargo test --workspace`, `cargo clippy --workspace --all-targets`,
`scripts/check_thin_hosts.ps1`, `scripts/check_quickstart.ps1`.

Docs: `PLAN_FINAL_TDD.md` (live plan), `docs/DECISIONS.md`, `docs/STATUS.md`.
