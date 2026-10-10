//! AetherLink Linux client (Ubuntu 24.04).
//!
//! THIN HOST: config load + lifecycle calls into the Rust core
//! (`aetherlink_client`) + hotspot management. No protocol, crypto or
//! packet code here (AGENT_INSTRUCTIONS §1.1) — the core owns all of it.
//!
//! Commands mirror the .NET Windows host:
//!   aetherlink-cli <config.yaml> up|down|cleanup|status
//!   aetherlink-cli hotspot up|down|status [...]

mod hotspot_cmd;
mod signals;

use std::sync::{mpsc, Arc, Mutex};

use aetherlink_client::{cleanup, Client, ClientError};

const USAGE: &str = "\
AetherLink client (Linux) — thin host over the Rust core.

Usage:
  aetherlink-cli <config.yaml> up [--hotspot]   tunnel up (+ WiFi hotspot if configured or forced)
  aetherlink-cli <config.yaml> down             tunnel down (restores routes/DNS)
  aetherlink-cli <config.yaml> status           tunnel + hotspot status JSON
  aetherlink-cli <config.yaml> cleanup          crash recovery: restore routes/DNS, hotspot down
  aetherlink-cli hotspot up   [--config f] [--iface X --ssid S --password P --subnet CIDR --backend auto|network-manager|hostapd]
  aetherlink-cli hotspot down
  aetherlink-cli hotspot status
  aetherlink-cli --version | --help

Environment: AETHERLINK_DEBUG=1 for verbose core logs.
";

fn main() {
    std::process::exit(match run(std::env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    });
}

fn run(args: Vec<String>) -> Result<i32, String> {
    if args.is_empty() {
        eprint!("{USAGE}");
        return Ok(2);
    }
    match args[0].as_str() {
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(0)
        }
        "-V" | "--version" => {
            println!("aetherlink-cli {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        "hotspot" => hotspot_cmd::dispatch(&args[1..]),
        config => {
            let Some(cmd) = args.get(1) else {
                eprint!("{USAGE}");
                return Ok(2);
            };
            let rest = &args[2..];
            match cmd.as_str() {
                "up" => cmd_up(config, rest),
                "down" => cmd_down(config),
                "status" => cmd_status(config),
                "cleanup" => cmd_cleanup(),
                other => Err(format!("unknown command '{other}'\n\n{USAGE}")),
            }
        }
    }
}

/// `up`: full tunnel + optional hotspot, then wait for SIGINT/SIGTERM or a
/// dead pump; teardown always restores routes/DNS (journal-backed).
fn cmd_up(config_path: &str, rest: &[String]) -> Result<i32, String> {
    require_root_hint();
    let doc = aetherlink_core::config::load(std::path::Path::new(config_path))
        .map_err(|e| format!("config {config_path}: {e}"))?;
    let mut client = Client::new(doc.clone()).map_err(|e| format!("config: {e}"))?;

    // Stale state (previous run died): recover once, then retry — same
    // contract the FFI hosts implement.
    match client.up_full(None) {
        Ok(()) => {}
        Err(ClientError::StaleState(msg)) => {
            eprintln!("stale tunnel state ({msg}); force_cleanup + retry once");
            let _ = cleanup::force_cleanup();
            client
                .up_full(None)
                .map_err(|e| format!("up failed after cleanup: {e}"))?;
        }
        Err(e) => return Err(format!("up failed (routes/DNS rolled back by core): {e}")),
    }
    println!("Tunnel up. Press Ctrl+C to bring it down (DNS/routes restored).");

    // Hotspot: config-driven (`hotspot.enabled`), `--hotspot` forces it.
    let mut hotspot_cfg = aetherlink_hotspot::HotspotConfig::from_doc(&doc)
        .map_err(|e| format!("hotspot config: {e}"))?;
    if has_flag(rest, "--hotspot") {
        hotspot_cfg.enabled = true;
    }
    let hotspot_started = if hotspot_cfg.enabled {
        match aetherlink_hotspot::up(&hotspot_cfg) {
            Ok(st) => {
                println!(
                    "Hotspot up: '{}' on {}, subnet {} — clients route via the tunnel (backend {:?})",
                    st.ssid, st.interface, st.subnet, st.backend
                );
                true
            }
            Err(e) => {
                eprintln!("WARNING: hotspot not started: {e} (tunnel stays up)");
                false
            }
        }
    } else {
        false
    };

    // Wait for a signal or a dead pump; whichever comes first.
    let client = Arc::new(Mutex::new(client));
    let (rx, tx) = signals::shutdown_channel();
    spawn_watchdog(Arc::clone(&client), tx);
    let reason = rx.recv().unwrap_or("signal");

    // Teardown: hotspot first (its guard references the tunnel iface), then
    // the tunnel itself. Both are idempotent/journal-backed.
    if hotspot_started {
        aetherlink_hotspot::down_quiet();
    }
    {
        let mut guard = client.lock().expect("client lock");
        if let Err(e) = guard.down() {
            eprintln!("down reported: {e}");
        }
    }
    println!("Tunnel down, network/DNS restored.");
    if reason == "pump-dead" {
        eprintln!("pump died while up (server unreachable?) — tunnel was torn down");
        Ok(3)
    } else {
        Ok(0)
    }
}

/// Watchdog: the pump dying means routes/DNS still point into a dark TUN —
/// the host must tear down, not show "Up" (same invariant as the GUI).
fn spawn_watchdog(client: Arc<Mutex<Client>>, notify: mpsc::Sender<&'static str>) {
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            let dead = {
                let Ok(guard) = client.lock() else {
                    break; // poisoned: main is already unwinding
                };
                if !guard.is_up() {
                    break; // down path in progress / done
                }
                guard
                    .status()
                    .ok()
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                    .and_then(|v| v.get("pump_alive").and_then(serde_json::Value::as_bool))
                    .is_some_and(|alive| !alive)
            };
            if dead {
                let _ = notify.send("pump-dead");
                break;
            }
        }
    });
}

/// `down`: graceful teardown via the state journal (works when the `up`
/// process is already gone).
fn cmd_down(config_path: &str) -> Result<i32, String> {
    let doc = aetherlink_core::config::load(std::path::Path::new(config_path))
        .map_err(|e| format!("config {config_path}: {e}"))?;
    let mut client = Client::new(doc).map_err(|e| format!("config: {e}"))?;
    client
        .down()
        .map_err(|e| format!("down failed: {e}"))?;
    println!("Tunnel down, network/DNS restored.");
    // Hotspot has its own lifecycle/state file; nudge, never guess.
    if aetherlink_hotspot::status().contains("\"up\"") {
        println!("note: hotspot is still up — `aetherlink-cli hotspot down` stops it.");
    }
    Ok(0)
}

/// `status`: tunnel JSON + hotspot JSON (no secrets in either).
fn cmd_status(config_path: &str) -> Result<i32, String> {
    let doc = aetherlink_core::config::load(std::path::Path::new(config_path))
        .map_err(|e| format!("config {config_path}: {e}"))?;
    let client = Client::new(doc).map_err(|e| format!("config: {e}"))?;
    println!("{}", client.status().map_err(|e| format!("status: {e}"))?);
    println!("{}", aetherlink_hotspot::status());
    Ok(0)
}

/// `cleanup`: idempotent crash recovery (routes + DNS + hotspot).
fn cmd_cleanup() -> Result<i32, String> {
    cleanup::force_cleanup().map_err(|e| format!("force_cleanup: {e}"))?;
    aetherlink_hotspot::down_quiet();
    println!("Cleanup done (routes/DNS restored from the journal, hotspot down).");
    Ok(0)
}

/// `--flag` present in the argument list.
fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

/// Pull `--name value` out of the argument list.
fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// Friendly hint when clearly not root (mutations will fail with named
/// errors anyway; this is just UX).
fn require_root_hint() {
    #[cfg(unix)]
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("warning: not root — TUN/routing/DNS changes need root/CAP_NET_ADMIN");
    }
}
