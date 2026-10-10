//! `hotspot` subcommand: AP lifecycle independent of the tunnel run.

use aetherlink_hotspot::HotspotConfig;

use crate::{flag_value, has_flag};

const USAGE: &str = "\
Usage:
  aetherlink-cli hotspot up   [--config f] [--iface X] [--ssid S] [--password P]
                              [--subnet CIDR] [--backend auto|network-manager|hostapd]
  aetherlink-cli hotspot down
  aetherlink-cli hotspot status
";

/// Dispatch `hotspot <subcmd>`; CLI flags overlay the config section.
pub fn dispatch(args: &[String]) -> Result<i32, String> {
    let Some(sub) = args.first() else {
        eprint!("{USAGE}");
        return Ok(2);
    };
    match sub.as_str() {
        "up" => {
            let mut cfg = match flag_value(args, "--config") {
                Some(path) => {
                    let doc = aetherlink_core::config::load(std::path::Path::new(&path))
                        .map_err(|e| format!("config {path}: {e}"))?;
                    HotspotConfig::from_doc(&doc)
                        .map_err(|e| format!("hotspot config: {e}"))?
                }
                None => HotspotConfig::default(),
            };
            if let Some(v) = flag_value(args, "--iface") {
                cfg.interface = Some(v);
            }
            if let Some(v) = flag_value(args, "--ssid") {
                cfg.ssid = v;
            }
            if let Some(v) = flag_value(args, "--password") {
                cfg.password = Some(v);
            }
            if let Some(v) = flag_value(args, "--subnet") {
                cfg.subnet = v;
            }
            if let Some(v) = flag_value(args, "--backend") {
                cfg.backend = aetherlink_hotspot::BackendChoice::parse(&v)
                    .map_err(|e| e.to_string())?;
            }
            if has_flag(args, "--help") || has_flag(args, "-h") {
                print!("{USAGE}");
                return Ok(0);
            }
            // The hotspot guard is fail-closed: client traffic only leaves
            // via the tunnel. Without an up (or up-able) tunnel, clients
            // associate but get no internet — say so up front.
            if !aetherlink_client::platform::default_state_path().exists() {
                eprintln!(
                    "note: no tunnel is up — hotspot clients will have no internet \
                     until you run `aetherlink-cli <config> up`."
                );
            }
            let st = aetherlink_hotspot::up(&cfg).map_err(|e| e.to_string())?;
            println!(
                "Hotspot up: '{}' on {}, subnet {} — clients route via the tunnel when it is up (backend {:?})",
                st.ssid, st.interface, st.subnet, st.backend
            );
            Ok(0)
        }
        "down" => {
            aetherlink_hotspot::down().map_err(|e| e.to_string())?;
            println!("Hotspot down (AP off, firewall guard removed, ip_forward restored).");
            Ok(0)
        }
        "status" => {
            println!("{}", aetherlink_hotspot::status());
            Ok(0)
        }
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(0)
        }
        other => Err(format!("unknown hotspot command '{other}'\n\n{USAGE}")),
    }
}
