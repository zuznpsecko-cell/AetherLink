//! TDD RED: Windows network capture/apply helpers (Phase W1, no privs).
//!
//! Pure parsers over canned `route print` / `ipconfig` output plus arg
//! builders for `route`/`netsh`. One live read-only test (cfg-gated)
//! proves parsing against the real machine without privileges.

use aetherlink_client::platform::windows::{
    dns_set_args, iface_admin_args, iface_metric_args, parse_ipconfig, parse_route_print,
    prefix_to_mask, route_add_args, route_add_if_args, route_delete_args, route_delete_if_args,
    tun_addr_args, TUN_IFACE_METRIC,
};

const ROUTE_PRINT: &str = "\
IPv4 Route Table\r\n\
===========================================================================\r\n\
Active Routes:\r\n\
Network Destination        Netmask          Gateway       Interface  Metric\r\n\
          0.0.0.0          0.0.0.0     192.168.31.1    192.168.31.95     25\r\n\
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331\r\n\
     192.168.31.0    255.255.255.0         On-link     192.168.31.95    281\r\n\
     192.168.56.0    255.255.255.0         On-link     192.168.56.1    281\r\n\
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    331\r\n\
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    331\r\n\
===========================================================================\r\n\
Persistent Routes:\r\n\
  None\r\n";

const IPCONFIG: &str = "\
Windows IP Configuration\r\n\
\r\n\
Ethernet adapter Ethernet0:\r\n\
\r\n\
   IPv4 Address. . . . . . . . . . . : 192.168.31.95(Preferred)\r\n\
   Subnet Mask . . . . . . . . . . . : 255.255.255.0\r\n\
   Default Gateway . . . . . . . . . : 192.168.31.1\r\n\
   DNS Servers . . . . . . . . . . . : 192.168.31.1\r\n\
                                       8.8.8.8\r\n";

#[test]
fn parse_route_table_finds_default() {
    // Given: real `route print -4` output
    let table = parse_route_print(ROUTE_PRINT).expect("parse");
    // When/Then: default + interface IP extracted, LAN rows kept.
    assert_eq!(
        table.default_gateway(),
        Some("192.168.31.1".parse().expect("ip"))
    );
    assert_eq!(
        table.default_iface_ip(),
        Some("192.168.31.95".parse().expect("ip"))
    );
    assert!(table
        .routes
        .iter()
        .any(|r| r.dest == "192.168.31.0/24" || r.dest == "192.168.31.0"));
}

#[test]
fn parse_ipconfig_finds_dns_and_iface() {
    // Given: real `ipconfig /all` fragment
    let (dns, ifaces) = parse_ipconfig(IPCONFIG);
    // Then: both DNS servers (primary + continuation line) found...
    assert_eq!(dns, vec!["192.168.31.1".to_string(), "8.8.8.8".to_string()]);
    // ...and adapter name maps to its IP.
    assert_eq!(
        ifaces.get("Ethernet0").map(String::as_str),
        Some("192.168.31.95")
    );
}

const IPCONFIG_RU: &str = "\
Windows IP Configuration\r\n\
\r\n\
Адаптер Ethernet Ethernet0:\r\n\
\r\n\
    IPv4-адрес. . . . . . . . . . . : 192.168.31.95(Preferred)\r\n\
    DNS-серверы . . . . . . . . . . : 192.168.31.1\r\n";

#[test]
fn parse_localized_ipconfig_by_technical_tokens() {
    // Given: non-English labels, same technical tokens (DNS/IPv4/dotless headers)
    let (dns, ifaces) = parse_ipconfig(IPCONFIG_RU);
    // Then: DNS + adapter mapping still extracted.
    assert_eq!(dns, vec!["192.168.31.1".to_string()]);
    // The type word ("Ethernet" after "Адаптер") is header chrome, not name.
    assert_eq!(
        ifaces.get("Ethernet0").map(String::as_str),
        Some("192.168.31.95")
    );
}

#[test]
fn parse_russian_unknown_adapter_header() {
    // Given: "Неизвестный адаптер <name>:" (wintun-style, no type word)
    let text = "Неизвестный адаптер singbox_tun:\r\n   IPv4-адрес. . . : 172.18.0.1\r\n";
    // Then: bare name extracted.
    let (_, ifaces) = parse_ipconfig(text);
    assert_eq!(
        ifaces.get("singbox_tun").map(String::as_str),
        Some("172.18.0.1")
    );
}

#[test]
fn prefix_to_mask_table() {
    assert_eq!(prefix_to_mask(1).expect("1"), "128.0.0.0");
    assert_eq!(prefix_to_mask(8).expect("8"), "255.0.0.0");
    assert_eq!(prefix_to_mask(24).expect("24"), "255.255.255.0");
    assert_eq!(prefix_to_mask(32).expect("32"), "255.255.255.255");
    assert_eq!(prefix_to_mask(0).expect("0"), "0.0.0.0");
    assert!(prefix_to_mask(33).is_err());
}

#[test]
fn route_arg_builders() {
    assert_eq!(
        route_add_args("1.2.3.4/32", "192.168.31.1").expect("add"),
        vec![
            "add".to_string(),
            "1.2.3.4".to_string(),
            "mask".to_string(),
            "255.255.255.255".to_string(),
            "192.168.31.1".to_string()
        ],
    );
    assert_eq!(
        route_add_args("10.0.0.0/8", "192.168.31.1").expect("add"),
        vec![
            "add".to_string(),
            "10.0.0.0".to_string(),
            "mask".to_string(),
            "255.0.0.0".to_string(),
            "192.168.31.1".to_string()
        ],
    );
    assert_eq!(
        route_delete_args("1.2.3.4/32", "192.168.31.1").expect("del"),
        vec![
            "delete".to_string(),
            "1.2.3.4".to_string(),
            "mask".to_string(),
            "255.255.255.255".to_string(),
            "192.168.31.1".to_string()
        ],
    );
    assert!(route_add_args("999.1.1.1/32", "192.168.31.1").is_err());
}

#[test]
fn dns_arg_builders() {
    assert_eq!(
        dns_set_args("Ethernet0", "10.255.0.1"),
        vec![
            "interface".to_string(),
            "ip".to_string(),
            "set".to_string(),
            "dnsservers".to_string(),
            "Ethernet0".to_string(),
            "static".to_string(),
            "10.255.0.1".to_string(),
        ],
    );
}

#[test]
fn tun_addr_arg_builder() {
    // Given: wintun adapter name + TUN address
    // When/Then: netsh static-address args, no gateway (point-to-point TUN).
    assert_eq!(
        tun_addr_args("aether0", "10.255.0.2", 30).expect("args"),
        vec![
            "interface".to_string(),
            "ipv4".to_string(),
            "set".to_string(),
            "address".to_string(),
            "name=\"aether0\"".to_string(),
            "source=static".to_string(),
            "address=10.255.0.2".to_string(),
            "mask=255.255.255.252".to_string(),
        ],
    );
    assert!(tun_addr_args("aether0", "999.0.0.1", 30).is_err());
    assert!(tun_addr_args("", "10.255.0.2", 30).is_err());
}

#[test]
fn iface_admin_arg_builder() {
    // Given: newborn (disabled) wintun adapter
    // Then: enable/disable args in the crate's quoted-name pattern.
    assert_eq!(
        iface_admin_args("aether0", true).expect("args"),
        vec![
            "interface".to_string(),
            "set".to_string(),
            "interface".to_string(),
            "name=\"aether0\"".to_string(),
            "admin=enabled".to_string(),
        ],
    );
    assert_eq!(
        iface_admin_args("aether0", false).expect("args")[4],
        "admin=disabled".to_string(),
    );
    assert!(iface_admin_args("", true).is_err());
}

#[test]
fn tun_iface_metric_arg_builder() {
    // Given: newborn wintun adapter → Then: interface metric pinned low so
    // derived route metrics beat DHCP Ethernet.
    assert!(TUN_IFACE_METRIC < 25, "must beat observed physical 25");
    assert_eq!(
        iface_metric_args("aether0", TUN_IFACE_METRIC).expect("args"),
        vec![
            "interface".to_string(),
            "ipv4".to_string(),
            "set".to_string(),
            "interface".to_string(),
            "name=\"aether0\"".to_string(),
            format!("metric={}", TUN_IFACE_METRIC),
        ],
    );
    assert!(iface_metric_args("", 1).is_err());
}

#[test]
fn tun_routes_bind_egress_ifindex() {
    // Given: TUN gateway + adapter index → Then: add/delete mirror the
    // `if` binding (unbound rows get pinned to the physical NIC live).
    assert_eq!(
        route_add_if_args("0.0.0.0/1", "10.255.0.1", 7).expect("args"),
        vec![
            "add".to_string(),
            "0.0.0.0".to_string(),
            "mask".to_string(),
            "128.0.0.0".to_string(),
            "10.255.0.1".to_string(),
            "if".to_string(),
            "7".to_string(),
        ],
    );
    assert_eq!(
        route_delete_if_args("128.0.0.0/1", "10.255.0.1", 7).expect("args")[5..],
        vec!["if".to_string(), "7".to_string()],
    );
    assert!(route_add_if_args("999.0.0.0/1", "10.255.0.1", 7).is_err());
}

#[test]
fn decode_utf16le_bom_ipconfig() {
    // Given: ipconfig bytes as Windows really emits them (UTF-16LE + BOM)
    let text = "Unknown adapter singbox_tun:\r\n   IPv4 Address. . . : 172.18.0.1(Preferred)\r\n";
    let mut raw = vec![0xFF, 0xFE];
    for w in text.encode_utf16() {
        raw.extend_from_slice(&w.to_le_bytes());
    }
    // When: decoding -> Then: headers end with ':' again, IPv4 mapping parses.
    let decoded = aetherlink_client::platform::windows::decode_cmd_output(&raw);
    let (_, ifaces) = parse_ipconfig(&decoded);
    assert_eq!(
        ifaces.get("singbox_tun").map(String::as_str),
        Some("172.18.0.1")
    );
    // And: plain UTF-8 passthrough still works.
    assert_eq!(
        aetherlink_client::platform::windows::decode_cmd_output(b"plain"),
        "plain"
    );
    // And: OEM IBM866 (direct-spawn ipconfig on RU Windows) decodes to text.
    let oem: Vec<u8> = vec![
        0x8D, 0xA5, 0xA8, 0xA7, 0xA2, 0xA5, 0xE1, 0xE2, 0xAD, 0xEB,
        0xA9, // Неизвестный
        0x20, // space
        0xA0, 0xA4, 0xA0, 0xAF, 0xE2, 0xA5, 0xE0, // адаптер
        0x20, // space
        b's', b'i', b'n', b'g', b'b', b'o', b'x', b'_', b't', b'u', b'n', b':',
    ];
    assert_eq!(
        aetherlink_client::platform::windows::decode_cmd_output(&oem),
        "Неизвестный адаптер singbox_tun:"
    );
}

#[test]
#[cfg(windows)]
fn live_snapshot_reads_this_machine() {
    // Given: real Windows without privileges (read-only commands need none)
    // When: capturing → Then: default route present, parse matches reality.
    let table = aetherlink_client::platform::windows::read_route_table().expect("live route print");
    assert!(table.default_gateway().is_some());
    assert!(table.default_iface_ip().is_some());
}
