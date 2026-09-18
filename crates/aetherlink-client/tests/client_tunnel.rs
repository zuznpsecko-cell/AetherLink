//! TDD RED: client routing rules + DNS no-leak + lifecycle safety.
//!
//! Locks §1.3 (DNS only via tunnel), §1.4 (full tunnel + precedence),
//! §5 (up/down idempotent, rollback) and §6 (rule engine) at the pure
//! logic level. Platform application (routes, NRPT, resolv.conf,
//! VpnService) lands in the platform task; these tests pin the policy.

use aetherlink_client::platform::FakePlatform;
use aetherlink_client::{cleanup, dns, lifecycle, routing};

// ---------- rule engine ----------

#[test]
fn routing_default_is_tunnel() {
    // Given: default ruleset, no custom rules
    let rs = routing::Ruleset::new();
    // When: matching a public IP and an unknown name
    // Then: everything goes via tunnel
    assert_eq!(rs.match_action("93.184.216.34"), routing::Action::Tunnel);
    assert_eq!(
        rs.match_action("unknown.example.org"),
        routing::Action::Tunnel
    );
}

#[test]
fn routing_private_lan_direct_by_default() {
    // Given: default ruleset (include_private_lan_direct: true)
    let rs = routing::Ruleset::new();
    // When: matching RFC1918 addresses
    // Then: direct, tunnel never sees LAN
    assert_eq!(rs.match_action("192.168.1.5"), routing::Action::Direct);
    assert_eq!(rs.match_action("10.0.0.9"), routing::Action::Direct);
    assert_eq!(rs.match_action("172.16.4.2"), routing::Action::Direct);
}

#[test]
fn routing_suffix_matches_subdomains_only() {
    // Given: suffix rule for .example.com
    let mut rs = routing::Ruleset::new();
    rs.add_suffix("site", ".example.com", 50);
    // When: matching names
    // Then: subdomains direct, bare domain and others tunnel
    assert_eq!(rs.match_action("a.b.example.com"), routing::Action::Direct);
    assert_eq!(rs.match_action("example.com"), routing::Action::Tunnel);
    assert_eq!(rs.match_action("notexample.com"), routing::Action::Tunnel);
}

#[test]
fn routing_exact_domain_and_ip_range() {
    // Given: exact domain + single ip + range rules
    let mut rs = routing::Ruleset::new();
    rs.add_domain("api", "api.example.com", 50);
    rs.add_ip("one", "198.51.100.10", 40).expect("ip rule");
    rs.add_ip_range("pool", "203.0.113.10", "203.0.113.50", 40)
        .expect("range rule");
    // When/Then: exact hits direct, neighbours tunnel
    assert_eq!(rs.match_action("api.example.com"), routing::Action::Direct);
    assert_eq!(rs.match_action("198.51.100.10"), routing::Action::Direct);
    assert_eq!(rs.match_action("198.51.100.11"), routing::Action::Tunnel);
    assert_eq!(rs.match_action("203.0.113.30"), routing::Action::Direct);
    assert_eq!(rs.match_action("203.0.113.51"), routing::Action::Tunnel);
}

#[test]
fn routing_higher_priority_wins() {
    // Given: overlapping suffix rules, different priority
    let mut rs = routing::Ruleset::new();
    rs.add_suffix("wide", ".example.com", 10);
    rs.add_suffix("narrow", ".sub.example.com", 90);
    // When: matching the overlap
    // Then: higher priority wins (direct either way here would hide the check,
    // so narrow is tunnel-scoped via explicit action below)
    let _ = &rs;
    let mut rs2 = routing::Ruleset::new();
    rs2.add_rule(
        "wide-direct",
        routing::Action::Direct,
        routing::Matcher::Suffix(".example.com".to_string()),
        10,
    );
    rs2.add_rule(
        "narrow-tunnel",
        routing::Action::Tunnel,
        routing::Matcher::Suffix(".sub.example.com".to_string()),
        90,
    );
    assert_eq!(
        rs2.match_action("a.sub.example.com"),
        routing::Action::Tunnel
    );
    assert_eq!(
        rs2.match_action("other.example.com"),
        routing::Action::Direct
    );
}

// ---------- DNS no-leak ----------

#[test]
fn dns_forced_through_tunnel() {
    // Given: tunnel up intent
    // When: forcing DNS to the virtual resolver
    // Then: policy call succeeds (platform override lands later)
    dns::force_tunnel_dns().expect("tunnel DNS policy must apply");
    assert_eq!(dns::mode(), "tunnel");
}

// ---------- lifecycle safety ----------

#[test]
fn lifecycle_down_without_up_is_safe() {
    // Given: never brought up
    let mut plat = FakePlatform::working(std::env::temp_dir().join("aether-legacy-down.json"));
    // When: tearing down
    // Then: no-op Ok, never half-applied state
    lifecycle::down(&mut plat).expect("down without up must be safe");
}

#[test]
fn cleanup_is_idempotent() {
    // Given: any state (including none)
    // When: force cleanup twice (crash recovery path)
    // Then: both succeed, network+DNS restore never fails the caller
    cleanup::force_cleanup().expect("first cleanup");
    cleanup::force_cleanup().expect("second cleanup");
}
