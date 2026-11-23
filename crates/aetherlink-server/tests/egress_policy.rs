//! Egress policy (DEC-021): which resolved addresses the relay may dial.
//!
//! These are pure policy checks — no sockets. The end-to-end behaviour (a
//! refused OPEN costs one flow, not the session) is in `egress_tests.rs`.

use std::net::IpAddr;

use aetherlink_server::egress::{Cidr, EgressDenied, EgressPolicy};

fn ip(s: &str) -> IpAddr {
    s.parse().expect("ip literal")
}

fn policy(deny_private: bool, allow: &[&str], deny: &[&str]) -> EgressPolicy {
    let parse = |list: &[&str]| -> Vec<Cidr> {
        list.iter().map(|s| Cidr::parse(s).expect("cidr")).collect()
    };
    EgressPolicy::new(deny_private, parse(allow), parse(deny))
}

#[test]
fn default_policy_blocks_loopback_lan_and_metadata() {
    // Given: the shipped default (deny_private on, no exceptions)
    let p = policy(true, &[], &[]);

    // Then: everything that lives inside a host or datacenter is refused
    for target in [
        "127.0.0.1",        // loopback
        "10.0.0.5",         // RFC1918
        "172.16.0.1",       // RFC1918
        "192.168.1.1",      // RFC1918
        "169.254.169.254",  // cloud metadata
        "169.254.1.1",      // link local
        "100.64.0.1",       // CGNAT
        "0.0.0.0",          // unspecified
        "::1",              // v6 loopback
        "fc00::1",          // v6 ULA
        "fe80::1",          // v6 link local
        "::ffff:127.0.0.1", // v4-mapped loopback must not sneak past
    ] {
        assert_eq!(
            p.check(ip(target)),
            Err(EgressDenied::Private),
            "{target} must be refused by default"
        );
    }
}

#[test]
fn public_addresses_are_allowed() {
    // Given: the default policy
    let p = policy(true, &[], &[]);
    // Then: ordinary internet targets pass (this is not an allowlist)
    for target in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700::1111"] {
        assert_eq!(p.check(ip(target)), Ok(()), "{target} must be dialable");
    }
}

#[test]
fn explicit_allow_wins_over_the_private_default() {
    // Given: an operator hole for one LAN host
    let p = policy(true, &["10.0.0.5/32"], &[]);
    // Then: exactly that host is reachable, the rest of the range is not
    assert_eq!(p.check(ip("10.0.0.5")), Ok(()));
    assert_eq!(p.check(ip("10.0.0.6")), Err(EgressDenied::Private));
}

#[test]
fn allow_takes_precedence_over_deny() {
    // Given: overlapping allow and deny entries
    let p = policy(true, &["10.0.7.0/24"], &["10.0.0.0/8"]);
    // Then: the narrower allow wins (documented order allow → deny → default)
    assert_eq!(p.check(ip("10.0.7.9")), Ok(()));
    assert_eq!(p.check(ip("10.0.8.9")), Err(EgressDenied::Denied));
}

#[test]
fn deny_list_blocks_public_targets_too() {
    // Given: a deny rule for a public range
    let p = policy(true, &[], &["93.184.216.0/24"]);
    // Then: it applies regardless of the private default
    assert_eq!(p.check(ip("93.184.216.34")), Err(EgressDenied::Denied));
    assert_eq!(p.check(ip("93.184.217.34")), Ok(()));
}

#[test]
fn permissive_policy_allows_loopback_for_tests_and_opt_out() {
    // Given: the opt-out
    let p = EgressPolicy::permissive();
    // Then: loopback passes, which is what local relays and the test suite
    // rely on. `denies_private` reports the mode for startup logging.
    assert_eq!(p.check(ip("127.0.0.1")), Ok(()));
    assert!(!p.denies_private());
}

#[test]
fn adjacent_private_ranges_are_not_swept_up() {
    // Given: the default policy
    let p = policy(true, &[], &[]);
    // Then: neighbours of private ranges stay reachable. These are the
    // off-by-one cases a hand-written octet check gets wrong.
    for target in [
        "9.255.255.255",
        "11.0.0.0",
        "172.15.255.255",
        "172.32.0.0",
        "192.167.255.255",
        "192.169.0.0",
        "100.63.255.255",
        "100.128.0.0",
    ] {
        assert_eq!(p.check(ip(target)), Ok(()), "{target} is public");
    }
}

#[test]
fn denied_reason_is_stable_for_logs() {
    // Then: the two reasons stay distinguishable in operator-facing logs
    assert_eq!(
        EgressDenied::Private.as_str(),
        "private or metadata address"
    );
    assert_eq!(EgressDenied::Denied.as_str(), "denied by egress policy");
}
