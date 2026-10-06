//! Blocklist matcher: suffix/exact domain blocking for the server.
//!
//! The client forwards tunneled targets by IP, so the robust server-side
//! choke point is DNS (QNAMEs arrive in plaintext) plus OPEN-time checks
//! for the rare unresolved domain target.

use aetherlink_server::blocklist::Blocklist;

#[test]
fn suffix_blocks_subdomains_but_not_parents_or_lookalikes() {
    let b = Blocklist::from_entries(["doubleclick.net"]);
    assert!(b.is_blocked("doubleclick.net"));
    assert!(b.is_blocked("www.doubleclick.net"));
    assert!(b.is_blocked("a.b.doubleclick.net"));
    assert!(!b.is_blocked("notdoubleclick.net"));
    assert!(!b.is_blocked("doubleclick.net.evil.com"));
    assert!(!b.is_blocked("doubleclick.com"));
}

#[test]
fn matching_is_case_insensitive_and_dot_tolerant() {
    let b = Blocklist::from_entries(["GoogleAds.COM"]);
    assert!(b.is_blocked("googleads.com"));
    assert!(b.is_blocked("GOOGLEADS.COM."));
    assert!(b.is_blocked("x.GoogleAds.Com"));
}

#[test]
fn full_prefix_is_exact_only() {
    let b = Blocklist::from_entries(["full:ads.example.com"]);
    assert!(b.is_blocked("ads.example.com"));
    assert!(!b.is_blocked("www.ads.example.com"));
}

#[test]
fn file_format_skips_comments_blanks_and_normalizes() {
    let text = "# comment\n\ndoubleclick.net\n  .GOOGLEADS.COM.  \nfull:ads.example.com\n";
    let b = Blocklist::parse_list(text);
    assert!(b.is_blocked("www.doubleclick.net"));
    assert!(b.is_blocked("googleads.com"));
    assert!(b.is_blocked("ads.example.com"));
    assert!(!b.is_blocked("www.ads.example.com"));
    assert!(!b.is_blocked("example.org"));
}

#[test]
fn empty_blocklist_blocks_nothing() {
    let b = Blocklist::default();
    assert!(!b.is_blocked("doubleclick.net"));
    assert!(!b.is_blocked("example.com"));
}

#[test]
fn dns_query_name_extracts_qname() {
    // example.com A query, txid 0x1234.
    let q = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x',
        b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
    ];
    assert_eq!(
        aetherlink_server::blocklist::dns_query_name(&q),
        Some("example.com".to_string())
    );
    assert_eq!(aetherlink_server::blocklist::dns_query_name(&[]), None);
    assert_eq!(
        aetherlink_server::blocklist::dns_query_name(&[0u8; 5]),
        None
    );
}
