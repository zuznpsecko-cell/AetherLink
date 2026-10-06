//! Domain blocklist: suffix/exact matching for ad/tracker filtering.
//!
//! The client forwards tunneled targets by IP, so the robust server-side
//! choke points are DNS (QNAMEs arrive in plaintext at the virtual
//! resolver) and OPEN-time checks for the rare unresolved domain target.
//!
//! List format (one entry per line, same as the category-ads-all txt):
//! `.example.com` or `example.com` = suffix (matches subdomains),
//! `full:example.com` = exact host only, `#` = comment, blanks ignored.

use std::collections::HashSet;

/// Suffix/exact domain blocklist (all lowercase, no trailing dots).
#[derive(Debug, Clone, Default)]
pub struct Blocklist {
    suffix: HashSet<String>,
    exact: HashSet<String>,
}

impl Blocklist {
    /// Build from raw entries (file lines or config strings).
    pub fn from_entries<'a>(entries: impl IntoIterator<Item = &'a str>) -> Self {
        let mut b = Self::default();
        for e in entries {
            b.add(e);
        }
        b
    }

    /// Parse a whole list file: comments, blanks tolerated.
    pub fn parse_list(text: &str) -> Self {
        Self::from_entries(text.lines())
    }

    /// Load a list file from disk; missing file = empty (log at caller).
    pub fn load_file(path: &str) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Ok(Self::parse_list(&text))
    }

    fn add(&mut self, raw: &str) {
        let e = raw.trim().trim_start_matches('.').trim_end_matches('.');
        if e.is_empty() || e.starts_with('#') {
            return;
        }
        if let Some(host) = e.strip_prefix("full:") {
            let host = host.trim().to_lowercase();
            if !host.is_empty() {
                self.exact.insert(host);
            }
        } else {
            self.suffix.insert(e.to_lowercase());
        }
    }

    /// True when `host` (any case, optional trailing dot) is blocked.
    pub fn is_blocked(&self, host: &str) -> bool {
        let h = host.trim().trim_end_matches('.').to_lowercase();
        if h.is_empty() {
            return false;
        }
        if self.exact.contains(&h) {
            return true;
        }
        // Suffix: the host itself or any parent zone matches.
        let mut rest = h.as_str();
        loop {
            if self.suffix.contains(rest) {
                return true;
            }
            match rest.find('.') {
                Some(i) => rest = &rest[i + 1..],
                None => return false,
            }
        }
    }

    /// Number of loaded entries (both kinds).
    #[must_use]
    pub fn len(&self) -> usize {
        self.suffix.len() + self.exact.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Curated seed: major ad/tracker networks. The full category-ads-all DB
/// (100k+ suffixes) loads via `blocked_domains_file` (see fetch script).
pub fn seed_entries() -> &'static [&'static str] {
    &[
        "doubleclick.net",
        "googlesyndication.com",
        "googleadservices.com",
        "google-analytics.com",
        "googletagmanager.com",
        "googletagservices.com",
        "facebook.net",
        "fbcdn.net",
        "amazon-adsystem.com",
        "ads.yahoo.com",
        "advertising.com",
        "adnxs.com",
        "criteo.com",
        "criteo.net",
        "outbrain.com",
        "taboola.com",
        "mgid.com",
        "revcontent.com",
        "pubmatic.com",
        "rubiconproject.com",
        "openx.net",
        "spotxchange.com",
        "moatads.com",
        "moat.com",
        "scorecardresearch.com",
        "quantserve.com",
        "hotjar.com",
        "mixpanel.com",
        "segment.io",
        "amplitude.com",
        "appsflyer.com",
        "adjust.com",
        "branch.io",
        "mopub.com",
        "applovin.com",
        "unityads.unity3d.com",
        "yandexadexchange.net",
        "an.yandex.ru",
        "mc.yandex.ru",
        "ads.yahoo.com",
        "ads.microsoft.com",
        "ads.linkedin.com",
        "ads.pinterest.com",
        "ads.reddit.com",
        "ads.snapchat.com",
        "ads.tiktok.com",
        "ads.twitter.com",
        "ads.youtube.com",
        "full:ads.example.com",
    ]
}

/// Extract the QNAME (lowercased, dotted) from a raw DNS query packet.
/// `None` on truncated/malformed input (never panic on attacker bytes).
pub fn dns_query_name(query: &[u8]) -> Option<String> {
    if query.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut labels = Vec::new();
    let mut i = 12usize;
    loop {
        let len = *query.get(i)? as usize;
        if len == 0 {
            i += 1;
            break;
        }
        // Compression pointers and absurd lengths: not a plain question.
        if len & 0xC0 != 0 || len > 63 {
            return None;
        }
        i += 1;
        let end = i.checked_add(len)?;
        let label = std::str::from_utf8(query.get(i..end)?).ok()?;
        if label.is_empty() {
            return None;
        }
        labels.push(label.to_lowercase());
        i = end;
        if labels.len() > 127 || i + 4 > query.len() {
            return None;
        }
    }
    let _ = i;
    if labels.is_empty() {
        return None;
    }
    Some(labels.join("."))
}
