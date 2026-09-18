//! Routing rules engine (§6).
//!
//! Pure policy: which destinations go `direct`, everything else `tunnel`.
//! Precedence: loopback/pin (platform) → `direct` rules by
//! priority + longest prefix → default `tunnel`.
//! DNS always resolves via tunnel even for direct names (§1.3.6).

use std::net::Ipv4Addr;

use serde::Serialize;

use crate::{ClientError, Result};

/// Routing action for a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Action {
    /// Via tunnel.
    Tunnel,
    /// Direct via physical gateway.
    Direct,
}

/// Destination matcher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Matcher {
    /// Exact IPv4 address.
    Ip(Ipv4Addr),
    /// IPv4 CIDR (base, prefix bits).
    Cidr(Ipv4Addr, u8),
    /// Inclusive IPv4 range.
    IpRange(Ipv4Addr, Ipv4Addr),
    /// Exact domain (case-insensitive).
    Domain(String),
    /// Suffix incl. leading dot (matches subdomains only).
    Suffix(String),
}

/// Named rule with priority (higher wins).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rule {
    /// Rule name (config `name:`).
    pub name: String,
    /// Action on match.
    pub action: Action,
    /// Destination matcher.
    pub matcher: Matcher,
    /// Priority (higher wins).
    pub priority: u32,
}

impl Rule {
    /// Parse one rule document (`{name, action, priority, when:{...}}`).
    pub fn from_doc(doc: &serde_json::Value) -> Result<Self> {
        let req = |field: &str| {
            doc.get(field)
                .and_then(serde_json::Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .ok_or_else(|| ClientError::RoutingError(format!("rule missing {field}")))
        };
        let name = req("name")?;
        let action = match req("action")?.as_str() {
            "direct" => Action::Direct,
            "tunnel" => Action::Tunnel,
            other => {
                return Err(ClientError::RoutingError(format!("bad action {other}")));
            }
        };
        let priority = doc
            .get("priority")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(50) as u32;
        let when = doc
            .get("when")
            .ok_or_else(|| ClientError::RoutingError("rule missing when".to_string()))?;
        let matcher = if let Some(cidr) = when.get("cidr").and_then(serde_json::Value::as_str) {
            let (base, prefix) = cidr
                .split_once('/')
                .ok_or_else(|| ClientError::RoutingError(format!("bad cidr {cidr}")))?;
            let base: Ipv4Addr = base
                .parse()
                .map_err(|_| ClientError::RoutingError(format!("bad cidr {cidr}")))?;
            let prefix: u8 = prefix
                .parse()
                .map_err(|_| ClientError::RoutingError(format!("bad cidr {cidr}")))?;
            if prefix > 32 {
                return Err(ClientError::RoutingError(format!("bad cidr {cidr}")));
            }
            Matcher::Cidr(base, prefix)
        } else if let Some(ip) = when.get("ip").and_then(serde_json::Value::as_str) {
            Matcher::Ip(
                ip.parse()
                    .map_err(|_| ClientError::RoutingError(format!("bad ip {ip}")))?,
            )
        } else if let Some(range) = when.get("ip_range").and_then(serde_json::Value::as_str) {
            let (lo, hi) = range
                .split_once('-')
                .ok_or_else(|| ClientError::RoutingError(format!("bad ip_range {range}")))?;
            let lo: Ipv4Addr = lo
                .parse()
                .map_err(|_| ClientError::RoutingError(format!("bad ip_range {range}")))?;
            let hi: Ipv4Addr = hi
                .parse()
                .map_err(|_| ClientError::RoutingError(format!("bad ip_range {range}")))?;
            if lo > hi {
                return Err(ClientError::RoutingError(format!("bad ip_range {range}")));
            }
            Matcher::IpRange(lo, hi)
        } else if let Some(domain) = when.get("domain").and_then(serde_json::Value::as_str) {
            if domain.is_empty() {
                return Err(ClientError::RoutingError("empty domain".to_string()));
            }
            Matcher::Domain(domain.to_string())
        } else if let Some(suffix) = when.get("suffix").and_then(serde_json::Value::as_str) {
            if suffix.is_empty() {
                return Err(ClientError::RoutingError("empty suffix".to_string()));
            }
            Matcher::Suffix(suffix.to_string())
        } else {
            return Err(ClientError::RoutingError(
                "rule when needs one matcher".to_string(),
            ));
        };
        Ok(Self {
            name,
            action,
            matcher,
            priority,
        })
    }

    /// Validate an already-built rule (reload path).
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(ClientError::RoutingError("empty rule name".to_string()));
        }
        match &self.matcher {
            Matcher::Cidr(_, prefix) if *prefix > 32 => {
                Err(ClientError::RoutingError("bad cidr prefix".to_string()))
            }
            Matcher::Domain(d) | Matcher::Suffix(d) if d.is_empty() => {
                Err(ClientError::RoutingError("empty matcher".to_string()))
            }
            Matcher::IpRange(lo, hi) if lo > hi => {
                Err(ClientError::RoutingError("bad ip_range".to_string()))
            }
            _ => Ok(()),
        }
    }
}

impl Matcher {
    /// Specificity for tie-breaks (longest prefix wins).
    fn specificity(&self) -> usize {
        match self {
            Self::Cidr(_, p) => *p as usize,
            Self::Ip(_) => 32,
            Self::IpRange(_, _) => 16,
            Self::Domain(d) => 64 + d.len(),
            Self::Suffix(s) => s.len(),
        }
    }

    fn matches_ip(&self, ip: Ipv4Addr) -> bool {
        match self {
            Self::Ip(a) => *a == ip,
            Self::Cidr(base, prefix) => {
                if *prefix == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - prefix);
                u32::from(*base) & mask == u32::from(ip) & mask
            }
            Self::IpRange(lo, hi) => *lo <= ip && ip <= *hi,
            Self::Domain(_) | Self::Suffix(_) => false,
        }
    }

    fn matches_name(&self, host: &str) -> bool {
        match self {
            Self::Domain(d) => host.eq_ignore_ascii_case(d),
            Self::Suffix(s) => host.len() > s.len() && host.ends_with(s.as_str()),
            Self::Ip(_) | Self::Cidr(_, _) | Self::IpRange(_, _) => false,
        }
    }
}

/// Ordered rule set with a default action.
#[derive(Debug, Clone)]
pub struct Ruleset {
    rules: Vec<Rule>,
    /// Default when nothing matches (`tunnel`).
    pub default_action: Action,
    /// RFC1918 direct without explicit rules.
    pub include_private_lan_direct: bool,
}

impl Ruleset {
    /// Default: tunnel-first, private LAN direct (§1.4).
    #[must_use]
    pub fn new() -> Self {
        let mut rs = Self {
            rules: Vec::new(),
            default_action: Action::Tunnel,
            include_private_lan_direct: true,
        };
        rs.add_cidr("lan-10", "10.0.0.0", 8, 10);
        rs.add_cidr("lan-172", "172.16.0.0", 12, 10);
        rs.add_cidr("lan-192", "192.168.0.0", 16, 10);
        rs
    }

    /// Borrow all rules (lifecycle installs IP-family ones as routes).
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Replace the complete rule list (FFI `rules_set`).
    ///
    /// Full replacement by contract: the caller owns defaults, so a set
    /// that must keep RFC1918-direct has to include LAN rules explicitly.
    /// Every rule is validated before anything is replaced (atomic).
    pub fn replace_rules(&mut self, rules: Vec<Rule>) -> Result<()> {
        for rule in &rules {
            rule.validate()?;
        }
        self.rules = rules;
        Ok(())
    }

    /// Push a fully-specified rule.
    pub fn add_rule(&mut self, name: &str, action: Action, matcher: Matcher, priority: u32) {
        self.rules.push(Rule {
            name: name.to_string(),
            action,
            matcher,
            priority,
        });
    }

    /// Suffix rule (`direct`).
    pub fn add_suffix(&mut self, name: &str, suffix: &str, priority: u32) {
        self.add_rule(
            name,
            Action::Direct,
            Matcher::Suffix(suffix.to_string()),
            priority,
        );
    }

    /// Exact-domain rule (`direct`).
    pub fn add_domain(&mut self, name: &str, domain: &str, priority: u32) {
        self.add_rule(
            name,
            Action::Direct,
            Matcher::Domain(domain.to_string()),
            priority,
        );
    }

    /// Single-IP rule (`direct`).
    pub fn add_ip(&mut self, name: &str, ip: &str, priority: u32) -> Result<()> {
        let addr: Ipv4Addr = ip
            .parse()
            .map_err(|_| ClientError::RoutingError(format!("bad ip {ip}")))?;
        self.add_rule(name, Action::Direct, Matcher::Ip(addr), priority);
        Ok(())
    }

    /// Inclusive-range rule (`direct`).
    pub fn add_ip_range(&mut self, name: &str, lo: &str, hi: &str, priority: u32) -> Result<()> {
        let parse = |s: &str| {
            s.parse::<Ipv4Addr>()
                .map_err(|_| ClientError::RoutingError(format!("bad ip {s}")))
        };
        let (lo, hi) = (parse(lo)?, parse(hi)?);
        if lo > hi {
            return Err(ClientError::RoutingError("range lo > hi".to_string()));
        }
        self.add_rule(name, Action::Direct, Matcher::IpRange(lo, hi), priority);
        Ok(())
    }

    fn add_cidr(&mut self, name: &str, base: &str, prefix: u8, priority: u32) {
        if let Ok(addr) = base.parse::<Ipv4Addr>() {
            self.add_rule(name, Action::Direct, Matcher::Cidr(addr, prefix), priority);
        }
    }

    /// Match `host` (IP literal or DNS name) to an action.
    #[must_use]
    pub fn match_action(&self, host: &str) -> Action {
        let mut best: Option<(&Rule, usize)> = None;
        let is_ip = host.parse::<Ipv4Addr>();
        for rule in &self.rules {
            let hit = match is_ip {
                Ok(ip) => rule.matcher.matches_ip(ip),
                Err(_) => {
                    // Private-LAN gate only applies to IP literals.
                    rule.matcher.matches_name(host)
                }
            };
            if !hit {
                continue;
            }
            // Skip built-in LAN rules for names (they only match IPs anyway).
            let spec = rule.matcher.specificity();
            let replace = match &best {
                None => true,
                Some((r, s)) => {
                    rule.priority > r.priority || (rule.priority == r.priority && spec > *s)
                }
            };
            if replace {
                best = Some((rule, spec));
            }
        }
        if let Some((rule, _)) = best {
            return rule.action;
        }
        // LAN-direct default for IP literals when enabled.
        if self.include_private_lan_direct {
            if let Ok(ip) = host.parse::<Ipv4Addr>() {
                if ip.is_private() {
                    return Action::Direct;
                }
            }
        }
        self.default_action
    }
}

impl Default for Ruleset {
    fn default() -> Self {
        Self::new()
    }
}
