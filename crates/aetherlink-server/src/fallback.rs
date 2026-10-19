//! Static web fallback decision (§4.5, G2).
//!
//! Valid AUTH → `"tunnel"` (mux inside TLS).
//! Missing/bad auth → `"static"` (plain web root, no tunnel banner).

use crate::{Result, ServerError};

/// Decide the path for an incoming connection.
pub fn decide(authed: bool) -> Result<&'static str> {
    if authed {
        Ok("tunnel")
    } else {
        Ok("static")
    }
}

/// True when the path serves the static web root (G2: no tunnel surface).
#[must_use]
pub fn is_static(path: &str) -> bool {
    path == "static"
}

/// Guard helper pairing the decision with an error mapping.
pub fn ensure_not_tunnel(path: &str) -> Result<()> {
    if is_static(path) {
        Ok(())
    } else {
        Err(ServerError::FallbackError("tunnel path denied".to_string()))
    }
}

/// Generic static-server identity for the fallback response header. Any
/// tunnel-specific string here would reveal the decoy on every probe.
pub const SERVER_IDENTITY: &str = "static-httpd/1.0";

/// Canonical reference static response head — the byte shape locked by
/// `server/tests/fallback_shape.rs`: status, Server, Date, Content-Length,
/// Content-Type, Connection: close, in exactly this order.
pub fn static_head(body_len: usize) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nServer: {SERVER_IDENTITY}\r\nDate: {}\r\nContent-Length: {body_len}\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n",
        imf_fixdate_now()
    )
}

/// Current wall clock as RFC 7231 IMF-fixdate: "Mon, 19 Oct 2026 12:34:56 GMT".
fn imf_fixdate_now() -> String {
    // Clamp at epoch: a clock before 1970 degrades to the epoch itself
    // instead of panicking or emitting negative components.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    imf_fixdate(secs)
}

/// Epoch seconds → IMF-fixdate string.
fn imf_fixdate(secs: i64) -> String {
    const WDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = secs / 86_400;
    let sod = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    let wday = ((days + 4) % 7) as usize; // 1970-01-01 = Thursday (index 4)
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        WDAYS[wday],
        d,
        MONTHS[(m - 1) as usize],
        y,
        sod / 3_600,
        (sod % 3_600) / 60,
        sod % 60
    )
}

/// Days since 1970-01-01 → civil (year, month 1-12, day 1-31);
/// Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (y + i64::from(m <= 2), m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imf_fixdate_epoch_is_canonical() {
        assert_eq!(imf_fixdate(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn imf_fixdate_matches_known_histories() {
        // 2026-10-19 was a Monday; 2024-02-29 (leap) a Thursday;
        // both markers cross-check the civil calendar conversion.
        assert_eq!(
            imf_fixdate(20_745 * 86_400),
            "Mon, 19 Oct 2026 00:00:00 GMT"
        );
        assert_eq!(
            imf_fixdate(19_782 * 86_400),
            "Thu, 29 Feb 2024 00:00:00 GMT"
        );
    }

    #[test]
    fn static_head_carries_canonical_shape() {
        // Date value is wall-clock; compare the deterministic prefix
        // (status, Server) and tail (Content-Length onward) separately.
        let head = static_head(45);
        let prefix = "HTTP/1.1 200 OK\r\nServer: static-httpd/1.0\r\n";
        let rest = head
            .strip_prefix(prefix)
            .expect("head must start with canonical prefix");
        assert!(rest.starts_with("Date: "), "head: {head}");
        assert!(
            head.ends_with(
                "\r\nContent-Length: 45\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n"
            ),
            "head: {head}"
        );
    }
}
