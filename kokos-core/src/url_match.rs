//! Domain matching for the browser interface. Strict eTLD+1
//! equality via the compiled-in public-suffix list — never a
//! "last two labels" heuristic, which would merge `a.co.uk` with `b.co.uk`
//! and split nothing under `github.io`.
//!
//! No URL crate: the input is one field value or one browser-supplied URL, so
//! a small hand-rolled host extractor keeps kokos-core's dependency surface
//! flat. It is deliberately strict — anything it cannot read is `None`, and
//! the caller answers `invalid_url`.

/// Lowercased host with scheme, userinfo, port, path, query and fragment
/// stripped. A port must be empty or decimal `0..=65535`, else `None`. Both `/` and `\` terminate the authority (WHATWG "special
/// scheme" rule: real browsers treat a backslash exactly like a forward
/// slash for http(s)/ws(s) authorities), so a backslash-obfuscated authority
/// cannot be smuggled through as userinfo. IPv6 literals keep their brackets
/// so they never look like labels; an unterminated `[...` literal (missing
/// `]`) yields `None` rather than a truncated, bogus host.
pub fn host_of(url: &str) -> Option<String> {
    let s = url.trim();
    if s.is_empty() || s.contains(char::is_whitespace) {
        return None;
    }
    let rest = match s.split_once("://") {
        Some((scheme, rest)) => {
            let scheme = scheme.to_ascii_lowercase();
            if scheme != "http" && scheme != "https" && scheme != "ws" && scheme != "wss" {
                return None;
            }
            rest
        }
        None => {
            if s.contains(':') && !s.starts_with('[') {
                return None;
            }
            s
        }
    };
    let authority = rest.split(['/', '\\', '?', '#']).next().unwrap_or("");
    let authority = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let (host, port) = if authority.starts_with('[') {
        match authority.find(']') {
            Some(end) => {
                let (h, after) = authority.split_at(end + 1);
                match after.strip_prefix(':') {
                    Some(p) => (h, p),
                    None if after.is_empty() => (h, ""),
                    None => return None,
                }
            }
            None => return None,
        }
    } else {
        authority.split_once(':').unwrap_or((authority, ""))
    };
    // An empty port (`host:`) is allowed; anything else must be a real port,
    // so `evil.com:x.example.com` cannot pass as `evil.com`.
    if !port.is_empty()
        && !(port.bytes().all(|b| b.is_ascii_digit()) && port.parse::<u32>().is_ok_and(|n| n <= 65535))
    {
        return None;
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host == "[]" {
        return None;
    }
    Some(host)
}

/// Registrable domain. An IP literal or a single-label host has no eTLD+1 —
/// those compare literally instead of being widened.
pub fn etld_plus_one(host: &str) -> Option<String> {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return None;
    }
    if h.starts_with('[') || h.chars().all(|c| c.is_ascii_digit() || c == '.') || !h.contains('.') {
        return Some(h);
    }
    match psl::domain_str(&h) {
        Some(d) => Some(d.to_ascii_lowercase()),
        None => Some(h),
    }
}

/// True when both inputs (URLs or bare hosts) resolve to the same eTLD+1.
pub fn same_site(a: &str, b: &str) -> bool {
    let (Some(ha), Some(hb)) = (host_of(a), host_of(b)) else {
        return false;
    };
    match (etld_plus_one(&ha), etld_plus_one(&hb)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_hosts_from_real_urls() {
        assert_eq!(
            host_of("https://login.example.com/path?q=1#f").unwrap(),
            "login.example.com"
        );
        assert_eq!(
            host_of("http://user:pw@Example.COM:8443/x").unwrap(),
            "example.com"
        );
        assert_eq!(
            host_of("example.com").unwrap(),
            "example.com",
            "a bare host is accepted"
        );
        assert_eq!(host_of("https://[::1]:8080/x").unwrap(), "[::1]");
        assert_eq!(
            host_of("https://example.com.").unwrap(),
            "example.com",
            "trailing root dot dropped"
        );
    }

    #[test]
    fn rejects_hostless_input() {
        for bad in [
            "",
            "   ",
            "https://",
            "file:///Users/x/secrets.txt",
            "about:blank",
            "not a url",
        ] {
            assert!(host_of(bad).is_none(), "{bad:?} must not yield a host");
        }
    }

    #[test]
    fn etld_plus_one_uses_the_public_suffix_list() {
        assert_eq!(
            etld_plus_one("login.example.co.uk").unwrap(),
            "example.co.uk"
        );
        assert_eq!(etld_plus_one("example.com").unwrap(), "example.com");
        assert_eq!(etld_plus_one("a.b.c.example.com").unwrap(), "example.com");
        assert_eq!(
            etld_plus_one("myapp.github.io").unwrap(),
            "myapp.github.io",
            "github.io is a public suffix"
        );
    }

    #[test]
    fn ip_and_single_label_hosts_compare_literally() {
        assert_eq!(etld_plus_one("127.0.0.1").unwrap(), "127.0.0.1");
        assert_eq!(etld_plus_one("[::1]").unwrap(), "[::1]");
        assert_eq!(etld_plus_one("localhost").unwrap(), "localhost");
    }

    #[test]
    fn treats_backslash_as_an_authority_separator() {
        assert_eq!(
            host_of("https://evil.com\\@example.com/").unwrap(),
            "evil.com",
            "backslash terminates the authority before the fake userinfo"
        );
        assert!(!same_site(
            "https://evil.com\\@example.com/",
            "https://example.com"
        ));
        assert!(same_site(
            "https://evil.com\\@example.com/",
            "https://evil.com"
        ));
        assert_eq!(
            host_of("https://example.com\\path").unwrap(),
            "example.com",
            "backslash before the path with no userinfo"
        );
    }

    #[test]
    fn rejects_an_unterminated_ipv6_bracket() {
        assert!(
            host_of("https://[::1/x").is_none(),
            "missing closing ']' must not fall through to a bogus host"
        );
        assert_eq!(
            host_of("https://[::1]:8080/x").unwrap(),
            "[::1]",
            "a properly terminated IPv6 literal still works"
        );
    }

    #[test]
    fn rejects_a_non_numeric_or_out_of_range_port() {
        for bad in [
            "https://example.com:bogus",
            "https://evil.com:x.example.com/",
            "https://example.com:65536",
            "https://example.com:99999999999999999999",
            "https://example.com:+80",
            "https://example.com:80:80",
            "https://[::1]:bogus/x",
            "https://[::1]x",
            "https://[::1]:65536",
        ] {
            assert!(host_of(bad).is_none(), "{bad:?} must not yield a host");
        }
        assert!(!same_site("https://evil.com:x.example.com/", "https://evil.com"));
    }

    #[test]
    fn accepts_empty_or_valid_ports() {
        assert_eq!(host_of("https://example.com:/x").unwrap(), "example.com");
        assert_eq!(host_of("https://example.com:0").unwrap(), "example.com");
        assert_eq!(host_of("https://example.com:65535").unwrap(), "example.com");
        assert_eq!(host_of("https://[::1]:").unwrap(), "[::1]");
        assert_eq!(host_of("https://[::1]").unwrap(), "[::1]");
    }

    #[test]
    fn same_site_is_etld_plus_one_equality() {
        assert!(same_site(
            "https://login.example.com/a",
            "https://example.com"
        ));
        assert!(same_site(
            "https://shop.example.co.uk",
            "https://www.example.co.uk/x"
        ));
        assert!(!same_site(
            "https://evil.com/example.com",
            "https://example.com"
        ));
        assert!(
            !same_site("https://a.github.io", "https://b.github.io"),
            "separate sites under a public suffix"
        );
        assert!(!same_site("https://example.com", "garbage"));
    }
}
