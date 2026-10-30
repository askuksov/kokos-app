//! Who launched us. The browser — not the extension — supplies these
//! arguments, which is why they can serve as the whitelist key:
//!   Chrome:  kokos-nmh chrome-extension://<id>/
//!   Firefox: kokos-nmh <path/to/manifest.json> <extension-id>
//! An unrecognised shape yields None; the app then refuses every action
//! rather than guessing an identity.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Browser {
    Chrome,
    Firefox,
}

impl Browser {
    pub fn as_str(self) -> &'static str {
        match self {
            Browser::Chrome => "chrome",
            Browser::Firefox => "firefox",
        }
    }

    /// Inverse of `as_str`, for rebuilding a `Caller` from a `hello` frame.
    /// Unknown input yields `None` — the app then refuses the connection
    /// rather than guessing an identity (fail closed).
    pub fn from_name(s: &str) -> Option<Browser> {
        match s.trim().to_ascii_lowercase().as_str() {
            "chrome" => Some(Browser::Chrome),
            "firefox" => Some(Browser::Firefox),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub browser: Browser,
    pub origin: String,
}

const CHROME_PREFIX: &str = "chrome-extension://";

pub fn from_args(args: &[String]) -> Option<Caller> {
    if let Some(raw) = args.iter().find(|a| a.starts_with(CHROME_PREFIX)) {
        let rest = &raw[CHROME_PREFIX.len()..];
        let id = rest.split(['/', '?', '#']).next().unwrap_or("");
        if id.is_empty() {
            return None;
        }
        return Some(Caller {
            browser: Browser::Chrome,
            origin: format!("{CHROME_PREFIX}{id}/"),
        });
    }
    let manifest_at = args.iter().position(|a| a.ends_with(".json"))?;
    let id = args.get(manifest_at + 1)?;
    if id.is_empty() {
        return None;
    }
    Some(Caller {
        browser: Browser::Firefox,
        origin: id.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn chrome_origin_argument() {
        let c = from_args(&args(&[
            "/path/kokos-nmh",
            "chrome-extension://abcdefghijklmnop/",
        ]))
        .unwrap();
        assert_eq!(c.browser.as_str(), "chrome");
        assert_eq!(c.origin, "chrome-extension://abcdefghijklmnop/");
    }

    #[test]
    fn chrome_origin_is_normalised_to_a_trailing_slash() {
        let c = from_args(&args(&[
            "/path/kokos-nmh",
            "chrome-extension://abcdefghijklmnop",
        ]))
        .unwrap();
        assert_eq!(
            c.origin, "chrome-extension://abcdefghijklmnop/",
            "whitelist compare must not hinge on the slash"
        );
    }

    #[test]
    fn firefox_manifest_path_then_extension_id() {
        let c = from_args(&args(&[
            "/path/kokos-nmh",
            "/Users/x/Library/Application Support/Mozilla/NativeMessagingHosts/dev.kuksov.kokos.json",
            "kokos@example.org",
        ]))
        .unwrap();
        assert_eq!(c.browser.as_str(), "firefox");
        assert_eq!(c.origin, "kokos@example.org");
    }

    #[test]
    fn firefox_extension_id_carries_case_through_verbatim() {
        let c = from_args(&args(&[
            "/path/kokos-nmh",
            "/p/host.json",
            "Kokos-Stub@Example.ORG",
        ]))
        .unwrap();
        assert_eq!(c.origin, "Kokos-Stub@Example.ORG");
    }

    #[test]
    fn firefox_brace_style_extension_id() {
        let c = from_args(&args(&[
            "/p/kokos-nmh",
            "/p/host.json",
            "{d4a1f2c0-0000-4000-8000-abcdefabcdef}",
        ]))
        .unwrap();
        assert_eq!(c.browser.as_str(), "firefox");
        assert_eq!(c.origin, "{d4a1f2c0-0000-4000-8000-abcdefabcdef}");
    }

    #[test]
    fn no_recognisable_caller() {
        assert!(
            from_args(&args(&["/path/kokos-nmh"])).is_none(),
            "bare launch by a user/attacker"
        );
        assert!(from_args(&args(&["/path/kokos-nmh", "--help"])).is_none());
        assert!(
            from_args(&args(&["/p/kokos-nmh", "/p/host.json"])).is_none(),
            "manifest path without an id"
        );
    }

    #[test]
    fn browser_as_str_is_exact() {
        assert_eq!(Browser::Chrome.as_str(), "chrome");
        assert_eq!(Browser::Firefox.as_str(), "firefox");
    }

    #[test]
    fn chrome_origin_normalisation_is_idempotent() {
        let c1 = from_args(&args(&["kokos-nmh", "chrome-extension://abc/"])).unwrap();
        let c2 = from_args(&args(&["kokos-nmh", "chrome-extension://abc/"])).unwrap();
        assert_eq!(c1.origin, c2.origin);
        assert_eq!(c1.origin, "chrome-extension://abc/");
    }

    #[test]
    fn chrome_origin_handles_doubled_trailing_slash() {
        let c = from_args(&args(&["kokos-nmh", "chrome-extension://abc//"])).unwrap();
        assert_eq!(
            c.origin, "chrome-extension://abc/",
            "doubled slash is normalised to single"
        );
    }

    #[test]
    fn firefox_resolves_first_json_argument() {
        let c = from_args(&args(&[
            "/p/kokos-nmh",
            "/p/first.json",
            "the-id",
            "/p/second.json",
            "wrong-id",
        ]))
        .unwrap();
        assert_eq!(c.browser.as_str(), "firefox");
        assert_eq!(
            c.origin, "the-id",
            "extension id is the arg immediately after first .json"
        );
    }

    #[test]
    fn from_name_round_trips_with_as_str_for_both_variants() {
        for b in [Browser::Chrome, Browser::Firefox] {
            assert_eq!(Browser::from_name(b.as_str()), Some(b));
        }
    }

    #[test]
    fn from_name_is_trimmed_and_case_insensitive() {
        assert_eq!(Browser::from_name("Chrome "), Some(Browser::Chrome));
        assert_eq!(Browser::from_name(" FIREFOX"), Some(Browser::Firefox));
    }

    #[test]
    fn from_name_rejects_unknown_empty_and_url_forms() {
        assert_eq!(Browser::from_name(""), None);
        assert_eq!(Browser::from_name("safari"), None);
        assert_eq!(
            Browser::from_name("chrome-extension://x/"),
            None,
            "from_name takes a browser name, not an origin"
        );
    }

    #[test]
    fn chrome_origin_strips_trailing_path() {
        let c = from_args(&args(&["kokos-nmh", "chrome-extension://abc/popup.html"])).unwrap();
        assert_eq!(c.origin, "chrome-extension://abc/");
    }

    #[test]
    fn chrome_origin_strips_trailing_query() {
        let c = from_args(&args(&[
            "kokos-nmh",
            "chrome-extension://abc/popup.html?x=1",
        ]))
        .unwrap();
        assert_eq!(c.origin, "chrome-extension://abc/");
    }

    #[test]
    fn chrome_origin_strips_trailing_fragment() {
        let c = from_args(&args(&["kokos-nmh", "chrome-extension://abc#frag"])).unwrap();
        assert_eq!(c.origin, "chrome-extension://abc/");
    }

    #[test]
    fn chrome_origin_empty_id_is_none() {
        assert!(
            from_args(&args(&["kokos-nmh", "chrome-extension://"])).is_none(),
            "bare prefix has no extension id"
        );
        assert!(
            from_args(&args(&["kokos-nmh", "chrome-extension:///"])).is_none(),
            "triple slash still has no extension id"
        );
    }
}
