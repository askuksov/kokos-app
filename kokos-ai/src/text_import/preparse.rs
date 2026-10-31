//! Heuristic pre-parser: the deterministic floor under the AI import. Splits a
//! file into blank-line blocks and extracts high-confidence typed field hints by
//! regex. Everything here is precise-or-nothing; the ambiguous remainder is left
//! for the LLM and, ultimately, the mandatory review-UI.

use crate::text_import::model::{EntryKind, FieldType, RawEntry, RawField, RawProposal, Span};
use regex::Regex;
use std::sync::OnceLock;

/// Split `text` into byte spans of blank-line-separated blocks. A "blank line"
/// is a line that is empty or whitespace-only; one or more of them separate
/// blocks. Leading/trailing whitespace is trimmed out of each returned span, and
/// whitespace-only blocks are dropped.
pub fn split_blocks(text: &str) -> Vec<Span> {
    let mut blocks = Vec::new();
    let mut cur_start: Option<usize> = None;
    let mut cur_end = 0usize;

    for (line, span) in line_spans(text) {
        if line.trim().is_empty() {
            if let Some(start) = cur_start.take() {
                blocks.push(Span { start, end: cur_end });
            }
        } else {
            let lead = line.len() - line.trim_start().len();
            let trimmed_start = span.start + lead;
            let trimmed_end = span.start + line.trim_end().len();
            if cur_start.is_none() {
                cur_start = Some(trimmed_start);
            }
            cur_end = trimmed_end;
        }
    }
    if let Some(start) = cur_start.take() {
        blocks.push(Span { start, end: cur_end });
    }
    blocks
}

/// Iterate `(line_without_newline, span_of_line_incl_content)` over `text`,
/// tracking byte offsets. The span covers the line's bytes, not the `\n`.
fn line_spans(text: &str) -> Vec<(&str, Span)> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for (i, b) in text.bytes().enumerate() {
        if b == b'\n' {
            out.push((&text[start..i], Span { start, end: i }));
            start = i + 1;
        }
    }
    if start <= text.len() && start != text.len() {
        out.push((&text[start..], Span { start, end: text.len() }));
    } else if start == 0 && !text.is_empty() {
        out.push((text, Span { start: 0, end: text.len() }));
    }
    out
}

fn url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"https?://[^\s]+").unwrap())
}
fn otpauth_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"otpauth://[^\s]+").unwrap())
}
fn email_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap())
}
/// A `key: value` or `key = value` line. Group 1 = key, group 2 = value.
fn kv_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^[ \t]*(\p{L}[\w .\-]*?)[ \t]*[:=][ \t]*(\S.*?)[ \t]*$").unwrap())
}
/// Standalone base32 run (>= 16 chars) — a likely TOTP secret. Precise-or-drop.
fn base32_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b[A-Z2-7]{16,}\b").unwrap())
}

/// Map a `key:value` key name to a field type. Case-insensitive substring match;
/// order matters (check `email` before `login`, `answer`/`question` before the
/// generic buckets, and the network-name bucket last so "wifi password" stays a
/// password). Returns `None` for unrecognized keys (the value becomes a
/// note candidate at higher layers).
pub fn classify_key(key: &str) -> Option<FieldType> {
    let k = key.trim().to_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| k.contains(n));
    // Cyrillic needles cover Russian and Ukrainian. The bare abbreviation "тел"
    // is matched whole: as a substring it would also claim "телеграм".
    if has(&["question", "вопрос", "питання"]) {
        Some(FieldType::SecurityQuestion)
    } else if has(&["answer", "ответ", "відповідь"]) {
        Some(FieldType::SecurityAnswer)
    } else if has(&["phone", "mobile", "телефон", "мобил", "мобіл"]) || k == "тел" || k == "тел." {
        Some(FieldType::Phone)
    } else if has(&["2fa", "totp", "otp", "secret", "секрет"]) {
        Some(FieldType::TotpSecret)
    } else if has(&["api", "token", "токен"]) || (k.contains("key") && !k.contains("keyword")) {
        Some(FieldType::ApiKey)
    } else if has(&["mail", "почта", "пошта"]) {
        Some(FieldType::Email)
    } else if has(&["pass", "pwd", "pw", "пароль"]) {
        Some(FieldType::Password)
    } else if has(&["login", "user", "логин", "логін", "пользовател", "користувач"]) {
        Some(FieldType::Login)
    } else if has(&["ssid", "wifi", "wi-fi", "wlan", "network", "сеть", "сети", "мережа", "мережі"])
        && !has(&["соцсет", "соцмереж"])
    {
        Some(FieldType::Ssid)
    } else {
        None
    }
}

/// Extract high-confidence typed field hints from `text`. Every hint's span is a
/// byte range into `text`; heuristic hints never set `echoed_value`.
pub fn extract_hints(text: &str) -> Vec<RawField> {
    let mut hints = Vec::new();
    let push = |hints: &mut Vec<RawField>, ft: FieldType, s: usize, e: usize, c: f32| {
        hints.push(RawField { field_type: ft, span: Span { start: s, end: e }, echoed_value: None, confidence: c });
    };

    for m in otpauth_re().find_iter(text) {
        push(&mut hints, FieldType::TotpSecret, m.start(), m.end(), 1.0);
    }
    for m in url_re().find_iter(text) {
        push(&mut hints, FieldType::Url, m.start(), m.end(), 1.0);
    }
    for m in email_re().find_iter(text) {
        push(&mut hints, FieldType::Email, m.start(), m.end(), 0.9);
    }
    for m in base32_re().find_iter(text) {
        push(&mut hints, FieldType::TotpSecret, m.start(), m.end(), 0.6);
    }
    for caps in kv_re().captures_iter(text) {
        let key = caps.get(1).unwrap().as_str();
        let val = caps.get(2).unwrap();
        if let Some(ft) = classify_key(key) {
            push(&mut hints, ft, val.start(), val.end(), 0.85);
        }
    }
    // One span, one hint: a labelled base32 secret matches both the base32 and
    // the `key: value` rule, and an e-mail under `user:` matches email + login.
    // Keep the most confident reading so the floor never shows a value twice.
    hints.sort_by(|a, b| {
        (a.span.start, a.span.end)
            .cmp(&(b.span.start, b.span.end))
            .then(b.confidence.total_cmp(&a.confidence))
    });
    hints.dedup_by(|b, a| a.span == b.span);
    hints
}

/// Upper bound on entries one `pre_parse` call returns, so a pathological input
/// (4 MiB of one-line blocks) cannot allocate unbounded entries. Deliberately
/// above the app's per-file cap (500): the app still counts and reports what it
/// drops below this ceiling.
const MAX_PRE_PARSE_ENTRIES: usize = 2000;

/// Turn a whole file into a raw proposal: one `RawEntry` per blank-line block,
/// each carrying the hints whose span falls inside that block. `kind` is
/// inferred from the field mix; `title` is derived from a URL/domain hint.
pub fn pre_parse(text: &str) -> RawProposal {
    let all = extract_hints(text);
    let mut entries = Vec::new();
    for block in split_blocks(text) {
        if entries.len() >= MAX_PRE_PARSE_ENTRIES {
            break;
        }
        let fields: Vec<RawField> = all
            .iter()
            .filter(|h| h.span.start >= block.start && h.span.end <= block.end)
            .cloned()
            .collect();
        if fields.is_empty() {
            continue;
        }
        let kind = infer_kind(&fields, &text[block.start..block.end]);
        let title = fields
            .iter()
            .find(|f| f.field_type == FieldType::Url)
            .map(|f| domain_of(&text[f.span.start..f.span.end]));
        entries.push(RawEntry { title, kind, fields });
    }
    RawProposal { entries }
}

fn infer_kind(fields: &[RawField], block: &str) -> EntryKind {
    let has = |ft: FieldType| fields.iter().any(|f| f.field_type == ft);
    // A wireless block ("Home wifi" / ssid + key) carries a secret but no
    // identity: without this arm it would read as a bare API key. The marker
    // requirement keeps ordinary logins out — they name a user or a URL. A
    // labelled network name is marker enough, even for an open network.
    let wireless =
        has(FieldType::Ssid) || (is_wifi_block(block) && (has(FieldType::Password) || has(FieldType::ApiKey)));
    if wireless
        && !has(FieldType::Login)
        && !has(FieldType::Email)
        && !has(FieldType::Url)
        && !has(FieldType::TotpSecret)
    {
        EntryKind::Wifi
    } else if has(FieldType::Password) || has(FieldType::Login) {
        EntryKind::Login
    } else if has(FieldType::ApiKey) {
        EntryKind::ApiKey
    } else if has(FieldType::TotpSecret) {
        EntryKind::Totp
    } else {
        EntryKind::SecureNote
    }
}

/// Lowercased-substring markers of a wireless-network block.
fn is_wifi_block(block: &str) -> bool {
    let b = block.to_ascii_lowercase();
    [
        "ssid",
        "wifi",
        "wi-fi",
        "wlan",
        "wireless",
        "wpa",
        "wep",
        "passphrase",
        "network name",
        "network:",
    ]
    .iter()
    .any(|m| b.contains(m))
}

/// Best-effort host extraction for a title. Not security-sensitive (a title is
/// not a secret value), so a plain string result is fine here.
fn domain_of(url: &str) -> String {
    let no_scheme = url.split("://").nth(1).unwrap_or(url);
    let host = no_scheme.split(['/', '?', '#']).next().unwrap_or(no_scheme);
    host.trim_start_matches("www.").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slice<'a>(text: &'a str, s: &Span) -> &'a str {
        &text[s.start..s.end]
    }

    fn value_of<'a>(text: &'a str, f: &RawField) -> &'a str {
        &text[f.span.start..f.span.end]
    }

    #[test]
    fn classify_key_recognizes_pw_abbreviation() {
        assert_eq!(classify_key("pw"), Some(FieldType::Password));
        assert_eq!(classify_key("PW"), Some(FieldType::Password));
        assert_eq!(classify_key("random note"), None);
    }

    #[test]
    fn classify_key_maps_phone_labels() {
        assert_eq!(classify_key("phone"), Some(FieldType::Phone));
        assert_eq!(classify_key("Mobile number"), Some(FieldType::Phone));
        assert_eq!(classify_key("telegram"), None);
    }

    #[test]
    fn classify_key_maps_russian_and_ukrainian_labels() {
        for (key, ft) in [
            ("пароль", FieldType::Password),
            ("Пароль от почты", FieldType::Password),
            ("логин", FieldType::Login),
            ("логін", FieldType::Login),
            ("Пользователь", FieldType::Login),
            ("користувач", FieldType::Login),
            ("тел", FieldType::Phone),
            ("тел.", FieldType::Phone),
            ("Телефон", FieldType::Phone),
            ("почта", FieldType::Email),
            ("пошта", FieldType::Email),
            ("секретный вопрос", FieldType::SecurityQuestion),
            ("ответ", FieldType::SecurityAnswer),
            ("відповідь", FieldType::SecurityAnswer),
        ] {
            assert_eq!(classify_key(key), Some(ft), "key {key:?}");
        }
        assert_eq!(classify_key("телеграм"), None);
        assert_eq!(classify_key("заметка"), None);
    }

    #[test]
    fn classify_key_maps_network_name_labels() {
        for key in ["ssid", "SSID", "wifi", "Wi-Fi", "network", "Network name", "wlan", "сеть", "имя сети", "мережа"] {
            assert_eq!(classify_key(key), Some(FieldType::Ssid), "key {key:?}");
        }
        for (key, ft) in [
            ("wifi password", FieldType::Password),
            ("пароль от wifi", FieldType::Password),
            ("network user", FieldType::Login),
        ] {
            assert_eq!(classify_key(key), Some(ft), "key {key:?}");
        }
        assert_eq!(classify_key("соцсеть"), None);
    }

    #[test]
    fn pre_parse_reads_a_wifi_block_as_ssid_and_password() {
        let text = "Домашний роутер\nwifi: Kovalenko_5G\nпароль: kiwi-lamp-7731";
        let p = pre_parse(text);
        assert_eq!(p.entries.len(), 1);
        let e = &p.entries[0];
        assert_eq!(e.kind, EntryKind::Wifi);
        for (ft, v) in [(FieldType::Ssid, "Kovalenko_5G"), (FieldType::Password, "kiwi-lamp-7731")] {
            assert!(
                e.fields.iter().any(|f| f.field_type == ft && value_of(text, f) == v),
                "{ft:?} = {v:?} missing from {e:?}"
            );
        }
    }

    #[test]
    fn open_network_with_only_an_ssid_is_still_wifi() {
        let p = pre_parse("Cafe\nnetwork: Cafe-Guest");
        assert_eq!(p.entries[0].kind, EntryKind::Wifi);
    }

    #[test]
    fn extract_hints_reads_cyrillic_keys() {
        let text = "логин: ivan_petrov\nпароль: Zx9!mQ2#vL\nтел: +380 67 123 45 67";
        let hints = extract_hints(text);
        for (ft, v) in [
            (FieldType::Login, "ivan_petrov"),
            (FieldType::Password, "Zx9!mQ2#vL"),
            (FieldType::Phone, "+380 67 123 45 67"),
        ] {
            assert!(
                hints.iter().any(|h| h.field_type == ft && value_of(text, h) == v),
                "{ft:?} = {v:?} missing from {hints:?}"
            );
        }
    }

    #[test]
    fn extract_hints_reports_each_span_once() {
        let text = "totp: JBSWY3DPEHPK3PXP\nuser: jane.doe@example.com";
        let hints = extract_hints(text);
        let mut spans: Vec<_> = hints.iter().map(|h| (h.span.start, h.span.end)).collect();
        spans.sort();
        let before = spans.len();
        spans.dedup();
        assert_eq!(before, spans.len(), "duplicate spans in {hints:?}");
    }

    #[test]
    fn classify_key_maps_common_names() {
        assert_eq!(classify_key("Login"), Some(FieldType::Login));
        assert_eq!(classify_key("username"), Some(FieldType::Login));
        assert_eq!(classify_key("Password"), Some(FieldType::Password));
        assert_eq!(classify_key("pwd"), Some(FieldType::Password));
        assert_eq!(classify_key("2FA secret"), Some(FieldType::TotpSecret));
        assert_eq!(classify_key("API key"), Some(FieldType::ApiKey));
        assert_eq!(classify_key("token"), Some(FieldType::ApiKey));
        assert_eq!(classify_key("Security question"), Some(FieldType::SecurityQuestion));
        assert_eq!(classify_key("answer"), Some(FieldType::SecurityAnswer));
        assert_eq!(classify_key("random note"), None);
    }

    #[test]
    fn extract_hints_finds_url_email_and_kv_value_spans() {
        let text = "site: https://github.com/login\nuser: octocat\npass: hunter2\nmail: me@x.com";
        let hints = extract_hints(text);
        let url = hints.iter().find(|h| h.field_type == FieldType::Url).unwrap();
        assert_eq!(value_of(text, url), "https://github.com/login");
        let pass = hints.iter().find(|h| h.field_type == FieldType::Password).unwrap();
        assert_eq!(value_of(text, pass), "hunter2");
        assert!(hints.iter().any(|h| h.field_type == FieldType::Email && value_of(text, h) == "me@x.com"));
    }

    #[test]
    fn extract_hints_detects_otpauth_and_labeled_totp() {
        let text = "2fa: JBSWY3DPEHPK3PXP\notp: otpauth://totp/x?secret=ABCD";
        let hints = extract_hints(text);
        let totp: Vec<_> = hints.iter().filter(|h| h.field_type == FieldType::TotpSecret).collect();
        assert!(totp.len() >= 2, "labeled base32 + otpauth both flagged, got {}", totp.len());
    }

    #[test]
    fn pre_parse_makes_one_entry_per_block_with_verbatim_spans() {
        let text = "site: github.com\nuser: octocat\npass: hunter2\n\nsite: gmail.com\nuser: me\npass: sesame";
        let proposal = pre_parse(text);
        assert_eq!(proposal.entries.len(), 2, "one entry per block");
        for e in &proposal.entries {
            for f in &e.fields {
                assert_eq!(&text[f.span.start..f.span.end], value_of(text, f));
                assert!(f.echoed_value.is_none(), "heuristic hints carry no echoed value");
            }
        }
        assert!(proposal.entries[0]
            .fields
            .iter()
            .any(|f| f.field_type == FieldType::Password && &text[f.span.start..f.span.end] == "hunter2"));
    }

    #[test]
    fn wifi_block_with_key_becomes_wifi_not_api_key() {
        let text = "Home wifi\nnetwork: Casa\nkey: sunflower-42-orange";
        let proposal = pre_parse(text);
        assert_eq!(proposal.entries.len(), 1);
        assert_eq!(proposal.entries[0].kind, EntryKind::Wifi);
    }

    #[test]
    fn login_block_with_user_and_url_stays_login() {
        let text = "Bank of Nowhere\nuser: anna_k\npassword: 7HdttQ9vvz\nhttps://bank.example.com";
        let proposal = pre_parse(text);
        assert_eq!(proposal.entries.len(), 1);
        assert_eq!(proposal.entries[0].kind, EntryKind::Login);
    }

    #[test]
    fn splits_on_blank_lines_and_trims() {
        let text = "site: github.com\nuser: octocat\n\n\nsite: gmail.com\nuser: me\n";
        let blocks = split_blocks(text);
        assert_eq!(blocks.len(), 2, "two blank-separated blocks");
        assert_eq!(slice(text, &blocks[0]), "site: github.com\nuser: octocat");
        assert_eq!(slice(text, &blocks[1]), "site: gmail.com\nuser: me");
    }

    #[test]
    fn single_block_when_no_blank_line() {
        let text = "just one line";
        let blocks = split_blocks(text);
        assert_eq!(blocks.len(), 1);
        assert_eq!(slice(text, &blocks[0]), "just one line");
    }

    #[test]
    fn empty_or_whitespace_only_yields_no_blocks() {
        assert!(split_blocks("").is_empty());
        assert!(split_blocks("\n\n   \n\t\n").is_empty());
    }

    #[test]
    fn spans_are_byte_offsets_over_unicode() {
        let text = "логин: юзер\n\nsite: x.com";
        let blocks = split_blocks(text);
        assert_eq!(blocks.len(), 2);
        assert_eq!(slice(text, &blocks[0]), "логин: юзер");
        assert_eq!(slice(text, &blocks[1]), "site: x.com");
    }
}
