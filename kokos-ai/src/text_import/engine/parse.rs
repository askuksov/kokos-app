//! Tolerant parser for the model's raw output. Extracts the outermost JSON array
//! and hand-builds `RawEntryDraft`s, dropping any malformed field/entry instead
//! of failing the whole parse or panicking. The locator + `integrity::validate`
//! are the safety net downstream — a lenient parse never weakens the invariant.

use serde_json::Value;

use crate::text_import::engine::extractor::{RawEntryDraft, RawFieldDraft};
use crate::text_import::model::{EntryKind, FieldType};

/// Parse the model's response into entry drafts. Returns `Vec::new()` for
/// non-JSON or a shape it cannot use — never panics.
pub fn parse_drafts(raw: &str) -> Vec<RawEntryDraft> {
    let slice = match outer_array(raw) {
        Some(s) => s,
        None => return Vec::new(),
    };
    match serde_json::from_str::<Vec<Value>>(slice) {
        Ok(arr) => arr.iter().filter_map(entry_from_value).collect(),
        Err(_) => salvage(slice),
    }
}

/// Fallback for a reply that is not valid JSON as a whole — a small model often
/// gets one bracket wrong in an otherwise good array, and a strict parse would
/// throw every entry away with it. Rebuilds entries from the pieces that still
/// parse: each brace-balanced object with no nested object is a field, and a
/// `"title"`/`"kind"` key in the text between them opens the next entry.
/// Entries left without a single field are dropped.
fn salvage(slice: &str) -> Vec<RawEntryDraft> {
    let mut out = Vec::new();
    let mut cur = SalvagedEntry::default();
    let mut gap_start = 0;
    let mut open_header = |cur: &mut SalvagedEntry, key: &'static str, value: Value| {
        if !cur.fields.is_empty() || cur.has(key) {
            out.extend(std::mem::take(cur).finish());
        }
        cur.set(key, value);
    };
    for (start, end) in leaf_objects(slice) {
        for (key, value) in header_keys(&slice[gap_start..start]) {
            open_header(&mut cur, key, value);
        }
        gap_start = end;
        let Ok(v) = serde_json::from_str::<Value>(&slice[start..end]) else { continue };
        if let Some(f) = field_from_value(&v) {
            cur.fields.push(f);
        } else if let Some(obj) = v.as_object() {
            // An entry with an empty `fields` array has no nested object, so it
            // is a leaf itself; its keys still mark an entry boundary.
            for key in ["title", "kind"] {
                if let Some(value) = obj.get(key) {
                    open_header(&mut cur, key, value.clone());
                }
            }
        }
    }
    out.extend(cur.finish());
    out
}

#[derive(Default)]
struct SalvagedEntry {
    title: Option<Value>,
    kind: Option<Value>,
    fields: Vec<RawFieldDraft>,
}

impl SalvagedEntry {
    fn has(&self, key: &str) -> bool {
        match key {
            "title" => self.title.is_some(),
            _ => self.kind.is_some(),
        }
    }

    fn set(&mut self, key: &str, value: Value) {
        match key {
            "title" => self.title = Some(value),
            _ => self.kind = Some(value),
        }
    }

    fn finish(self) -> Option<RawEntryDraft> {
        if self.fields.is_empty() {
            return None;
        }
        let mut obj = serde_json::Map::new();
        obj.extend(self.title.map(|t| ("title".to_string(), t)));
        obj.extend(self.kind.map(|k| ("kind".to_string(), k)));
        let mut draft = entry_from_value(&Value::Object(obj))?;
        draft.fields = self.fields;
        Some(draft)
    }
}

/// Byte ranges of `{…}` objects that contain no nested `{`, skipping braces
/// inside JSON strings. Unbalanced closers are ignored rather than trusted.
fn leaf_objects(s: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut open: Option<usize> = None;
    let mut in_str = false;
    let mut escaped = false;
    for (i, b) in s.bytes().enumerate() {
        if in_str {
            match b {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_str = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'{' => open = Some(i),
            b'}' => {
                if let Some(start) = open.take() {
                    out.push((start, i + 1));
                }
            }
            _ => {}
        }
    }
    out
}

/// `"title": …` / `"kind": …` pairs in source order, values parsed as JSON.
fn header_keys(gap: &str) -> Vec<(&'static str, Value)> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r#""(title|kind)"\s*:\s*("(?:[^"\\]|\\.)*"|null)"#).unwrap()
    });
    re.captures_iter(gap)
        .filter_map(|c| {
            let key = if &c[1] == "title" { "title" } else { "kind" };
            serde_json::from_str(&c[2]).ok().map(|v| (key, v))
        })
        .collect()
}

/// The substring from the first `[` to the last `]` inclusive, if both exist.
fn outer_array(raw: &str) -> Option<&str> {
    let start = raw.find('[')?;
    let end = raw.rfind(']')?;
    if end > start {
        Some(&raw[start..=end])
    } else {
        None
    }
}

fn entry_from_value(v: &Value) -> Option<RawEntryDraft> {
    let obj = v.as_object()?;
    let kind = obj
        .get("kind")
        .and_then(|k| serde_json::from_value::<EntryKind>(k.clone()).ok())
        .unwrap_or(EntryKind::SecureNote);
    let title = obj.get("title").and_then(|t| t.as_str()).map(str::to_string);
    let fields = obj
        .get("fields")
        .and_then(Value::as_array)
        .map(|fs| fs.iter().filter_map(field_from_value).collect())
        .unwrap_or_default();
    Some(RawEntryDraft { title, kind, fields })
}

fn field_from_value(v: &Value) -> Option<RawFieldDraft> {
    let obj = v.as_object()?;
    let field_type: FieldType = obj
        .get("fieldType")
        .and_then(|t| serde_json::from_value::<FieldType>(t.clone()).ok())?;
    let verbatim_text = obj.get("verbatimText").and_then(|t| t.as_str())?.to_string();
    if verbatim_text.is_empty() {
        return None;
    }
    Some(RawFieldDraft { field_type, verbatim_text })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text_import::model::{EntryKind, FieldType};

    #[test]
    fn parses_a_clean_array() {
        let raw = r#"[{"title":"GH","kind":"login","fields":[{"fieldType":"password","verbatimText":"pw"}]}]"#;
        let d = parse_drafts(raw);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].fields[0].field_type, FieldType::Password);
    }

    #[test]
    fn tolerates_prose_around_the_json() {
        let raw = "Sure! Here is the JSON:\n[{\"kind\":\"apiKey\",\"fields\":[{\"fieldType\":\"apiKey\",\"verbatimText\":\"sk-1\"}]}]\nHope that helps.";
        let d = parse_drafts(raw);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, EntryKind::ApiKey);
        assert_eq!(d[0].fields[0].verbatim_text, "sk-1");
    }

    #[test]
    fn drops_a_malformed_field_but_keeps_the_valid_one() {
        let raw = r#"[{"kind":"login","fields":[{"fieldType":"nonsense","verbatimText":"x"},{"fieldType":"login","verbatimText":"bob"}]}]"#;
        let d = parse_drafts(raw);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].fields.len(), 1);
        assert_eq!(d[0].fields[0].field_type, FieldType::Login);
    }

    #[test]
    fn parses_wifi_kind() {
        let raw = r#"[{"title":"Home wifi","kind":"wifi","fields":[{"fieldType":"password","verbatimText":"sunflower-42-orange"}]}]"#;
        let d = parse_drafts(raw);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, EntryKind::Wifi);
    }

    #[test]
    fn keeps_the_ssid_field() {
        let raw = r#"[{"title":"Домашний роутер","kind":"wifi","fields":[{"fieldType":"ssid","verbatimText":"Kovalenko_5G"},{"fieldType":"password","verbatimText":"kiwi-lamp-7731"}]}]"#;
        let d = parse_drafts(raw);
        assert_eq!(d.len(), 1);
        let got: Vec<_> = d[0].fields.iter().map(|f| (f.field_type, f.verbatim_text.as_str())).collect();
        assert_eq!(got, vec![(FieldType::Ssid, "Kovalenko_5G"), (FieldType::Password, "kiwi-lamp-7731")]);
    }

    /// Real Qwen2.5-1.5B output (a real-world test file, trimmed): the second entry
    /// closes its `fields` array with `}` instead of `]`. One slip must not cost
    /// the entries around it.
    #[test]
    fn one_malformed_entry_does_not_discard_the_others() {
        let raw = r#"```json
[
    {
        "title": "GitHub",
        "kind": "login",
        "fields": [
            {"fieldType": "login", "verbatimText": "jane.doe@example.com"}
        ]
    },
    {
        "title": "Сбербанк онлайн",
        "kind": "login",
        "fields": [
            {"fieldType": "login", "verbatimText": "ivan_petrov"},
            {"fieldType": "password", "verbatimText": "Zx9!mQ2#vL"}
        },
        {
            "fieldType": "phone",
            "verbatimText": "+380 67 123 45 67"
        }
    },
    {
        "title": "Google 2FA",
        "kind": "login",
        "fields": [
            {"fieldType": "password", "verbatimText": "correct-battery-staple"},
            {"fieldType": "totpSecret", "verbatimText": "JBSWY3DPEHPK3PXP"}
        ]
    }
]
```"#;
        let d = parse_drafts(raw);
        let titles: Vec<_> = d.iter().map(|e| e.title.as_deref().unwrap_or("")).collect();
        assert_eq!(titles, ["GitHub", "Сбербанк онлайн", "Google 2FA"], "got {d:?}");
        let bank: Vec<_> = d[1].fields.iter().map(|f| (f.field_type, f.verbatim_text.as_str())).collect();
        assert_eq!(
            bank,
            [
                (FieldType::Login, "ivan_petrov"),
                (FieldType::Password, "Zx9!mQ2#vL"),
                (FieldType::Phone, "+380 67 123 45 67"),
            ]
        );
        assert_eq!(d[2].fields.len(), 2);
    }

    #[test]
    fn salvage_keeps_braces_inside_strings_and_skips_fieldless_entries() {
        let raw = r#"[{"title":"A","kind":"login","fields":[{"fieldType":"password","verbatimText":"p{w}["}},
            {"title":"B","kind":"login","fields":[]}]"#;
        let d = parse_drafts(raw);
        assert_eq!(d.len(), 1, "got {d:?}");
        assert_eq!(d[0].fields[0].verbatim_text, "p{w}[");
    }

    #[test]
    fn non_json_returns_empty_not_panic() {
        assert!(parse_drafts("I refuse to answer.").is_empty());
        assert!(parse_drafts("").is_empty());
    }
}
