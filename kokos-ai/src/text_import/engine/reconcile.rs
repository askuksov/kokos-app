//! Deterministic reconciliation: a pure relabel pass that fixes the systematic
//! misclassifications the generative extractor makes (a phone labeled TotpSecret;
//! a bare password labeled SecurityAnswer; a credential dump labeled SecureNote).
//! It changes `field_type` and `entry.kind` ONLY — it never reads-then-rewrites,
//! mutates, or logs a `value`, so `integrity::validate` stays the single value
//! chokepoint and the verbatim-span invariant is untouched.

use crate::text_import::model::{EntryKind, FieldType, ImportProposal};

/// True if `v` looks like a phone number: an optional single leading `+`, then
/// digits and common separators, 7..=15 total digits, and NO ascii letters. A
/// canonical base32 TOTP secret contains letters, so it never matches — that is
/// the point (a phone must never remain classified as TotpSecret).
fn looks_like_phone(v: &str) -> bool {
    let v = v.trim();
    let rest = v.strip_prefix('+').unwrap_or(v);
    if rest.is_empty() {
        return false;
    }
    let mut digits = 0usize;
    for c in rest.chars() {
        if c.is_ascii_digit() {
            digits += 1;
        } else if c.is_ascii_alphabetic() {
            return false;
        } else if !matches!(c, ' ' | '(' | ')' | '-' | '.') {
            return false;
        }
    }
    (7..=15).contains(&digits)
}

/// True if `v` plausibly IS a TOTP secret: an `otpauth://` URI, or a base32
/// secret (A–Z, 2–7, optional space/`=`/`-` separators) of at least 16 significant
/// chars. A normal password — lowercase mixed with the digits 0/1/8/9 or symbols,
/// or simply short — is none of these. TOTP secrets are never confusable with
/// passwords in the source (an `otpauth://` prefix or a long base32 blob), which
/// is exactly why a TotpSecret failing this test is really a mislabeled password.
fn looks_like_totp(v: &str) -> bool {
    let t = v.trim();
    if t.len() >= 10 && t.get(..10).is_some_and(|p| p.eq_ignore_ascii_case("otpauth://")) {
        return true;
    }
    let mut significant = 0usize;
    for c in t.chars() {
        if c.is_ascii_alphabetic() || matches!(c, '2'..='7') {
            significant += 1;
        } else if matches!(c, ' ' | '=' | '-') {
        } else {
            return false;
        }
    }
    significant >= 16
}

/// True if `v` looks like an unlabeled password: a single
/// whitespace-free token, >= 6 chars, with at least one ASCII letter AND at least
/// one digit or symbol, and not itself a URL or email. Deliberately narrow — note
/// prose (has spaces) and plain words (no digit/symbol) never match, so an
/// ordinary note is not masked as a secret.
fn looks_like_secret(v: &str) -> bool {
    let t = v.trim();
    if t.chars().count() < 6 {
        return false;
    }
    if t.chars().any(|c| c.is_whitespace()) {
        return false;
    }
    if t.contains("://") || t.contains('@') {
        return false;
    }
    let has_letter = t.chars().any(|c| c.is_ascii_alphabetic());
    let has_digit_or_symbol = t.chars().any(|c| c.is_ascii_digit() || (!c.is_alphanumeric() && !c.is_whitespace()));
    has_letter && has_digit_or_symbol
}

/// Relabel systematically-misclassified fields. Order matters: Rule P runs first
/// so a phone-shaped lone SecurityAnswer becomes Phone (not Password).
pub fn reconcile(proposal: &mut ImportProposal) {
    for entry in &mut proposal.entries {
        for f in &mut entry.fields {
            if !looks_like_phone(&f.value) {
                continue;
            }
            let plus_led = f.value.trim().starts_with('+');
            match f.field_type {
                FieldType::TotpSecret => f.field_type = FieldType::Phone,
                FieldType::Note
                | FieldType::Login
                | FieldType::ApiKey
                | FieldType::SecurityAnswer
                    if plus_led =>
                {
                    f.field_type = FieldType::Phone;
                }
                _ => {}
            }
        }
        for f in &mut entry.fields {
            if f.field_type == FieldType::TotpSecret && !looks_like_totp(&f.value) {
                f.field_type = FieldType::Password;
            }
        }
        let has_question =
            entry.fields.iter().any(|f| f.field_type == FieldType::SecurityQuestion);
        if !has_question {
            for f in &mut entry.fields {
                if f.field_type == FieldType::SecurityAnswer {
                    f.field_type = FieldType::Password;
                }
            }
        }
        let has_credential_context = entry
            .fields
            .iter()
            .any(|f| matches!(f.field_type, FieldType::Login | FieldType::Email));
        if has_credential_context {
            for f in &mut entry.fields {
                if f.field_type == FieldType::Note && looks_like_secret(&f.value) {
                    f.field_type = FieldType::Password;
                }
            }
        }
        if entry.kind == EntryKind::SecureNote
            && entry.fields.iter().any(|f| {
                matches!(
                    f.field_type,
                    FieldType::Password
                        | FieldType::Login
                        | FieldType::Url
                        | FieldType::TotpSecret
                        | FieldType::ApiKey
                )
            })
        {
            entry.kind = EntryKind::Login;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text_import::model::{EntryKind, ProposedEntry, ProposedField};

    fn field(ft: FieldType, value: &str) -> ProposedField {
        ProposedField { field_type: ft, value: value.into(), confidence: 0.8 }
    }
    fn entry_of(kind: EntryKind, fields: Vec<ProposedField>) -> ImportProposal {
        ImportProposal { entries: vec![ProposedEntry { title: None, kind, source_file: None, source_text: None, fields }], unparsed: vec![], entries_dropped: 0 }
    }
    fn entry(fields: Vec<ProposedField>) -> ImportProposal {
        entry_of(EntryKind::Login, fields)
    }
    fn first_type(p: &ImportProposal) -> FieldType {
        p.entries[0].fields[0].field_type
    }

    #[test]
    fn phone_labeled_totp_becomes_phone() {
        let mut p = entry(vec![field(FieldType::TotpSecret, "+380000000000")]);
        reconcile(&mut p);
        assert_eq!(first_type(&p), FieldType::Phone);
        assert_eq!(p.entries[0].fields[0].value, "+380000000000");
    }

    #[test]
    fn real_base32_totp_secret_stays_totp() {
        let mut p = entry(vec![field(FieldType::TotpSecret, "JBSWY3DPEHPK3PXP")]);
        reconcile(&mut p);
        assert_eq!(first_type(&p), FieldType::TotpSecret, "a real base32 secret must not be relabeled");
    }


    #[test]
    fn totp_labeled_password_becomes_password() {
        let mut p = entry(vec![field(FieldType::TotpSecret, "Test123!")]);
        reconcile(&mut p);
        assert_eq!(first_type(&p), FieldType::Password);
    }

    #[test]
    fn totp_labeled_short_secret_becomes_password() {
        let mut p = entry(vec![field(FieldType::TotpSecret, "ABC234")]);
        reconcile(&mut p);
        assert_eq!(first_type(&p), FieldType::Password);
    }

    #[test]
    fn otpauth_uri_stays_totp() {
        let mut p = entry(vec![field(FieldType::TotpSecret, "otpauth://totp/Site:me?secret=JBSWY3DPEHPK3PXP&issuer=Site")]);
        reconcile(&mut p);
        assert_eq!(first_type(&p), FieldType::TotpSecret);
    }

    #[test]
    fn spaced_base32_secret_stays_totp() {
        let mut p = entry(vec![field(FieldType::TotpSecret, "JBSW Y3DP EHPK 3PXP")]);
        reconcile(&mut p);
        assert_eq!(first_type(&p), FieldType::TotpSecret);
    }

    #[test]
    fn plus_led_phone_labeled_note_becomes_phone() {
        let mut p = entry(vec![field(FieldType::Note, "+1 (415) 555-0132")]);
        reconcile(&mut p);
        assert_eq!(first_type(&p), FieldType::Phone);
    }

    #[test]
    fn password_is_never_relabeled_to_phone() {
        let mut p = entry(vec![field(FieldType::Password, "+12345678")]);
        reconcile(&mut p);
        assert_eq!(first_type(&p), FieldType::Password);
    }

    #[test]
    fn lone_security_answer_becomes_password() {
        let mut p = entry(vec![field(FieldType::SecurityAnswer, "hunter2")]);
        reconcile(&mut p);
        assert_eq!(first_type(&p), FieldType::Password);
    }

    #[test]
    fn phone_shaped_lone_security_answer_becomes_phone_not_password() {
        let mut p = entry(vec![field(FieldType::SecurityAnswer, "+380000000000")]);
        reconcile(&mut p);
        assert_eq!(first_type(&p), FieldType::Phone);
    }

    #[test]
    fn security_answer_with_question_sibling_is_kept() {
        let mut p = entry(vec![
            field(FieldType::SecurityQuestion, "First pet name?"),
            field(FieldType::SecurityAnswer, "Fluffy"),
        ]);
        reconcile(&mut p);
        assert_eq!(p.entries[0].fields[1].field_type, FieldType::SecurityAnswer);
    }


    #[test]
    fn secure_note_with_password_becomes_login() {
        let mut p = entry_of(EntryKind::SecureNote, vec![
            field(FieldType::Email, "jane.doe@example.com"),
            field(FieldType::Password, "Test123!"),
        ]);
        reconcile(&mut p);
        assert_eq!(p.entries[0].kind, EntryKind::Login);
    }

    #[test]
    fn secure_note_with_only_a_url_becomes_login() {
        let mut p = entry_of(EntryKind::SecureNote, vec![field(FieldType::Url, "https://themes.getbootstrap.com/signin/")]);
        reconcile(&mut p);
        assert_eq!(p.entries[0].kind, EntryKind::Login);
    }

    #[test]
    fn genuine_secure_note_without_credentials_stays_a_note() {
        let mut p = entry_of(EntryKind::SecureNote, vec![
            field(FieldType::Note, "remember to renew"),
            field(FieldType::Email, "contact@example.com"),
        ]);
        reconcile(&mut p);
        assert_eq!(p.entries[0].kind, EntryKind::SecureNote);
    }

    #[test]
    fn never_demotes_a_login() {
        let mut p = entry_of(EntryKind::Login, vec![field(FieldType::Note, "just a note")]);
        reconcile(&mut p);
        assert_eq!(p.entries[0].kind, EntryKind::Login);
    }


    #[test]
    fn secret_shaped_note_with_login_context_becomes_password() {
        let mut p = entry(vec![
            field(FieldType::Email, "jane.doe@example.com"),
            field(FieldType::Note, "Test123!"),
        ]);
        reconcile(&mut p);
        assert_eq!(p.entries[0].fields[1].field_type, FieldType::Password);
        assert_eq!(p.entries[0].fields[1].value, "Test123!", "value untouched");
    }

    #[test]
    fn ordinary_note_prose_is_not_relabeled_password() {
        let mut p = entry(vec![
            field(FieldType::Login, "bob"),
            field(FieldType::Note, "renew next year"),
        ]);
        reconcile(&mut p);
        assert_eq!(p.entries[0].fields[1].field_type, FieldType::Note);
    }

    #[test]
    fn plain_word_note_is_not_relabeled_password() {
        let mut p = entry(vec![
            field(FieldType::Login, "bob"),
            field(FieldType::Note, "Netflix"),
        ]);
        reconcile(&mut p);
        assert_eq!(p.entries[0].fields[1].field_type, FieldType::Note);
    }

    #[test]
    fn secret_shaped_note_without_credential_sibling_stays_note() {
        let mut p = entry_of(EntryKind::SecureNote, vec![field(FieldType::Note, "Test123!")]);
        reconcile(&mut p);
        assert_eq!(p.entries[0].fields[0].field_type, FieldType::Note);
    }
}
