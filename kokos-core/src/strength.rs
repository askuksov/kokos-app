//! Canonical password-strength scorer. The frontend does not score passwords
//! (`src/lib/strength.ts` only maps a 0-4 score to a display label) -- this is
//! the single source of the score, kept in core so the plaintext never leaves
//! Rust. Deliberately NOT zxcvbn (or any dictionary/entropy-aware estimator)
//! -- a real estimator is deferred. Pure, no I/O, and never logs its
//! input: the password never leaves [`estimate`] as anything other than the
//! returned 0-4 score.

/// Estimates password strength on a 0-4 scale.
///
/// Combines two cheap, deterministic signals: how long the password is
/// (three length thresholds: 8/12/16 chars) and how many distinct character
/// classes it uses (lowercase/uppercase/digit/symbol). Each crossed
/// threshold is worth one point (0-7 total), then the point total buckets
/// into a 0-4 score. ASCII character-class predicates and
/// `chars().count()` for length reproduce the original client-side heuristic
/// (regexes `[a-z]`/`[A-Z]`/`[0-9]`/`[^a-zA-Z0-9]`) that this backend
/// scorer replaced.
pub fn estimate(password: &str) -> u8 {
    if password.is_empty() {
        return 0;
    }

    let mut points = 0u32;

    let len = password.chars().count();
    if len >= 8 {
        points += 1;
    }
    if len >= 12 {
        points += 1;
    }
    if len >= 16 {
        points += 1;
    }

    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    for c in password.chars() {
        if c.is_ascii_lowercase() {
            has_lower = true;
        } else if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else {
            has_symbol = true;
        }
    }
    if has_lower {
        points += 1;
    }
    if has_upper {
        points += 1;
    }
    if has_digit {
        points += 1;
    }
    if has_symbol {
        points += 1;
    }

    match points {
        0..=1 => 0,
        2 => 1,
        3..=4 => 2,
        5..=6 => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_is_zero() {
        assert_eq!(estimate(""), 0);
    }

    #[test]
    fn short_lowercase_only_is_zero() {
        assert_eq!(estimate("abc"), 0);
    }

    #[test]
    fn medium_lower_and_digit_is_two() {
        assert_eq!(estimate("password123"), 2);
    }

    #[test]
    fn len_12_all_classes_is_three() {
        assert_eq!(estimate("Xy9!aB3$kLmN"), 3);
    }

    #[test]
    fn len_16_all_classes_is_four() {
        assert_eq!(estimate("Xy9!aB3$kLmN2Qr#"), 4);
    }
}
