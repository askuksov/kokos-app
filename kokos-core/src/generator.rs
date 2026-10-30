//! CSPRNG password generator. Port of the Go reference crypto/password.go:
//! required min-per-class chars first, fill from the union charset, then
//! Fisher-Yates shuffle — all draws from the OS CSPRNG (rand::rngs::OsRng).

use rand::rngs::OsRng;
use rand::RngCore;

use crate::error::{Result, VaultError};

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()_+-=[]{}|;:,.<>?";

#[derive(Debug, Clone)]
pub struct GenOpts {
    pub length: usize,
    pub upper: bool,
    pub lower: bool,
    pub digits: bool,
    pub symbols: bool,
    pub min_upper: usize,
    pub min_lower: usize,
    pub min_digits: usize,
    pub min_symbols: usize,
}

/// Uniform index in [0, n) from the CSPRNG via rejection sampling (avoids the
/// modulo bias a plain `next_u32() % n` would introduce).
fn secure_index(n: usize) -> usize {
    debug_assert!(n > 0);
    let bound = (u32::MAX as usize / n) * n;
    loop {
        let r = OsRng.next_u32() as usize;
        if r < bound {
            return r % n;
        }
    }
}

pub fn generate(opts: &GenOpts) -> Result<String> {
    const MAX_LENGTH: usize = 512;
    if opts.length < 4 || opts.length > MAX_LENGTH {
        return Err(VaultError::GeneratorOptions("length must be between 4 and 512".into()));
    }
    let mins_sum = opts.min_lower
        .saturating_add(opts.min_upper)
        .saturating_add(opts.min_digits)
        .saturating_add(opts.min_symbols);
    if mins_sum > opts.length {
        return Err(VaultError::GeneratorOptions("minimums exceed length".into()));
    }
    let mut charset: Vec<u8> = Vec::new();
    let mut required: Vec<u8> = Vec::new();
    let push_class = |on: bool, set: &[u8], min: usize, charset: &mut Vec<u8>, required: &mut Vec<u8>| {
        if on {
            charset.extend_from_slice(set);
            for _ in 0..min {
                required.push(set[secure_index(set.len())]);
            }
        }
    };
    push_class(opts.lower, LOWER, opts.min_lower, &mut charset, &mut required);
    push_class(opts.upper, UPPER, opts.min_upper, &mut charset, &mut required);
    push_class(opts.digits, DIGITS, opts.min_digits, &mut charset, &mut required);
    push_class(opts.symbols, SYMBOLS, opts.min_symbols, &mut charset, &mut required);

    if charset.is_empty() {
        return Err(VaultError::GeneratorOptions("at least one character class must be enabled".into()));
    }
    if required.len() > opts.length {
        return Err(VaultError::GeneratorOptions("minimums exceed length".into()));
    }

    let mut out: Vec<u8> = Vec::with_capacity(opts.length);
    out.extend_from_slice(&required);
    while out.len() < opts.length {
        out.push(charset[secure_index(charset.len())]);
    }
    for i in (1..out.len()).rev() {
        let j = secure_index(i + 1);
        out.swap(i, j);
    }
    Ok(String::from_utf8(out).expect("ASCII charset yields valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> GenOpts {
        GenOpts {
            length: 16,
            upper: true,
            lower: true,
            digits: true,
            symbols: true,
            min_upper: 1,
            min_lower: 1,
            min_digits: 1,
            min_symbols: 1,
        }
    }

    #[test]
    fn length_is_exact() {
        assert_eq!(generate(&base()).unwrap().chars().count(), 16);
    }

    #[test]
    fn honors_minimums_per_class() {
        for _ in 0..50 {
            let pw = generate(&base()).unwrap();
            assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
            assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
            assert!(pw.chars().any(|c| c.is_ascii_digit()));
            assert!(pw.chars().any(|c| !c.is_ascii_alphanumeric()));
        }
    }

    #[test]
    fn only_selected_classes_appear() {
        let opts = GenOpts {
            upper: false,
            digits: false,
            symbols: false,
            min_upper: 0,
            min_digits: 0,
            min_symbols: 0,
            ..base()
        };
        let pw = generate(&opts).unwrap();
        assert!(pw.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn rejects_no_class() {
        let opts = GenOpts {
            upper: false,
            lower: false,
            digits: false,
            symbols: false,
            min_upper: 0,
            min_lower: 0,
            min_digits: 0,
            min_symbols: 0,
            ..base()
        };
        assert!(matches!(generate(&opts), Err(crate::error::VaultError::GeneratorOptions(_))));
    }

    #[test]
    fn rejects_too_short() {
        assert!(matches!(
            generate(&GenOpts {
                length: 3,
                ..base()
            }),
            Err(crate::error::VaultError::GeneratorOptions(_))
        ));
    }

    #[test]
    fn happy_path_read_back() {
        let pw = generate(&base()).unwrap();
        assert_eq!(pw.chars().count(), 16);
        let valid_chars = [LOWER, UPPER, DIGITS, SYMBOLS]
            .iter()
            .flat_map(|&set| set.iter().copied())
            .collect::<Vec<u8>>();
        for c in pw.chars() {
            let b = c as u8;
            assert!(valid_chars.contains(&b), "stray byte {} in password", b);
        }
    }

    #[test]
    fn rejects_too_short_even_with_no_minimums() {
        let opts = GenOpts { length: 3, upper: true, lower: false, digits: false, symbols: false, min_upper: 0, min_lower: 0, min_digits: 0, min_symbols: 0 };
        assert!(matches!(generate(&opts), Err(crate::error::VaultError::GeneratorOptions(_))));
    }

    #[test]
    fn rejects_minimums_exceeding_length() {
        let opts = GenOpts { length: 4, upper: true, lower: false, digits: false, symbols: false, min_upper: 5, min_lower: 0, min_digits: 0, min_symbols: 0 };
        assert!(matches!(generate(&opts), Err(crate::error::VaultError::GeneratorOptions(_))));
    }

    #[test]
    fn rejects_huge_minimum_immediately_before_the_loop() {
        let opts = GenOpts { min_upper: 100_000_000, ..base() };
        let t0 = std::time::Instant::now();
        let r = generate(&opts);
        let elapsed = t0.elapsed();
        assert!(matches!(r, Err(crate::error::VaultError::GeneratorOptions(_))), "must reject");
        assert!(elapsed < std::time::Duration::from_millis(50),
            "huge min_* must be rejected before the loop (took {elapsed:?})");
    }

    #[test]
    fn rejects_length_above_max_accepts_max() {
        assert!(matches!(generate(&GenOpts { length: 513, ..base() }),
            Err(crate::error::VaultError::GeneratorOptions(_))), "length > 512 must be rejected");
        assert!(generate(&GenOpts { length: 512, ..base() }).is_ok(), "length == 512 must be accepted");
    }
}
