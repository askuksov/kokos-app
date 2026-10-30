//! RFC 6238 TOTP. `parse` accepts an otpauth:// URI or a bare base32 secret;
//! `code_at` computes the current code from those parsed params. The secret is
//! read in core and never crosses the IPC boundary — only the derived digits leave.

use crate::error::{Result, VaultError};
use hmac::{Hmac, Mac};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy)]
pub enum TotpAlgo { Sha1, Sha256, Sha512 }

#[derive(Clone)]
pub struct TotpParams { secret: Zeroizing<Vec<u8>>, pub digits: u32, pub period: u32, pub algo: TotpAlgo }

impl std::fmt::Debug for TotpParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpParams")
            .field("secret", &"<redacted>")
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("algo", &self.algo)
            .finish()
    }
}

fn decode_secret(s: &str) -> Result<Zeroizing<Vec<u8>>> {
    // Upper-casing grows a char at most 3x in bytes: reserve that up front so
    // the seed text never reallocates and leaves an unwiped copy behind.
    let mut cleaned = Zeroizing::new(String::with_capacity(s.len() * 3));
    cleaned.extend(s.chars().filter(|c| !c.is_whitespace() && *c != '-' && *c != '=').flat_map(char::to_uppercase));
    // Reject a bad alphabet before decoding: on failure `base32::decode` drops
    // its partly filled buffer without wiping it.
    if !cleaned.bytes().all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b)) {
        return Err(VaultError::TotpParse("secret is not valid base32".into()));
    }
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned)
        .map(Zeroizing::new)
        .filter(|b| !b.is_empty())
        .ok_or_else(|| VaultError::TotpParse("secret is not valid base32".into()))
}

/// RFC 3986 percent-decoding of one query component (`+` is left as-is).
/// A malformed escape or non-UTF-8 result is a parse error, not a guess.
/// The output may be the seed, so every buffer is wiped on drop.
fn percent_decode(s: &str) -> Result<Zeroizing<String>> {
    let bad = || VaultError::TotpParse("otpauth URI has an invalid percent-escape".into());
    let bytes = s.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3).ok_or_else(bad)?;
            let hex = std::str::from_utf8(hex).map_err(|_| bad())?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| bad())?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    let text = std::str::from_utf8(&out).map_err(|_| bad())?;
    Ok(Zeroizing::new(text.to_owned()))
}

pub fn parse(input: &str) -> Result<TotpParams> {
    let input = input.trim();
    if let Some(rest) = input.strip_prefix("otpauth://totp/") {
        let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");
        let mut secret = None;
        // Only an absent parameter takes the default: a present-but-invalid
        // one would yield codes the issuer never accepts.
        let (mut digits, mut period, mut algo) = (6u32, 30u32, TotpAlgo::Sha1);
        for pair in query.split('&') {
            let (k, v) = match pair.split_once('=') {
                Some((k, v)) => (percent_decode(k)?, v),
                // A bare recognised key is present with an empty value, so
                // the checks below reject it; other bare tokens are ignored.
                None => match percent_decode(pair) {
                    Ok(k) => (k, ""),
                    Err(_) => continue,
                },
            };
            // Values of unknown keys (e.g. a free-text `issuer`) are never
            // decoded, so a stray `%` there cannot fail the whole URI.
            match k.as_str() {
                "secret" => secret = Some(decode_secret(&percent_decode(v)?)?),
                "digits" => {
                    digits = percent_decode(v)?
                        .parse()
                        .ok()
                        .filter(|d| (6..=8).contains(d))
                        .ok_or_else(|| VaultError::TotpParse("digits must be 6, 7 or 8".into()))?;
                }
                "period" => {
                    period = percent_decode(v)?
                        .parse()
                        .ok()
                        .filter(|p| (1..=3600).contains(p))
                        .ok_or_else(|| VaultError::TotpParse("period must be 1..=3600 seconds".into()))?;
                }
                "algorithm" => {
                    algo = match percent_decode(v)?.to_ascii_uppercase().replace('-', "").as_str() {
                        "SHA1" => TotpAlgo::Sha1,
                        "SHA256" => TotpAlgo::Sha256,
                        "SHA512" => TotpAlgo::Sha512,
                        _ => return Err(VaultError::TotpParse("unsupported algorithm".into())),
                    };
                }
                _ => {}
            }
        }
        let secret = secret.ok_or_else(|| VaultError::TotpParse("otpauth URI has no secret".into()))?;
        Ok(TotpParams { secret, digits, period, algo })
    } else {
        Ok(TotpParams { secret: decode_secret(input)?, digits: 6, period: 30, algo: TotpAlgo::Sha1 })
    }
}

#[derive(Clone)]
pub struct TotpCode {
    pub code: String,
    pub remaining: u32,
    pub period: u32,
}
impl std::fmt::Debug for TotpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpCode")
            .field("code", &"<redacted>")
            .field("remaining", &self.remaining)
            .field("period", &self.period)
            .finish()
    }
}

fn hmac_digest(algo: TotpAlgo, key: &[u8], msg: &[u8]) -> Vec<u8> {
    match algo {
        TotpAlgo::Sha1 => {
            let mut m = <Hmac<sha1::Sha1>>::new_from_slice(key).unwrap();
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
        TotpAlgo::Sha256 => {
            let mut m = <Hmac<sha2::Sha256>>::new_from_slice(key).unwrap();
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
        TotpAlgo::Sha512 => {
            let mut m = <Hmac<sha2::Sha512>>::new_from_slice(key).unwrap();
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }
    }
}

pub fn code_at(p: &TotpParams, unix_secs: u64) -> TotpCode {
    let period = p.period.max(1);
    let digits = p.digits.clamp(1, 9);
    let counter = unix_secs / period as u64;
    let digest = hmac_digest(p.algo, &p.secret, &counter.to_be_bytes());
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let bin = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let modulo = 10u32.pow(digits);
    let code = format!("{:0width$}", bin % modulo, width = digits as usize);
    let remaining = period - (unix_secs % period as u64) as u32;
    TotpCode { code, remaining, period }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(seed_ascii: &str, algo: TotpAlgo) -> TotpParams {
        TotpParams { secret: Zeroizing::new(seed_ascii.as_bytes().to_vec()), digits: 8, period: 30, algo }
    }

    #[test]
    fn parses_bare_base32_with_defaults() {
        let p = parse("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        assert_eq!(p.secret.len(), 20);
        assert_eq!(p.digits, 6);
        assert_eq!(p.period, 30);
        assert!(matches!(p.algo, TotpAlgo::Sha1));
    }

    #[test]
    fn parses_base32_with_spaces_and_lowercase() {
        let p = parse("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap();
        assert_eq!(p.secret.as_slice(), "12345678901234567890".as_bytes());
        assert_eq!(p.digits, 6);
        assert_eq!(p.period, 30);
        assert!(matches!(p.algo, TotpAlgo::Sha1));
    }

    #[test]
    fn parses_otpauth_uri_params() {
        let p = parse("otpauth://totp/ACME:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=60&algorithm=SHA256").unwrap();
        assert_eq!(p.digits, 8);
        assert_eq!(p.period, 60);
        assert!(matches!(p.algo, TotpAlgo::Sha256));
        assert_eq!(p.secret.len(), 20);
    }

    #[test]
    fn percent_encoded_query_is_decoded() {
        let p = parse("otpauth://totp/ACME:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ%3D%3D&%64igits=8&algorithm=SHA%2D256").unwrap();
        assert_eq!(p.secret.as_slice(), "12345678901234567890".as_bytes());
        assert_eq!(p.digits, 8);
        assert!(matches!(p.algo, TotpAlgo::Sha256));
    }

    #[test]
    fn invalid_percent_escape_is_rejected() {
        for uri in [
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ%G1",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ%3",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ%FF",
        ] {
            assert!(matches!(parse(uri), Err(crate::error::VaultError::TotpParse(_))), "{uri}");
        }
    }

    #[test]
    fn stray_percent_in_an_unknown_param_is_ignored() {
        let p = parse("otpauth://totp/x?issuer=100%&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        assert_eq!(p.secret.len(), 20);
    }

    #[test]
    fn present_but_invalid_params_are_rejected() {
        let base = "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        for extra in [
            "&digits=5", "&digits=9", "&digits=abc", "&digits=",
            "&period=0", "&period=-30", "&period=3601", "&period=abc", "&period=",
            "&algorithm=MD5", "&algorithm=",
        ] {
            let uri = format!("{base}{extra}");
            assert!(matches!(parse(&uri), Err(crate::error::VaultError::TotpParse(_))), "{uri}");
        }
    }

    #[test]
    fn bare_recognised_keys_are_rejected_and_unknown_ones_ignored() {
        let base = "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        for extra in ["&digits", "&period", "&algorithm", "&%64igits"] {
            let uri = format!("{base}{extra}");
            assert!(matches!(parse(&uri), Err(crate::error::VaultError::TotpParse(_))), "{uri}");
        }
        assert!(matches!(
            parse("otpauth://totp/x?secret&digits=6"),
            Err(crate::error::VaultError::TotpParse(_))
        ));
        let p = parse(&format!("{base}&issuer&100%&")).unwrap();
        assert_eq!((p.digits, p.period, p.secret.len()), (6, 30, 20));
    }

    #[test]
    fn absent_params_default_and_algorithm_spellings_are_accepted() {
        let base = "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let p = parse(base).unwrap();
        assert_eq!((p.digits, p.period), (6, 30));
        assert!(matches!(p.algo, TotpAlgo::Sha1));
        for (alg, want) in [("sha1", "Sha1"), ("SHA-1", "Sha1"), ("sha-256", "Sha256"), ("SHA512", "Sha512")] {
            let p = parse(&format!("{base}&algorithm={alg}&digits=7&period=3600")).unwrap();
            assert_eq!(format!("{:?}", p.algo), want, "{alg}");
            assert_eq!((p.digits, p.period), (7, 3600));
        }
    }

    #[test]
    fn rejects_bad_base32() {
        assert!(matches!(parse("!!!! not base32 !!!!"), Err(crate::error::VaultError::TotpParse(_))));
    }

    #[test]
    fn rfc6238_vectors_t59() {
        assert_eq!(code_at(&params("12345678901234567890", TotpAlgo::Sha1), 59).code, "94287082");
        assert_eq!(code_at(&params("12345678901234567890123456789012", TotpAlgo::Sha256), 59).code, "46119246");
        let seed512 = "1234567890123456789012345678901234567890123456789012345678901234";
        assert_eq!(code_at(&params(seed512, TotpAlgo::Sha512), 59).code, "90693936");
    }

    #[test]
    fn remaining_counts_down_within_period() {
        let p = params("12345678901234567890", TotpAlgo::Sha1);
        assert_eq!(code_at(&p, 59).remaining, 1);
        assert_eq!(code_at(&p, 30).remaining, 30);
        assert_eq!(code_at(&p, 45).remaining, 15);
    }

    #[test]
    fn six_digit_is_zero_padded() {
        let p = TotpParams { digits: 6, ..params("12345678901234567890", TotpAlgo::Sha1) };
        assert_eq!(code_at(&p, 59).code.len(), 6);
    }

    #[test]
    fn code_at_survives_zero_period() {
        let p = TotpParams { period: 0, ..params("12345678901234567890", TotpAlgo::Sha1) };
        let c = code_at(&p, 59);
        assert_eq!(c.code.len(), 8);
        assert!(c.period >= 1);
    }

    #[test]
    fn code_at_survives_large_digits() {
        let p = TotpParams { digits: 12, ..params("12345678901234567890", TotpAlgo::Sha1) };
        let c = code_at(&p, 59);
        assert!(!c.code.is_empty());
    }

    #[test]
    fn debug_redacts_totp_secret_and_code() {
        let p = parse("otpauth://totp/ACME:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=6&period=30").unwrap();
        let dbg = format!("{:?}", p);
        assert!(dbg.contains("<redacted>"), "TotpParams Debug must redact the secret: {dbg}");
        assert!(!dbg.contains("secret: ["), "raw seed leaked in TotpParams Debug: {dbg}");
        assert!(!dbg.contains("49, 50, 51"), "raw seed bytes leaked: {dbg}");
        assert!(dbg.contains("digits") && dbg.contains("period"), "non-secret fields must still show");

        let c = code_at(&p, 59);
        let cdbg = format!("{:?}", c);
        assert!(!cdbg.contains(&c.code), "live OTP code leaked in TotpCode Debug: {cdbg}");
        assert!(cdbg.contains("<redacted>"));
    }

    #[test]
    fn code_at_correct_after_redaction() {
        assert_eq!(code_at(&params("12345678901234567890", TotpAlgo::Sha1), 59).code, "94287082");
    }
}
