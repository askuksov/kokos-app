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

fn decode_secret(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace() && *c != '-' && *c != '=').collect::<String>().to_uppercase();
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned)
        .filter(|b| !b.is_empty())
        .ok_or_else(|| VaultError::TotpParse("secret is not valid base32".into()))
}

pub fn parse(input: &str) -> Result<TotpParams> {
    let input = input.trim();
    if let Some(rest) = input.strip_prefix("otpauth://totp/") {
        let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");
        let mut secret = None;
        let (mut digits, mut period, mut algo) = (6u32, 30u32, TotpAlgo::Sha1);
        for pair in query.split('&') {
            let Some((k, v)) = pair.split_once('=') else { continue };
            match k {
                "secret" => secret = Some(decode_secret(v)?),
                "digits" => digits = v.parse().unwrap_or(6),
                "period" => period = v.parse().unwrap_or(30),
                "algorithm" => algo = match v.to_uppercase().as_str() {
                    "SHA256" => TotpAlgo::Sha256,
                    "SHA512" => TotpAlgo::Sha512,
                    _ => TotpAlgo::Sha1,
                },
                _ => {}
            }
        }
        let secret = secret.ok_or_else(|| VaultError::TotpParse("otpauth URI has no secret".into()))?;
        Ok(TotpParams { secret: Zeroizing::new(secret), digits, period, algo })
    } else {
        Ok(TotpParams { secret: Zeroizing::new(decode_secret(input)?), digits: 6, period: 30, algo: TotpAlgo::Sha1 })
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
