//! Google OAuth 2.0 Installed-App PKCE flow. We request ONLY the
//! `drive.appdata` scope (app-private storage; no access to the user's other
//! Drive files, no email/userinfo). The client is a Desktop-app OAuth client:
//! PKCE protects the auth code, but Google's token endpoint still rejects the
//! exchange without the client_secret ("client_secret is missing"), so we send
//! it too. The client_id is embedded (non-sensitive); the client_secret is kept
//! OUT of git and loaded at runtime (see `client_secret()`).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};

/// Register a "Desktop app" OAuth client in Google Cloud Console and paste its
/// id here. Without it the flow cannot run.
pub const GOOGLE_CLIENT_ID: &str = "802967863663-ptpns3h0bhlao5010vff22efsrm1ufpq.apps.googleusercontent.com";
pub const SCOPE: &str = "https://www.googleapis.com/auth/drive.appdata";
pub const AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

/// The Desktop-app client secret. Kept OUT of git: read at runtime from the
/// `KOKOS_GDRIVE_CLIENT_SECRET` env var, else from a gitignored
/// `<src-tauri>/.gdrive_client_secret` file. Google's token endpoint requires it
/// even with PKCE (installed-app secret; not confidential per Google). Empty when
/// neither source is present — the token exchange then fails cleanly.
/// Note: the file fallback resolves via the compile-time `CARGO_MANIFEST_DIR`
/// path, which only exists on this build machine's checkout and will not exist
/// in a distributed/packaged binary — a shipped build must supply the secret
/// via the `KOKOS_GDRIVE_CLIENT_SECRET` env var (build-time injection is a
/// packaging concern).
pub fn client_secret() -> String {
    if let Ok(s) = std::env::var("KOKOS_GDRIVE_CLIENT_SECRET") {
        let s = s.trim().to_string();
        if !s.is_empty() {
            return s;
        }
    }
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/.gdrive_client_secret"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

/// 96-char verifier (three uuid-v4 hex blocks — CSPRNG via getrandom, all
/// chars in the unreserved set) + its S256 challenge.
pub fn make_pkce() -> Pkce {
    let verifier: String = (0..3)
        .map(|_| uuid::Uuid::new_v4().simple().to_string())
        .collect();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    Pkce { verifier, challenge }
}

pub fn consent_url(challenge: &str, redirect_uri: &str, state: &str) -> String {
    let enc = |s: &str| urlencoding::encode(s).into_owned();
    format!(
        "{AUTH_ENDPOINT}?response_type=code&access_type=offline&prompt=consent\
         &client_id={cid}&redirect_uri={ru}&scope={sc}&code_challenge={ch}\
         &code_challenge_method=S256&state={st}",
        cid = enc(GOOGLE_CLIENT_ID),
        ru = enc(redirect_uri),
        sc = enc(SCOPE),
        ch = enc(challenge),
        st = enc(state),
    )
}

use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum OauthError { Timeout, StateMismatch, Denied(String), Io(String), Cancelled }
impl std::fmt::Display for OauthError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            OauthError::Timeout => write!(f, "authorization timed out"),
            OauthError::StateMismatch => write!(f, "state mismatch (possible CSRF)"),
            OauthError::Denied(e) => write!(f, "authorization denied: {e}"),
            OauthError::Cancelled => write!(f, "oauth_cancelled"),
            OauthError::Io(e) => write!(f, "{e}"),
        }
    }
}

/// Extract just the `error` reason from a redirect query, dropping all other
/// params (notably `state`, so the CSRF nonce never rides along into an error).
fn error_reason(url: &str) -> Option<String> {
    let q = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == "error" {
                return Some(urlencoding::decode(v).map(|c| c.into_owned()).unwrap_or_else(|_| v.to_string()));
            }
        }
    }
    None
}

/// Extract (code, state) from a redirect path like `/?code=..&state=..`.
/// Returns None on `error=` or non-callback paths.
pub fn parse_redirect_query(url: &str) -> Option<(String, String)> {
    let q = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    let mut code = None;
    let mut state = None;
    for pair in q.split('&') {
        let (k, v) = pair.split_once('=')?;
        let v = urlencoding::decode(v).ok()?.into_owned();
        match k { "code" => code = Some(v), "state" => state = Some(v), "error" => return None, _ => {} }
    }
    Some((code?, state?))
}

/// Bind an ephemeral loopback port and report the bound redirect_uri via `tx`
/// right after binding, then block for the callback (verifying `state`).
/// Lets the caller open the browser once the port is known.
///
/// `cancel` ends the wait early: the user can abandon the consent page, and a
/// closed tab sends nothing back at all, so the flag is the only way out short
/// of the deadline.
pub fn listen_for_code_reporting(
    expected_state: &str,
    timeout: Duration,
    tx: std::sync::mpsc::Sender<String>,
    cancel: &'static std::sync::atomic::AtomicBool,
) -> Result<(String, String), OauthError> {
    let server = tiny_http::Server::http("127.0.0.1:0").map_err(|e| OauthError::Io(e.to_string()))?;
    let port = server
        .server_addr()
        .to_ip()
        .ok_or_else(|| OauthError::Io("no ip addr".into()))?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}");
    tx.send(redirect_uri.clone()).map_err(|_| OauthError::Io("report channel closed".into()))?;
    let deadline = Instant::now() + timeout;
    const SLICE: Duration = Duration::from_millis(250);
    loop {
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(OauthError::Cancelled);
        }
        let remaining = deadline.checked_duration_since(Instant::now()).ok_or(OauthError::Timeout)?;
        match server.recv_timeout(remaining.min(SLICE)).map_err(|e| OauthError::Io(e.to_string()))? {
            None => continue,
            Some(req) => {
                let url = req.url().to_string();
                if let Some((code, state)) = parse_redirect_query(&url) {
                    let body = "<html><body style='font-family:sans-serif'>Kokos: authorization complete. You can close this tab.</body></html>";
                    let _ = req.respond(tiny_http::Response::from_string(body).with_header(
                        "Content-Type: text/html".parse::<tiny_http::Header>().unwrap()));
                    if state != expected_state { return Err(OauthError::StateMismatch); }
                    return Ok((code, redirect_uri));
                } else {
                    let _ = req.respond(tiny_http::Response::from_string("ok"));
                    if let Some(reason) = error_reason(&url) { return Err(OauthError::Denied(reason)); }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_is_s256_base64url_of_verifier() {
        let p = make_pkce();
        assert!(p.verifier.len() >= 43 && p.verifier.len() <= 128);
        assert!(p.verifier.chars().all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c)));
        use sha2::{Digest, Sha256};
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let want = URL_SAFE_NO_PAD.encode(Sha256::digest(p.verifier.as_bytes()));
        assert_eq!(p.challenge, want);
        assert!(!p.challenge.contains('=') && !p.challenge.contains('+') && !p.challenge.contains('/'));
    }

    #[test]
    fn consent_url_has_required_params() {
        let u = consent_url("CHAL", "http://127.0.0.1:5000", "STATE");
        assert!(u.starts_with(AUTH_ENDPOINT));
        assert!(u.contains("response_type=code"));
        assert!(u.contains("code_challenge=CHAL"));
        assert!(u.contains("code_challenge_method=S256"));
        assert!(u.contains("client_id="));
        assert!(u.contains("scope="));
        assert!(u.contains("state=STATE"));
        assert!(u.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A5000"));
        assert!(u.contains("access_type=offline"));
    }

    #[test]
    fn parses_code_and_state_from_redirect() {
        assert_eq!(parse_redirect_query("/?code=abc123&state=xyz"), Some(("abc123".into(), "xyz".into())));
        assert_eq!(parse_redirect_query("/?state=xyz&code=abc"), Some(("abc".into(), "xyz".into())));
        assert_eq!(parse_redirect_query("/?error=access_denied&state=xyz"), None);
        assert_eq!(parse_redirect_query("/favicon.ico"), None);
    }

    #[test]
    fn exchange_posts_pkce_body_and_parses_token() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = match server.server_addr() { tiny_http::ListenAddr::IP(a) => a.port(), _ => unreachable!() };
        let handle = std::thread::spawn(move || {
            let mut req = server.recv().unwrap();
            let mut body = String::new();
            req.as_reader().read_to_string(&mut body).unwrap();
            assert!(body.contains("grant_type=authorization_code"));
            assert!(body.contains("code=THECODE"));
            assert!(body.contains("code_verifier=THEVERIFIER"));
            let _ = req.respond(tiny_http::Response::from_string(
                r#"{"access_token":"AT","refresh_token":"RT","expires_in":3599,"token_type":"Bearer","scope":"x"}"#));
        });
        let ep = format!("http://127.0.0.1:{port}");
        let tok = exchange_code_at(&ep, "THECODE", "THEVERIFIER", "http://127.0.0.1:1").unwrap();
        handle.join().unwrap();
        assert_eq!(tok.access_token, "AT");
        assert_eq!(tok.refresh_token.as_deref(), Some("RT"));
        assert_eq!(tok.expires_in, 3599);
    }

    #[test]
    fn listener_rejects_mismatched_state_csrf() {
        use std::sync::atomic::AtomicBool;
        use std::sync::mpsc::channel;
        static NO_CANCEL: AtomicBool = AtomicBool::new(false);
        let (tx, rx) = channel();
        let handle = std::thread::spawn(move || {
            listen_for_code_reporting("EXPECTED", std::time::Duration::from_secs(5), tx, &NO_CANCEL)
        });
        let redirect_uri = rx.recv().expect("listener should report its redirect_uri");
        let _ = reqwest::blocking::get(format!("{redirect_uri}/?code=abc&state=WRONG"));
        let result = handle.join().expect("listener thread should not panic");
        assert!(matches!(result, Err(OauthError::StateMismatch)));
    }

    #[test]
    fn listener_aborts_when_cancelled() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc::channel;
        static CANCEL: AtomicBool = AtomicBool::new(false);
        let (tx, rx) = channel();
        let handle = std::thread::spawn(move || {
            listen_for_code_reporting("EXPECTED", std::time::Duration::from_secs(600), tx, &CANCEL)
        });
        rx.recv().expect("listener should report its redirect_uri");
        CANCEL.store(true, Ordering::Relaxed);
        let result = handle.join().expect("listener thread should not panic");
        assert!(matches!(result, Err(OauthError::Cancelled)));
    }

    #[test]
    fn refresh_posts_grant_and_parses_token_without_refresh_token() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = match server.server_addr() { tiny_http::ListenAddr::IP(a) => a.port(), _ => unreachable!() };
        let handle = std::thread::spawn(move || {
            let mut req = server.recv().unwrap();
            let mut body = String::new();
            req.as_reader().read_to_string(&mut body).unwrap();
            assert!(body.contains("grant_type=refresh_token"));
            assert!(body.contains("refresh_token=THERT"));
            let _ = req.respond(tiny_http::Response::from_string(
                r#"{"access_token":"AT2","expires_in":3599,"token_type":"Bearer","scope":"x"}"#));
        });
        let ep = format!("http://127.0.0.1:{port}");
        let tok = refresh_access_token_at(&ep, "THERT").unwrap();
        handle.join().unwrap();
        assert_eq!(tok.access_token, "AT2");
        assert_eq!(tok.refresh_token, None);
        assert_eq!(tok.expires_in, 3599);
    }
}

#[derive(Clone, serde::Deserialize)]
pub struct GdriveToken {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: i64,
}

/// Hand-written `Debug` (mirrors `OpenVault` in kokos-core/src/vault.rs) so a
/// stray `dbg!(tok)` / `error!("{:?}", tok)` never dumps the long-lived
/// `refresh_token` (or the `access_token`) to logs.
impl std::fmt::Debug for GdriveToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GdriveToken")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &self.refresh_token.as_ref().map(|_| "<redacted>"))
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

/// One POST to a Google token endpoint (shared by code-exchange and refresh).
/// Returns the parsed token or an OauthError; a non-2xx body is surfaced as
/// `Denied` (Google's error JSON — not our secret).
fn post_token_request(endpoint: &str, params: &[(&str, &str)]) -> Result<GdriveToken, OauthError> {
    let client = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .build()
        .unwrap_or_else(|_| reqwest::blocking::Client::new());
    let resp = client.post(endpoint).form(params).send().map_err(|e| OauthError::Io(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(OauthError::Denied(resp.text().unwrap_or_default()));
    }
    resp.json::<GdriveToken>().map_err(|e| OauthError::Io(e.to_string()))
}

pub fn exchange_code(code: &str, verifier: &str, redirect_uri: &str) -> Result<GdriveToken, OauthError> {
    exchange_code_at(TOKEN_ENDPOINT, code, verifier, redirect_uri)
}

fn exchange_code_at(endpoint: &str, code: &str, verifier: &str, redirect_uri: &str) -> Result<GdriveToken, OauthError> {
    let secret = client_secret();
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("code_verifier", verifier),
        ("client_id", GOOGLE_CLIENT_ID),
        ("client_secret", secret.as_str()),
        ("redirect_uri", redirect_uri),
    ];
    post_token_request(endpoint, &params)
}

/// Exchange a stored refresh_token for a fresh token bundle (used per sync op).
/// Returns the FULL `GdriveToken`: Google may rotate the refresh_token, and the
/// caller must be able to persist a rotated one (it is `None` when Google
/// returns no new refresh_token — the common case, keep the old one).
pub fn refresh_access_token(refresh_token: &str) -> Result<GdriveToken, OauthError> {
    refresh_access_token_at(TOKEN_ENDPOINT, refresh_token)
}

fn refresh_access_token_at(endpoint: &str, refresh_token: &str) -> Result<GdriveToken, OauthError> {
    let secret = client_secret();
    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", GOOGLE_CLIENT_ID),
        ("client_secret", secret.as_str()),
    ];
    post_token_request(endpoint, &params)
}
