//! The wire contract, shared by the host binary and the app. Field order
//! in `Response` matches the documented example byte-for-byte so an extension
//! author can diff against the documented shape.

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;

/// Error codes. Extensions branch on these strings, so they are part of the
/// public contract — never rename one without bumping PROTOCOL_VERSION.
pub mod codes {
    pub const BAD_REQUEST: &str = "bad_request";
    pub const UNSUPPORTED_VERSION: &str = "unsupported_version";
    pub const UNKNOWN_ACTION: &str = "unknown_action";
    pub const APP_NOT_RUNNING: &str = "app_not_running";
    pub const LOCKED: &str = "locked";
    pub const NO_VAULT: &str = "no_vault";
    pub const DENIED: &str = "denied";
    pub const NOT_IN_SCOPE: &str = "not_in_scope";
    pub const ENTRY_NOT_FOUND: &str = "entry_not_found";
    pub const INVALID_URL: &str = "invalid_url";
    pub const TOO_LARGE: &str = "too_large";
    pub const TIMEOUT: &str = "timeout";
    pub const UNSUPPORTED_PLATFORM: &str = "unsupported_platform";
    pub const INTERNAL: &str = "internal";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: String,
    #[serde(default)]
    pub version: u32,
    pub action: String,
    #[serde(default)]
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorObj {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub id: String,
    pub ok: bool,
    pub payload: Option<serde_json::Value>,
    pub error: Option<ErrorObj>,
}

impl Response {
    pub fn ok(id: &str, payload: serde_json::Value) -> Self {
        Self { id: id.to_string(), ok: true, payload: Some(payload), error: None }
    }

    pub fn err(id: &str, code: &str, message: &str) -> Self {
        Self {
            id: id.to_string(),
            ok: false,
            payload: None,
            error: Some(ErrorObj { code: code.to_string(), message: message.to_string() }),
        }
    }
}

/// Handshake sent by the host on the app socket — NOT part of the stdio
/// protocol the extension speaks, so an extension cannot forge an origin.
#[derive(Clone, Serialize, Deserialize)]
pub struct Hello {
    pub browser: String,
    pub origin: String,
    pub host_version: String,
    /// Shared-secret handshake token (Layer B). The app writes a
    /// random token to a `0600` file at startup; the host reads it (same-user
    /// FS access) and echoes it here, and the app rejects any socket peer that
    /// cannot present the current token. `#[serde(default)]` so a host that
    /// predates this field still deserialises — as `""`, which the app then
    /// rejects; the field is APPENDED, never reordered, so the wire shape
    /// stays a superset of the documented example and PROTOCOL_VERSION need not bump
    /// (the version gates the extension-visible stdio contract, and `Hello` is
    /// host↔app only, per this struct's own doc comment above).
    ///
    /// Defense-in-depth ONLY: the token file is `0600`, so the same-user
    /// attacker this addresses can read it exactly as the host does — this
    /// raises the bar, it does not close the gap (docs/THREAT-MODEL.md).
    #[serde(default)]
    pub token: String,
}

impl std::fmt::Debug for Hello {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hello")
            .field("browser", &self.browser)
            .field("origin", &self.origin)
            .field("host_version", &self.host_version)
            .field("token", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloFrame {
    pub hello: Hello,
}

/// Parses a request frame. On failure returns a ready-to-send `Response`
/// carrying the id when it could be recovered — a malformed frame still gets
/// a correlatable answer instead of silence.
pub fn parse_request(bytes: &[u8]) -> Result<Request, Response> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| Response::err("", codes::BAD_REQUEST, &format!("malformed JSON: {e}")))?;
    let id = value.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let req: Request = serde_json::from_value(value)
        .map_err(|e| Response::err(&id, codes::BAD_REQUEST, &format!("bad request shape: {e}")))?;
    if req.version != PROTOCOL_VERSION {
        return Err(Response::err(
            &req.id,
            codes::UNSUPPORTED_VERSION,
            &format!(
                "this host speaks protocol version {PROTOCOL_VERSION}; the request asked for {}",
                req.version
            ),
        ));
    }
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_well_formed_request() {
        let r = parse_request(br#"{"id":"req-1","version":1,"action":"get_logins","payload":{"url":"https://a.com"}}"#)
            .expect("valid request");
        assert_eq!(r.id, "req-1");
        assert_eq!(r.action, "get_logins");
        assert_eq!(r.payload["url"], "https://a.com");
    }

    #[test]
    fn missing_payload_defaults_to_null_not_an_error() {
        let r = parse_request(br#"{"id":"p","version":1,"action":"ping"}"#).expect("ping has no payload");
        assert!(r.payload.is_null());
    }

    #[test]
    fn wrong_version_is_rejected_but_keeps_the_id() {
        let resp = parse_request(br#"{"id":"req-2","version":2,"action":"ping"}"#)
            .expect_err("version 2 is not supported");
        assert_eq!(resp.id, "req-2", "the extension must be able to correlate the error");
        assert_eq!(resp.error.unwrap().code, codes::UNSUPPORTED_VERSION);
    }

    #[test]
    fn garbage_json_is_rejected_with_an_empty_id() {
        let resp = parse_request(b"not json at all").expect_err("garbage");
        assert_eq!(resp.id, "");
        assert_eq!(resp.error.unwrap().code, codes::BAD_REQUEST);
    }

    #[test]
    fn response_serialises_exactly_as_documented() {
        let ok = serde_json::to_string(&Response::ok("i", serde_json::json!({"locked": true}))).unwrap();
        assert_eq!(ok, r#"{"id":"i","ok":true,"payload":{"locked":true},"error":null}"#);
        let err = serde_json::to_string(&Response::err("i", codes::LOCKED, "vault is locked")).unwrap();
        assert_eq!(
            err,
            r#"{"id":"i","ok":false,"payload":null,"error":{"code":"locked","message":"vault is locked"}}"#
        );
    }

    #[test]
    fn hello_frame_round_trips() {
        let h = HelloFrame { hello: Hello { browser: "chrome".into(), origin: "chrome-extension://abc/".into(), host_version: "0.1.0".into(), token: "tok-abc123".into() } };
        let s = serde_json::to_string(&h).unwrap();
        let back: HelloFrame = serde_json::from_str(&s).unwrap();
        assert_eq!(back.hello.origin, "chrome-extension://abc/");
        assert_eq!(back.hello.token, "tok-abc123", "the token survives the round trip");
    }

    #[test]
    fn hello_without_a_token_field_defaults_to_empty() {
        let back: HelloFrame = serde_json::from_str(
            r#"{"hello":{"browser":"chrome","origin":"chrome-extension://abc/","host_version":"0.1.0"}}"#,
        )
        .expect("a hello with no token field still parses");
        assert_eq!(back.hello.token, "");
    }

    #[test]
    fn response_ok_constructor_sets_fields_correctly() {
        let resp = Response::ok("test-id", serde_json::json!({"value": 42}));
        assert_eq!(resp.id, "test-id");
        assert_eq!(resp.ok, true);
        assert!(resp.payload.is_some());
        assert_eq!(resp.payload.as_ref().unwrap()["value"], 42);
        assert!(resp.error.is_none());
    }

    #[test]
    fn response_err_constructor_sets_fields_correctly() {
        let resp = Response::err("test-id", codes::LOCKED, "vault is locked");
        assert_eq!(resp.id, "test-id");
        assert_eq!(resp.ok, false);
        assert!(resp.payload.is_none());
        assert!(resp.error.is_some());
        let err = resp.error.as_ref().unwrap();
        assert_eq!(err.code, codes::LOCKED);
        assert_eq!(err.message, "vault is locked");
    }

    #[test]
    fn request_with_nontrivial_payload_round_trips() {
        let payload = serde_json::json!({
            "url": "https://example.com",
            "username": "user@example.com",
            "tags": ["work", "important"],
            "nested": {
                "field": "value"
            }
        });
        let req = Request {
            id: "req-123".to_string(),
            version: PROTOCOL_VERSION,
            action: "save_login".to_string(),
            payload: payload.clone(),
        };
        let json_vec = serde_json::to_vec(&req).expect("request serialises");
        let req_back: Request = serde_json::from_slice(&json_vec).expect("request deserialises");
        assert_eq!(req_back.id, req.id);
        assert_eq!(req_back.version, req.version);
        assert_eq!(req_back.action, req.action);
        assert_eq!(req_back.payload, payload);
    }
}
