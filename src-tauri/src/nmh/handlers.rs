//! The native-messaging actions, executed against the app's Session. Every handler is
//! sync and short: hold the session mutex only while reading, never across a
//! confirmation wait (that would freeze the UI that has to answer it).

use tauri::Manager;

use kokos_nmh::protocol::{codes, Request, Response};

/// Hard cap on `get_logins` results (max 50, no passwords).
pub const MAX_ITEMS: usize = 50;

/// Per-connection state. One connection = one browser-launched host process
/// = one extension.
///
/// Domain anchoring (an addition beyond the base action payloads): a secret
/// or write request must name an entry this connection was actually offered
/// for the current site. `get_logins` is what fills the candidate set, so
/// anchoring is only ever as wide as the last lookup.
///
/// The set is deliberately per-CONNECTION and not persisted: the host nulls
/// its cached connection on any I/O failure, so a hiccup drops the candidate
/// set and the next `get_secret` answers `not_in_scope`. That is acceptable
/// and intentional — an extension always issues `get_logins` before offering
/// a fill, which re-anchors it, and `get_secret`/`get_totp`/`update_login`
/// additionally accept an explicit `url` that anchors on its own. A
/// persistent, connection-independent candidate set would be a strictly
/// larger attack surface for no real gain.
#[derive(Default)]
pub struct ConnScope {
    pub candidate_ids: Vec<String>,
    pub last_domain: Option<String>,
}

/// A rejected payload: the wire code plus a human-readable reason. Handlers
/// turn it into a `Response` once they have the request id. Used instead of
/// building a `Response` directly inside a pure helper, since a `Response`
/// needs the request id, which parsing helpers like `url_arg`/`gen_opts`
/// never see.
#[derive(Debug)]
pub struct ReqError {
    pub code: &'static str,
    pub message: String,
}

/// Session-vault three-way state every vault-touching handler needs. `Open`
/// carries no data itself — a caller in that arm re-reads `s.vault` while
/// still holding the guard `classify_access` was given.
///
/// `Locked` covers two situations on purpose: a vault that genuinely is
/// locked (`last_path` is set, `vault` is not), and a vault that is
/// momentarily out on loan to a `spawn_blocking` command (`borrow_identity`
/// is `Some`) — see `Session::begin_borrow`. The second case is transient,
/// not an absence: reporting `locked` is the fail-closed answer, and the
/// extension simply retries.
///
/// Only a session that has never opened a vault at all is `NoVault`.
enum Access {
    Open,
    Locked,
    NoVault,
}

/// Classifies an already-locked `Session` guard. Must be called while still
/// holding the session mutex: an `Open` result only promises `s.vault` is
/// `Some` at the moment of the call, not afterward.
fn classify_access(s: &kokos_core::session::Session) -> Access {
    if s.vault.is_some() {
        Access::Open
    } else if s.last_path.is_some() || s.borrow_identity().is_some() {
        Access::Locked
    } else {
        Access::NoVault
    }
}

/// Answers `ping` / `get_status`. `locked` means "no vault is readable" — the
/// session's `vault` is `None`. This is intentionally simpler than `Access`
/// above (it does not distinguish `Locked` from `NoVault`, since both read as
/// "you cannot read right now" for a status probe): `Access` exists for
/// handlers that must pick between `codes::LOCKED` and `codes::NO_VAULT`. A
/// poisoned session mutex is treated as locked: fail closed, same discipline
/// as `is_allowed_origin`.
pub fn status(app: &tauri::AppHandle, req: &Request) -> Response {
    let locked = app
        .state::<crate::state::AppState>()
        .sessions
        .lock()
        .map(|mut reg| reg.active_mut().map(|s| s.vault.is_none()).unwrap_or(true))
        .unwrap_or(true);

    if req.action == "ping" {
        Response::ok(
            &req.id,
            serde_json::json!({
                "app_version": app.package_info().version.to_string(),
                "protocol_version": kokos_nmh::protocol::PROTOCOL_VERSION,
                "locked": locked,
                "running": true,
            }),
        )
    } else {
        Response::ok(
            &req.id,
            serde_json::json!({
                "locked": locked,
                "running": true,
            }),
        )
    }
}

/// Reads and validates the payload's `url` field, shared by `get_logins`
/// and the optional `url` on `get_secret`/`get_totp`/`update_login`. A missing or non-string `url` is a
/// caller bug (`bad_request`); a present-but-unreadable one (`about:blank`,
/// `file:///x`, `""`, garbage) fails `url_match::host_of` and is
/// `invalid_url` — a different mistake, so it gets a different code.
fn url_arg(payload: &serde_json::Value) -> Result<String, ReqError> {
    let raw = payload
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ReqError {
            code: codes::BAD_REQUEST,
            message: "payload must carry a string 'url' field".to_string(),
        })?;
    if kokos_core::url_match::host_of(raw).is_none() {
        return Err(ReqError {
            code: codes::INVALID_URL,
            message: format!("'{raw}' is not a readable URL"),
        });
    }
    Ok(raw.to_string())
}

/// Reads `generate_password`'s payload: `{ length, options: { upper, lower,
/// digits, symbols, min_upper, min_lower, min_digits, min_symbols } }`.
/// Mirrors `commands::GenOptsDto`'s field names and defaults so
/// the browser-triggered generator matches the in-app one exactly.
///
/// `length` absent -> `20`; present but not an integer -> `bad_request`;
/// valid range is `4..=256` inclusive (the generator's own floor is 4 —
/// this wire contract adds the 256 ceiling), so both `0` and `5000` are
/// rejected. `options` absent (or JSON `null`) -> all four classes `true`,
/// all `min_*` `0`; a present `options` keeps that same per-field default
/// for any key it omits, so `{"symbols": false}` only turns symbols off.
/// A present `options` that is not a JSON object (string/array/number) is a
/// malformed request, not "use defaults" — rejected below, rather than
/// silently generating with defaults and never telling the caller.
///
/// Each of the four class booleans follows that same convention
/// individually: absent, or explicit JSON `null`, keeps its default `true`;
/// present-but-wrong-typed (`{"symbols": 0}`, `{"symbols": "false"}`) is
/// `bad_request`, never silently reinterpreted as `true` — the caller asking
/// for a lowercase-only password must be told, not handed uppercase anyway.
///
/// Every `min_*` is bounded here — individually against `length`, summed
/// against `length`, and against its class being enabled — BEFORE
/// `kokos_core::generator::generate` ever runs. `generate`'s `push_class`
/// helper loops `min` times doing a CSPRNG draw and a `Vec` push per
/// iteration, and only checks `required.len() > length` *after* that loop;
/// an unbounded `min_*` (the wire accepts values up into the billions/
/// `u64::MAX`, `length`'s only cap is 4..=256) is otherwise a wire-reachable
/// CPU/memory DoS on the connection's serving thread — reachable with the
/// vault LOCKED and with no confirmation, since `generate_password` is
/// deliberately the one action with neither gate. Rejecting here, before
/// `generate` is ever called, also happens to be strictly better than
/// letting the generator discover the same requests are unsatisfiable: a
/// `min_*` exceeding `length` (individually or summed) can never produce a
/// valid password anyway.
fn gen_opts(payload: &serde_json::Value) -> Result<kokos_core::generator::GenOpts, ReqError> {
    let bad = |msg: &str| ReqError {
        code: codes::BAD_REQUEST,
        message: msg.to_string(),
    };

    let length = match payload.get("length") {
        None | Some(serde_json::Value::Null) => 20,
        Some(v) => v.as_u64().ok_or_else(|| bad("length must be an integer"))? as usize,
    };
    if !(4..=256).contains(&length) {
        return Err(bad("length must be between 4 and 256"));
    }

    let opts = match payload.get("options") {
        None | Some(serde_json::Value::Null) => serde_json::Value::Null,
        Some(v) if v.is_object() => v.clone(),
        Some(_) => return Err(bad("options must be an object")),
    };
    let flag = |key: &str, default: bool| -> Result<bool, ReqError> {
        match opts.get(key) {
            None | Some(serde_json::Value::Null) => Ok(default),
            Some(v) => v
                .as_bool()
                .ok_or_else(|| bad(&format!("{key} must be a boolean"))),
        }
    };

    let count = |key: &str| -> Result<usize, ReqError> {
        match opts.get(key) {
            None | Some(serde_json::Value::Null) => Ok(0),
            Some(v) => {
                let n = v
                    .as_u64()
                    .ok_or_else(|| bad(&format!("{key} must be a non-negative integer")))?;
                usize::try_from(n).map_err(|_| bad(&format!("{key} is too large")))
            }
        }
    };

    let upper = flag("upper", true)?;
    let lower = flag("lower", true)?;
    let digits = flag("digits", true)?;
    let symbols = flag("symbols", true)?;
    let min_upper = count("min_upper")?;
    let min_lower = count("min_lower")?;
    let min_digits = count("min_digits")?;
    let min_symbols = count("min_symbols")?;

    for (name, min, enabled) in [
        ("min_upper", min_upper, upper),
        ("min_lower", min_lower, lower),
        ("min_digits", min_digits, digits),
        ("min_symbols", min_symbols, symbols),
    ] {
        if !enabled && min > 0 {
            return Err(bad(&format!(
                "{name} must be 0 when its character class is disabled"
            )));
        }
        if min > length {
            return Err(bad(&format!("{name} must not exceed length")));
        }
    }
    if min_upper + min_lower + min_digits + min_symbols > length {
        return Err(bad(
            "min_upper + min_lower + min_digits + min_symbols must not exceed length",
        ));
    }

    Ok(kokos_core::generator::GenOpts {
        length,
        upper,
        lower,
        digits,
        symbols,
        min_upper,
        min_lower,
        min_digits,
        min_symbols,
    })
}

/// Overwrites (never merges) the connection's `get_logins` candidate set.
/// Pulled out of `get_logins` as a pure seam — see
/// `scope_replacement_never_leaks_the_previous_sites_candidates` — so the
/// security property (a lookup for a new site drops the previous site's
/// candidates, even when the new lookup is empty) is directly testable
/// without a live `AppHandle`.
fn set_scope(scope: &mut ConnScope, ids: Vec<String>, url: &str) {
    scope.candidate_ids = ids;
    scope.last_domain =
        kokos_core::url_match::host_of(url).and_then(|h| kokos_core::url_match::etld_plus_one(&h));
}

/// Resets a connection's candidate set to empty/none. `get_logins` calls this
/// unconditionally as its very first statement — before payload validation
/// or session access — so that EVERY exit path (bad_request, invalid_url,
/// locked, no_vault, internal, and success) ends with a scope that reflects
/// only the current call. A failed lookup must never leave a wider (stale,
/// possibly wrong-site) scope than a successful one would: fail closed, since
/// the only cost of over-clearing is a repeat `get_logins`, while under-
/// clearing is a secret-disclosure path, since `anchored()` trusts
/// `candidate_ids` membership. Do NOT move this call back into only the
/// success branch — see `scope_is_cleared_...` tests below.
fn clear_scope(scope: &mut ConnScope) {
    scope.candidate_ids.clear();
    scope.last_domain = None;
}

/// `get_logins`: metadata only, no passwords, no confirmation, no
/// audit row (reading the list for an already-whitelisted extension is not a
/// security event, same as the app's own list view). Replaces — never
/// merges — the connection's candidate set on every call, including an
/// empty result, so a lookup for a new site cannot be followed by reusing a
/// previous site's candidates (see `ConnScope`'s doc comment).
pub fn get_logins(app: &tauri::AppHandle, req: &Request, scope: &mut ConnScope) -> Response {
    clear_scope(scope);

    let url = match url_arg(&req.payload) {
        Ok(u) => u,
        Err(e) => return Response::err(&req.id, e.code, &e.message),
    };

    let st = app.state::<crate::state::AppState>();
    let mut reg = match st.sessions.lock() {
        Ok(reg) => reg,
        Err(_) => return Response::err(&req.id, codes::LOCKED, "vault session is unavailable"),
    };
    let v = match reg.active_mut() {
        None => return Response::err(&req.id, codes::NO_VAULT, "no vault is open"),
        Some(s) => match classify_access(s) {
            Access::Locked => return Response::err(&req.id, codes::LOCKED, "vault is locked"),
            Access::NoVault => return Response::err(&req.id, codes::NO_VAULT, "no vault is open"),
            Access::Open => s
                .vault
                .as_ref()
                .expect("Access::Open guarantees a vault is present"),
        },
    };

    let hits = match kokos_core::logins::for_url(&v.conn, &url, MAX_ITEMS) {
        Ok(h) => h,
        Err(_) => return Response::err(&req.id, codes::INTERNAL, "failed to read the vault"),
    };

    let ids: Vec<String> = hits.iter().map(|h| h.id.clone()).collect();
    set_scope(scope, ids, &url);

    let items: Vec<serde_json::Value> = hits
        .into_iter()
        .map(|h| {
            serde_json::json!({
                "id": h.id,
                "title": h.title,
                "username": h.username,
                "hasTotp": h.has_totp,
            })
        })
        .collect();

    Response::ok(&req.id, serde_json::json!({ "items": items }))
}

/// `generate_password`: not vault data, so it takes no `app`/
/// session and is deliberately allowed while locked — it lets a user
/// register on a site with the app locked. Never logs or audits the
/// generated value.
pub fn generate_password(req: &Request) -> Response {
    let opts = match gen_opts(&req.payload) {
        Ok(o) => o,
        Err(e) => return Response::err(&req.id, e.code, &e.message),
    };
    match kokos_core::generator::generate(&opts) {
        Ok(password) => Response::ok(&req.id, serde_json::json!({ "password": password })),
        Err(_) => Response::err(&req.id, codes::BAD_REQUEST, "impossible password options"),
    }
}

/// Appends a security event to the open vault's audit log. Best-effort: a
/// locked vault has nowhere to write, and a failed append must never fail the
/// action. `detail` is a browser name or an eTLD+1 — NEVER a field value.
pub fn audit_event(app: &tauri::AppHandle, event: &str, detail: Option<&str>) {
    let st = app.state::<crate::state::AppState>();
    if let Ok(mut reg) = st.sessions.lock() {
        if let Some(s) = reg.active_mut() {
            if let Some(v) = s.vault.as_ref() {
                let _ = kokos_core::audit::append(&v.conn, event, detail);
            }
        }
    };
}


/// Domain anchoring (beyond the base action payloads): a secret request
/// must name an entry this connection was actually offered for the current
/// site, or prove the entry belongs to the URL it passes. Without this, a
/// whitelisted-but-compromised extension could walk entry ids and pull every
/// secret in the vault, because the per-site domain rule alone only ever
/// constrained `get_logins`.
///
/// A supplied `url` is a CLAIM about the page the user is on, and it must
/// NEVER be silently ignored (an earlier version of this function let the
/// candidate-set branch win unconditionally before `url` was ever looked at,
/// so an attacker-supplied `url` could ride along on an entry that was
/// legitimately offered for a DIFFERENT site, and that arbitrary domain then
/// went straight into the confirm prompt, the
/// `extension_denied`/`extension_secret` audit rows, and the `session_domain`
/// grant key, turning one human approval into a vault-wide bypass). The rule
/// now:
///
/// - `url` is `None` -> in scope only if `entry_id` is in
///   `scope.candidate_ids` (this connection's last `get_logins` actually
///   offered this entry for the current site).
/// - `url` is `Some(u)` AND `entry_id` IS in `scope.candidate_ids` -> in
///   scope only if `u` is `same_site` with `scope.last_domain` (the domain
///   that candidate set was actually built for). Candidate-set membership no
///   longer overrides a mismatched claimed `url`.
/// - `url` is `Some(u)` AND `entry_id` is NOT in `scope.candidate_ids` -> in
///   scope only if `u` is `same_site` with some value in `entry_urls` (the
///   entry's OWN `url`-typed field values — see `entry_urls_of`).
///
/// Truth table (`c` = entry_id in candidate_ids, `u` = an explicit url was
/// given, `m` = that url is same_site with the relevant domain —
/// `scope.last_domain` when `c` holds, an `entry_urls` member otherwise):
///
/// | c     | u   | m     | anchored? |
/// |-------|-----|-------|-----------|
/// | true  | no  | —     | true      |
/// | true  | yes | true  | true      |
/// | true  | yes | false | **false** |
/// | false | no  | —     | false     |
/// | false | yes | true  | true      |
/// | false | yes | false | false     |
///
/// The real gate against a compromised-but-whitelisted extension remains the
/// human confirmation (`confirm`), not this function — this only prevents an
/// attacker from choosing which domain the human is shown and which domain
/// gets logged/granted.
pub fn anchored(
    scope: &ConnScope,
    entry_id: &str,
    url: Option<&str>,
    entry_urls: &[String],
) -> bool {
    if scope.candidate_ids.iter().any(|id| id == entry_id) {
        return match (url, scope.last_domain.as_deref()) {
            (None, _) => true,
            (Some(u), Some(d)) => kokos_core::url_match::same_site(d, u),
            (Some(_), None) => false,
        };
    }
    match url {
        Some(u) => entry_urls
            .iter()
            .any(|stored| kokos_core::url_match::same_site(stored, u)),
        None => false,
    }
}

/// Values of an entry's `url`-**typed** fields only — never `title`, never
/// `notes`, never any other field type (widening this to any field that
/// merely looks like a URL would be a phishing surface). A
/// protected url field's `value` is already `None` from `entries::get`
/// (withheld before we ever see it), so it is simply absent from the result
/// here — fail-closed and intentional, not a bug: a protected url field
/// cannot anchor a request, only an unprotected one can.
fn entry_urls_of(fields: &[kokos_core::entries::Field]) -> Vec<String> {
    fields
        .iter()
        .filter(|f| f.field_type == "url")
        .filter_map(|f| f.value.clone())
        .filter(|v| !v.is_empty())
        .collect()
}

/// Field to reveal for `get_secret`: `want` may be a field name
/// (case-insensitive, trimmed) or a field id; absent = the entry's first
/// eligible field in `entries::get`'s own order (`sort_order ASC, id ASC`).
/// Eligible = `field_type == "secret" || is_protected`, EXCLUDING an otp
/// field regardless of that rule — a non-eligible field (plain
/// text/url/notes) is never selectable, even by exact id: otherwise
/// `get_secret` would become a way to read arbitrary text fields, not just
/// secrets. An otp field is doubly excluded: it is reachable ONLY through
/// `get_totp`, which emits `code`/`period`/`remaining` and never the stored
/// otpauth URI or base32 secret — the built-in TOTP template is
/// `is_protected = 1` (`kokos-core/src/db/schema.rs`'s `DEFAULT_TEMPLATES`),
/// so without this exclusion `get_secret {field: "TOTP"}` (or no `field` at all, when
/// the otp field sorts first) would hand the extension the permanent seed
/// under a confirm prompt that cannot even say so (`confirm`'s signature
/// carries no field name).
pub fn pick_secret_field(
    fields: &[kokos_core::entries::Field],
    want: Option<&str>,
) -> Option<String> {
    let secret = |f: &&kokos_core::entries::Field| {
        let is_otp = f.field_type == "otp" || f.template_id.as_deref() == Some("tpl_totp");
        !is_otp && (f.field_type == "secret" || f.is_protected)
    };
    match want {
        None => fields.iter().find(secret).map(|f| f.id.clone()),
        Some(w) => {
            let w = w.trim().to_ascii_lowercase();
            fields
                .iter()
                .find(|f| {
                    secret(f)
                        && (f.id.to_ascii_lowercase() == w || f.name.to_ascii_lowercase() == w)
                })
                .map(|f| f.id.clone())
        }
    }
}

/// Field to reveal for `get_totp`: unlike `pick_secret_field` there is no
/// `field` selector in the wire contract — an entry has at most one otp
/// field, so there is nothing to disambiguate. Matches either the field type
/// used by a hand-added otp field, or the built-in otp template
/// (`kokos-core/src/db/schema.rs`).
fn pick_otp_field(fields: &[kokos_core::entries::Field]) -> Option<String> {
    fields
        .iter()
        .find(|f| f.field_type == "otp" || f.template_id.as_deref() == Some("tpl_totp"))
        .map(|f| f.id.clone())
}

/// The display NAME of the field `pick_secret_field`/`pick_otp_field`/
/// `pick_password_field` selected -- NEVER a value. Exists purely to give
/// `confirm`'s prompt something concrete to show (e.g. "PIN" instead of a
/// generic "a password"), so the human is not asked to approve releasing or
/// overwriting an unnamed field. `None` when `id` does not match any field in
/// THIS slice -- deliberately fails closed to "nothing to show" rather than
/// reporting an unrelated field's name, which matters when a caller compares
/// an id picked from one snapshot against a name looked up in a different one
/// (see `update_login`'s pre/post-confirm comparison).
fn field_name_of(fields: &[kokos_core::entries::Field], id: &str) -> Option<String> {
    fields.iter().find(|f| f.id == id).map(|f| f.name.clone())
}

/// The entry's username, for display in the confirm prompt only (the
/// confirm event carries an optional `username`). Mirrors the `tpl_username` lookup
/// `entries::SUMMARY_COLS`/`logins::for_url` use elsewhere. A protected
/// username field's value is already `None` from `entries::get` (same
/// discipline as `get_logins`'s protected-username fix) — absent
/// here just means the prompt shows no username, which is fail-closed, not a
/// leak.
/// Falls back to the entry's email when there is no username field, matching
/// `logins::for_url` — an entry whose login is an email must not show an empty
/// name in the prompt it is about to authorise.
fn username_of(fields: &[kokos_core::entries::Field]) -> Option<String> {
    let by = |pred: &dyn Fn(&kokos_core::entries::Field) -> bool| {
        fields.iter().find(|f| pred(f)).and_then(|f| f.value.clone())
    };
    by(&|f| f.template_id.as_deref() == Some("tpl_username")).or_else(|| {
        by(&|f| f.template_id.as_deref() == Some("tpl_email") || f.field_type == "email")
    })
}

/// The domain used in the confirm prompt and audit rows: an explicit `url`'s
/// eTLD+1 wins when present, else the connection's last `get_logins` domain,
/// else the literal `"unknown"`. `url_match::host_of` having already
/// validated `url` by this point (see `optional_url_arg`), this is only ever
/// called with a `url` it can read — but is written total regardless, so a
/// malformed `url` degrades to the same fallback chain rather than panicking.
///
/// NOTE ON THE CURRENT `url_match::etld_plus_one` CONTRACT: for an IP
/// literal or a single-label host (e.g. `127.0.0.1`, `localhost`) it does
/// NOT return `None` as one might expect from its doc comment — it already
/// returns `Some(host)` (the bare host, used for literal comparison in
/// `same_site`). The `.unwrap_or(host)` below is still correct and is kept
/// as defensive belt-and-braces in case that contract ever tightens to a
/// real `None`; either way the observable behaviour is "fall back to the
/// bare host, never silently to `unknown`", which is what this function must
/// guarantee.
fn domain_for(url: Option<&str>, last_domain: Option<&str>) -> String {
    if let Some(u) = url {
        if let Some(host) = kokos_core::url_match::host_of(u) {
            return kokos_core::url_match::etld_plus_one(&host).unwrap_or(host);
        }
    }
    last_domain
        .map(|d| d.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Outcome of the existence-and-anchor decision, kept as a pure function
/// separate from `anchored` so the "no existence oracle" property is directly
/// testable without a live `Session`.
///
/// Existence must not leak: answering `entry_not_found` for an unknown id
/// and `not_in_scope` for a known-but-unanchored one would turn `get_secret`
/// into an oracle that tells a whitelisted extension which entry ids exist —
/// before any confirmation prompt and without an audit row for the probe.
/// Ids are uuids, so brute force is infeasible, but the leak is free to
/// close and closing it costs nothing. So an unknown id answers
/// `entry_not_found` ONLY when it was legitimately offered to this
/// connection (i.e. it once existed and has since been deleted) — every
/// other "no" answers the same `not_in_scope`, indistinguishable from an id
/// that never existed at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeDecision {
    Anchored,
    EntryNotFound,
    NotInScope,
}

fn scope_decision(entry_found: bool, was_candidate: bool, is_anchored: bool) -> ScopeDecision {
    if !entry_found {
        return if was_candidate {
            ScopeDecision::EntryNotFound
        } else {
            ScopeDecision::NotInScope
        };
    }
    if is_anchored {
        ScopeDecision::Anchored
    } else {
        ScopeDecision::NotInScope
    }
}

/// One confirmation request, as shown to the human and as scoped for a grant.
/// `field` is a field NAME (e.g. "Password", "PIN", "TOTP") -- NEVER a value:
/// this struct's `field` crosses into `confirm`'s emitted
/// `nmh-confirm-request` payload verbatim, so a caller that put a value here
/// would put that value on the wire to the frontend.
pub struct ConfirmReq<'a> {
    pub action: &'a str,
    /// The whitelisted caller origin (`chrome-extension://<id>/` or a
    /// Firefox extension id) the handshake already authenticated. Scopes
    /// the grant (`Grants` is keyed `(origin, domain)`, never the bare
    /// domain -- see that type's own doc comment for why); never shown in
    /// the prompt and never emitted on `nmh-confirm-request`.
    pub origin: &'a str,
    pub domain: &'a str,
    pub title: &'a str,
    pub username: Option<&'a str>,
    pub field: Option<&'a str>,
    /// The vault this request was scoped against (the active vault when the
    /// handler began). Grant lookups, the touch and any persisted grant all
    /// act on THIS vault, never a fresh `active_mut()`, so a vault switch
    /// during the confirmation wait cannot redirect an approval to another
    /// vault. Never emitted to the frontend.
    pub vault_id: &'a str,
}

/// Whether an ALLOWED confirmation should mint a `session_domain` grant (the
/// grant-capture rule, factored out as a pure, unit-tested seam). Only the
/// two READ actions ever capture a grant: a write
/// (`save_login`/`update_login`) always confirms regardless of mode
/// (`grants::needs_confirm` already enforces that on the way in), so
/// capturing a grant for one would be dead state rather than a live bug --
/// but keeping this whitelist explicit means a THIRD write action added later
/// does not silently start capturing grants just because someone forgot to
/// extend a blacklist instead.
fn should_capture_grant(action: &str, mode: &str, allowed: bool) -> bool {
    allowed && mode == "session_domain" && matches!(action, "get_secret" | "get_totp")
}

/// Whether an ALLOWED confirmation, with the human's "remember this site"
/// checkbox also set, should mint a PERSISTENT `kokos_core::nmh_grants` row.
/// The persistent counterpart to `should_capture_grant` just above: that
/// function mints a SESSION `nmh::confirm::Grants` entry, scoped to
/// `session_domain` mode and gone at the next lock/close/restart; this one
/// mints a row that survives all three, and ONLY when the live mode is
/// `remember_site` -- `remember` arriving `true` while the mode is
/// `always`/`session_domain`/`trust_extension` is a mismatch between what
/// the frontend sent and what the server-side settings actually allow (the
/// frontend is never the authority) and must be silently ignored, never
/// stored. A write action (`save_login`/`update_login`) never reaches here as
/// `true` either, for the same reason `should_capture_grant`'s own doc
/// comment gives for its own action whitelist: `needs_confirm` already forces
/// a write to confirm in every mode, so a write can never legitimately be
/// "the thing that got remembered" -- capturing a grant for one would let a
/// single approved save silently exempt every later READ for that site, which
/// is not what remembering a site is supposed to mean. `allowed = false` (a
/// Deny) never stores anything regardless of `remember`: a denial is not a
/// decision to trust the site, whatever box was ticked alongside it.
fn should_persist_grant(action: &str, mode: &str, allowed: bool, remember: bool) -> bool {
    allowed && remember && mode == "remember_site" && matches!(action, "get_secret" | "get_totp")
}

/// Converts the user-facing `nmh_session_minutes` setting into the `Duration`
/// `Grants::allow` needs. Widens through `u64` before multiplying by 60 so a
/// large setting cannot overflow the multiplication itself (a bare `u32 * 60`
/// overflows past roughly 71.5 million minutes; a `u64` of SECONDS does not
/// overflow until roughly 584 billion years). `0` produces a zero `Duration`;
/// `Grants::is_granted`'s expiry check is already strict (`deadline > now`,
/// never `>=`), so a zero-TTL grant is dead the instant it is minted.
fn grant_ttl(minutes: u32) -> std::time::Duration {
    std::time::Duration::from_secs(u64::from(minutes) * 60)
}

/// cap on the display fields (title/username) placed into the
/// nmh-confirm-request event, bounding the payload a whitelisted-but-compromised
/// extension can push into the WebView via save_login. Generous for real logins.
const MAX_CONFIRM_FIELD_CHARS: usize = 256;

/// Truncate to at most `max_chars` Unicode scalar values on a char boundary
/// (never splits a multi-byte char, always valid UTF-8). Display-only bound for
/// the confirm-request event payload; does not touch stored vault values.
fn clamp_confirm_field(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

/// Human confirmation -- see `ConfirmReq`'s own doc comment for the payload
/// shape. Every caller is written as if this blocks for up to 60s on a human:
/// the session mutex must NOT be held across it. `confirm` itself holds no
/// guard across the park either -- the settings guard is taken once and
/// dropped before the emit, and the only locks `Registry`/`Grants` take
/// internally (see that module's own lock-ordering note) are short,
/// leaf-level, and never held across a `send`/`recv`.
///
/// Two connections can park here simultaneously -- `Registry::open` mints an
/// independent request id and channel per call, so nothing here assumes a
/// single pending request.
///
/// `app.emit` succeeding is NOT proof that anyone is listening for the event
/// -- in tauri 2.11.5 it only errors on an event-name or serialisation
/// problem, never on "no webview exists". The real "nobody can answer" check
/// is the `get_webview_window("main")` lookup below, done BEFORE the park (a
/// `None` there forgets the entry and denies at once, instead of parking the
/// connection thread for the full 60s with nobody able to ever reply).
pub fn confirm(app: &tauri::AppHandle, r: ConfirmReq<'_>) -> bool {
    use tauri::{Emitter, Manager};
    let st = app.state::<crate::state::AppState>();

    let (mode, minutes) = match st.settings.lock() {
        Ok(s) => (s.nmh_confirm_mode.clone(), s.nmh_session_minutes),
        Err(_) => ("always".to_string(), 5),
    };

    let vault_id: &str = r.vault_id;

    let session_granted = st
        .nmh
        .grants
        .is_granted(vault_id, r.origin, r.domain, std::time::Instant::now());

    let persistent_granted = if mode == "remember_site" {
        match st.sessions.lock() {
            Ok(mut reg) => {
                let granted = if let Some(s) = reg.get_mut(vault_id) {
                    if let Access::Open = classify_access(s) {
                        let v = s
                            .vault
                            .as_ref()
                            .expect("Access::Open guarantees a vault is present");
                        kokos_core::nmh_grants::is_granted(&v.conn, r.origin, r.domain)
                            .unwrap_or(false)
                    } else {
                        false
                    }
                } else {
                    false
                };
                drop(reg);
                granted
            }
            Err(_) => false,
        }
    } else {
        false
    };

    if !super::grants::needs_confirm(r.action, &mode, session_granted, persistent_granted) {
        if mode == "remember_site" {
            if let Ok(mut reg) = st.sessions.lock() {
                if let Some(s) = reg.get_mut(vault_id) {
                    if let Access::Open = classify_access(s) {
                        let v = s
                            .vault
                            .as_ref()
                            .expect("Access::Open guarantees a vault is present");
                        let _ = kokos_core::nmh_grants::touch(
                            &v.conn,
                            r.origin,
                            r.domain,
                            kokos_core::db::now_unix(),
                        );
                    }
                }
            }
        }
        super::audit_grant_release(app, r.action, r.domain);
        return true;
    }

    let (req_id, rx) = st.nmh.confirms.open();
    let emitted = app.emit(
        "nmh-confirm-request",
        serde_json::json!({
            "req_id": req_id,
            "action": r.action,
            "domain": r.domain,
            "title": clamp_confirm_field(r.title, MAX_CONFIRM_FIELD_CHARS),
            "username": r.username.map(|u| clamp_confirm_field(u, MAX_CONFIRM_FIELD_CHARS)),
            "field": r.field,
            "mode": mode,
            "session_minutes": minutes,
        }),
    );
    if emitted.is_err() {
        st.nmh.confirms.forget(&req_id);
        return false;
    }
    let Some(w) = app.get_webview_window("main") else {
        st.nmh.confirms.forget(&req_id);
        return false;
    };
    let _ = w.show();
    let _ = w.set_focus();
    let _ = w.request_user_attention(Some(tauri::UserAttentionType::Informational));

    let answer = match rx.recv_timeout(std::time::Duration::from_secs(60)) {
        Ok(v) => v,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            st.nmh.confirms.forget(&req_id);
            let _ = app.emit(
                "nmh-confirm-cancel",
                serde_json::json!({ "req_id": req_id }),
            );
            super::grants::ConfirmAnswer {
                allowed: false,
                remember: false,
            }
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => super::grants::ConfirmAnswer {
            allowed: false,
            remember: false,
        },
    };
    let allowed = answer.allowed;

    if should_capture_grant(r.action, &mode, allowed) {
        st.nmh.grants.allow(
            vault_id,
            r.origin,
            r.domain,
            grant_ttl(minutes),
            std::time::Instant::now(),
        );
    }

    if should_persist_grant(r.action, &mode, allowed, answer.remember) {
        let borrowed = match st.sessions.lock() {
            Ok(mut reg) => match reg.get_mut(vault_id) {
                Some(s) => match classify_access(s) {
                    Access::Open => s.begin_borrow().map(|v| (vault_id.to_string(), v)),
                    Access::Locked | Access::NoVault => None,
                },
                None => None,
            },
            Err(_) => None,
        };
        let persisted = match borrowed {
            Some((vid, mut v)) => {
                let ok = kokos_core::nmh_grants::upsert(
                    &v.conn,
                    r.origin,
                    r.domain,
                    kokos_core::db::now_unix(),
                )
                .and_then(|_| kokos_core::vault::save(&mut v))
                .is_ok();
                if let Ok(mut reg) = st.sessions.lock() {
                    if let Some(s) = reg.get_mut(&vid) {
                        s.end_borrow(v);
                    }
                }
                ok
            }
            None => false,
        };
        if persisted {
            audit_event(app, "extension_grant_added", Some(r.domain));
        }
    }

    allowed
}

/// `entry_id`: missing or not a non-empty string → `bad_request`.
fn entry_id_arg(payload: &serde_json::Value) -> Result<String, ReqError> {
    payload
        .get("entry_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .ok_or_else(|| ReqError {
            code: codes::BAD_REQUEST,
            message: "payload must carry a non-empty string 'entry_id'".to_string(),
        })
}

/// The OPTIONAL `url` shared by `get_secret`/`get_totp`: the key may be
/// entirely absent or JSON `null` (fine — the domain falls back to the
/// connection's last `get_logins` site), but if present it must be a string
/// `host_of` can read, else `invalid_url`. Deliberately a separate helper
/// from `url_arg` (whose `url` is REQUIRED for `get_logins`) so a future edit
/// to one required-ness cannot silently change the other's.
fn optional_url_arg(payload: &serde_json::Value) -> Result<Option<String>, ReqError> {
    match payload.get("url") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => {
            let raw = v.as_str().ok_or_else(|| ReqError {
                code: codes::BAD_REQUEST,
                message: "'url', if present, must be a string".to_string(),
            })?;
            if kokos_core::url_match::host_of(raw).is_none() {
                return Err(ReqError {
                    code: codes::INVALID_URL,
                    message: format!("'{raw}' is not a readable URL"),
                });
            }
            Ok(Some(raw.to_string()))
        }
    }
}

/// The optional `field` selector for `get_secret`: the key may be entirely
/// absent or JSON `null` (both mean "the entry's first eligible field" -- see
/// `pick_secret_field`), but if the key IS present it must be a string. Same
/// call as for `gen_opts`'s `options` key (a non-object value is
/// `bad_request` rather than silently falling back to defaults, since that
/// could hand the caller a weaker request than the one it meant to send): a
/// present-but-malformed `field` (a number, object, array, or bool) must not
/// be silently reinterpreted as "no preference" and answered with a
/// different field than the caller named, with no error to notice by.
fn field_arg(payload: &serde_json::Value) -> Result<Option<String>, ReqError> {
    match payload.get("field") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v
            .as_str()
            .map(|s| Some(s.to_string()))
            .ok_or_else(|| ReqError {
                code: codes::BAD_REQUEST,
                message: "'field', if present, must be a string".to_string(),
            }),
    }
}

/// Data `get_secret`/`get_totp` need once the entry has cleared the
/// existence-and-anchor gate: everything is copied OUT of the session guard
/// (owned `String`s / a cloned `Vec<Field>`), so by the time this is
/// returned the guard is already dropped and nothing here borrows the vault.
struct SecretGate {
    /// Vault the entry was read from; every post-confirmation step must act
    /// on this vault, not whichever one is active by then.
    vault_id: String,
    entry_id: String,
    domain: String,
    title: String,
    username: Option<String>,
    fields: Vec<kokos_core::entries::Field>,
}

/// Shared prelude for `get_secret`/`get_totp` — the gates before field
/// selection (entry_id/url validation, domain, locked/no_vault,
/// read-and-drop-guard, the existence-and-anchor decision, and its
/// `not_in_scope` audit). `action` is `"get_secret"` or `"get_totp"`, used
/// only for the `not_in_scope` audit detail (`format!("{action}@{domain}")`).
///
/// Returns `Ok(gate)` when the caller should continue into its own field
/// selection + `confirm` + `reveal_field`, or `Err(response)` with a
/// fully-formed early response the caller must return immediately
/// (`bad_request` / `invalid_url` / `locked` / `no_vault` / `entry_not_found`
/// / `not_in_scope` / `internal`).
fn secret_gate(
    app: &tauri::AppHandle,
    req: &Request,
    scope: &ConnScope,
    action: &str,
) -> Result<SecretGate, Response> {
    let entry_id =
        entry_id_arg(&req.payload).map_err(|e| Response::err(&req.id, e.code, &e.message))?;
    let url =
        optional_url_arg(&req.payload).map_err(|e| Response::err(&req.id, e.code, &e.message))?;
    let domain = domain_for(url.as_deref(), scope.last_domain.as_deref());

    let st = app.state::<crate::state::AppState>();
    let mut reg = st
        .sessions
        .lock()
        .map_err(|_| Response::err(&req.id, codes::LOCKED, "vault session is unavailable"))?;
    let vault_id = match reg.active_id() {
        Some(id) => id.to_string(),
        None => return Err(Response::err(&req.id, codes::NO_VAULT, "no vault is open")),
    };
    let v = match reg.active_mut() {
        None => return Err(Response::err(&req.id, codes::NO_VAULT, "no vault is open")),
        Some(s) => match classify_access(s) {
            Access::Locked => return Err(Response::err(&req.id, codes::LOCKED, "vault is locked")),
            Access::NoVault => return Err(Response::err(&req.id, codes::NO_VAULT, "no vault is open")),
            Access::Open => s
                .vault
                .as_ref()
                .expect("Access::Open guarantees a vault is present"),
        },
    };

    let entry = match kokos_core::entries::get(&v.conn, &entry_id) {
        Ok(e) => e,
        Err(_) => {
            drop(reg);
            return Err(Response::err(
                &req.id,
                codes::INTERNAL,
                "failed to read the vault",
            ));
        }
    };
    let was_candidate = scope.candidate_ids.iter().any(|id| id == &entry_id);
    let (title, username, fields, entry_urls) = match &entry {
        Some(e) => (
            e.title.clone(),
            username_of(&e.fields),
            e.fields.clone(),
            entry_urls_of(&e.fields),
        ),
        None => (String::new(), None, Vec::new(), Vec::new()),
    };
    drop(reg);

    let is_anchored = entry.is_some() && anchored(scope, &entry_id, url.as_deref(), &entry_urls);
    match scope_decision(entry.is_some(), was_candidate, is_anchored) {
        ScopeDecision::EntryNotFound => Err(Response::err(
            &req.id,
            codes::ENTRY_NOT_FOUND,
            "entry not found",
        )),
        ScopeDecision::NotInScope => {
            let denial = format!("{action}@{domain}");
            super::audit_denial(app, &denial, &denial);
            Err(Response::err(
                &req.id,
                codes::NOT_IN_SCOPE,
                "entry is not in scope for this connection",
            ))
        }
        ScopeDecision::Anchored => Ok(SecretGate {
            vault_id,
            entry_id,
            domain,
            title,
            username,
            fields,
        }),
    }
}

/// `get_secret`. `confirm` is the human-confirmation gate -- see
/// `ConfirmReq`'s doc comment for the prompt's field-name contract.
pub fn get_secret(
    app: &tauri::AppHandle,
    req: &Request,
    scope: &ConnScope,
    origin: &str,
) -> Response {
    let gate = match secret_gate(app, req, scope, "get_secret") {
        Ok(g) => g,
        Err(resp) => return resp,
    };

    let field_want = match field_arg(&req.payload) {
        Ok(w) => w,
        Err(e) => return Response::err(&req.id, e.code, &e.message),
    };
    let field_id = match pick_secret_field(&gate.fields, field_want.as_deref()) {
        Some(id) => id,
        None => return Response::err(&req.id, codes::ENTRY_NOT_FOUND, "no secret field found"),
    };
    let field_name = field_name_of(&gate.fields, &field_id);

    if !confirm(
        app,
        ConfirmReq {
            action: "get_secret",
            origin,
            domain: &gate.domain,
            title: &gate.title,
            username: gate.username.as_deref(),
            field: field_name.as_deref(),
            vault_id: &gate.vault_id,
        },
    ) {
        let detail = format!("get_secret@{}", gate.domain);
        let key = format!("confirm:{detail}");
        super::audit_denial(app, &key, &detail);
        return Response::err(&req.id, codes::DENIED, "confirmation was denied");
    }

    let st = app.state::<crate::state::AppState>();
    let mut reg = match st.sessions.lock() {
        Ok(reg) => reg,
        Err(_) => return Response::err(&req.id, codes::LOCKED, "vault session is unavailable"),
    };
    let v = match reg.get_mut(&gate.vault_id) {
        None => return Response::err(&req.id, codes::NO_VAULT, "no vault is open"),
        Some(s) => match classify_access(s) {
            Access::Locked => return Response::err(&req.id, codes::LOCKED, "vault is locked"),
            Access::NoVault => return Response::err(&req.id, codes::NO_VAULT, "no vault is open"),
            Access::Open => s
                .vault
                .as_ref()
                .expect("Access::Open guarantees a vault is present"),
        },
    };
    match kokos_core::entries::reveal_field(&v.conn, &gate.entry_id, &field_id) {
        Ok(Some(value)) => {
            drop(reg);
            audit_event(app, "extension_secret", Some(&gate.domain));
            Response::ok(&req.id, serde_json::json!({ "value": value }))
        }
        Ok(None) => {
            drop(reg);
            Response::err(&req.id, codes::ENTRY_NOT_FOUND, "entry not found")
        }
        Err(_) => {
            drop(reg);
            Response::err(&req.id, codes::INTERNAL, "failed to read the vault")
        }
    }
}

/// `get_totp`. Identical gate order to `get_secret` through the confirmation
/// step, but selects the entry's otp field instead of a named secret field,
/// and answers with the current six-digit code rather than a raw value. The
/// otp secret itself never leaves core: only `code`/`period`/`remaining`
/// cross the wire, never the stored otpauth URI or base32 secret, in the
/// response, in an error, or in an audit row.
pub fn get_totp(
    app: &tauri::AppHandle,
    req: &Request,
    scope: &ConnScope,
    origin: &str,
) -> Response {
    let gate = match secret_gate(app, req, scope, "get_totp") {
        Ok(g) => g,
        Err(resp) => return resp,
    };

    let field_id = match pick_otp_field(&gate.fields) {
        Some(id) => id,
        None => return Response::err(&req.id, codes::ENTRY_NOT_FOUND, "no otp field found"),
    };
    let field_name = field_name_of(&gate.fields, &field_id);

    if !confirm(
        app,
        ConfirmReq {
            action: "get_totp",
            origin,
            domain: &gate.domain,
            title: &gate.title,
            username: gate.username.as_deref(),
            field: field_name.as_deref(),
            vault_id: &gate.vault_id,
        },
    ) {
        let detail = format!("get_totp@{}", gate.domain);
        let key = format!("confirm:{detail}");
        super::audit_denial(app, &key, &detail);
        return Response::err(&req.id, codes::DENIED, "confirmation was denied");
    }

    let st = app.state::<crate::state::AppState>();
    let mut reg = match st.sessions.lock() {
        Ok(reg) => reg,
        Err(_) => return Response::err(&req.id, codes::LOCKED, "vault session is unavailable"),
    };
    let v = match reg.get_mut(&gate.vault_id) {
        None => return Response::err(&req.id, codes::NO_VAULT, "no vault is open"),
        Some(s) => match classify_access(s) {
            Access::Locked => return Response::err(&req.id, codes::LOCKED, "vault is locked"),
            Access::NoVault => return Response::err(&req.id, codes::NO_VAULT, "no vault is open"),
            Access::Open => s
                .vault
                .as_ref()
                .expect("Access::Open guarantees a vault is present"),
        },
    };
    match kokos_core::entries::reveal_field(&v.conn, &gate.entry_id, &field_id) {
        Ok(Some(raw)) => {
            let raw = zeroize::Zeroizing::new(raw);
            drop(reg);
            match kokos_core::totp::parse(&raw) {
                Ok(params) => {
                    let code =
                        kokos_core::totp::code_at(&params, kokos_core::db::now_unix() as u64);
                    audit_event(app, "extension_totp", Some(&gate.domain));
                    Response::ok(
                        &req.id,
                        serde_json::json!({
                            "code": code.code,
                            "period": code.period,
                            "remaining": code.remaining,
                        }),
                    )
                }
                Err(_) => Response::err(&req.id, codes::INTERNAL, "failed to read the otp field"),
            }
        }
        Ok(None) => {
            drop(reg);
            Response::err(&req.id, codes::ENTRY_NOT_FOUND, "entry not found")
        }
        Err(_) => {
            drop(reg);
            Response::err(&req.id, codes::INTERNAL, "failed to read the vault")
        }
    }
}


/// The three fields a browser-saved login carries. Uses the built-in template
/// ids (`db/schema.rs::DEFAULT_TEMPLATES`) so the entry looks native in the
/// app's own editor. Nothing beyond these three is ever invented.
pub fn new_login_fields(
    url: &str,
    username: &str,
    password: &str,
) -> Vec<kokos_core::entries::NewField> {
    vec![
        kokos_core::entries::NewField {
            template_id: Some("tpl_username".into()),
            name: "Username".into(),
            value: Some(username.to_string()),
            is_protected: false,
            field_type: "text".into(),
        },
        kokos_core::entries::NewField {
            template_id: Some("tpl_password".into()),
            name: "Password".into(),
            value: Some(password.to_string()),
            is_protected: true,
            field_type: "secret".into(),
        },
        kokos_core::entries::NewField {
            template_id: Some("tpl_url".into()),
            name: "URL".into(),
            value: Some(url.to_string()),
            is_protected: false,
            field_type: "url".into(),
        },
    ]
}

/// Validated `save_login` payload: `{ url, username, password, title? }`.
pub struct SaveArgs {
    pub url: String,
    pub username: String,
    pub password: String,
    pub title: String,
}

/// `url` — required, must be readable (`url_arg` covers both "missing/not a
/// string" -> `bad_request` and "present but unreadable" -> `invalid_url`).
/// `username` — required string, empty allowed. `password` — required,
/// non-empty. `title` — optional: absent or explicit JSON `null` falls back
/// to the url's own host, so a browser that never sends a title still gets a
/// sane entry name; a present value that is not a string is `bad_request` —
/// never silently treated as absent and replaced by the host, same convention
/// as `field_arg`. A present string that is blank after trimming ALSO falls
/// back to the host (unchanged: a blank title is not a real title, distinct
/// from "wrong type").
pub fn save_args(payload: &serde_json::Value) -> Result<SaveArgs, ReqError> {
    let url = url_arg(payload)?;
    let username = payload
        .get("username")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ReqError {
            code: codes::BAD_REQUEST,
            message: "payload must carry a string 'username' field".to_string(),
        })?
        .to_string();
    let password = payload
        .get("password")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ReqError {
            code: codes::BAD_REQUEST,
            message: "payload must carry a non-empty string 'password' field".to_string(),
        })?
        .to_string();
    let raw_title = match payload.get("title") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(v.as_str().ok_or_else(|| ReqError {
            code: codes::BAD_REQUEST,
            message: "'title', if present, must be a string".to_string(),
        })?),
    };
    let title = raw_title
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| kokos_core::url_match::host_of(&url).unwrap_or_else(|| url.clone()));
    Ok(SaveArgs {
        url,
        username,
        password,
        title,
    })
}

/// Validated `update_login` payload: `{ entry_id, password, url? }`. `url`,
/// if present, is validated the same way `get_secret`'s optional `url` is
/// (`optional_url_arg`) so a malformed one is rejected here too -- but it is
/// not carried forward in `UpdateArgs`: `secret_gate` re-derives it from this
/// same payload to compute the domain and the anchoring decision, so there is
/// nothing left for this struct to do with a second copy of it.
pub struct UpdateArgs {
    pub entry_id: String,
    pub password: String,
}

pub fn update_args(payload: &serde_json::Value) -> Result<UpdateArgs, ReqError> {
    let entry_id = entry_id_arg(payload)?;
    let password = payload
        .get("password")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ReqError {
            code: codes::BAD_REQUEST,
            message: "payload must carry a non-empty string 'password' field".to_string(),
        })?
        .to_string();
    optional_url_arg(payload)?;
    Ok(UpdateArgs { entry_id, password })
}

/// Selects the field `update_login` overwrites. Deliberately
/// NOT `pick_secret_field`'s rule (first `secret`-eligible field in sort
/// order): on a migrated Go vault a protected `PIN` can easily be sorted
/// before `Password`, and blindly taking the first eligible field would
/// silently overwrite the PIN with the site's password -- corruption no
/// error would ever surface. Selection order:
/// 1. the field with `template_id == Some("tpl_password")`, if present;
/// 2. otherwise the first field with `field_type == "secret"`;
/// 3. otherwise the first `is_protected` field that is NOT an otp field;
/// 4. none of the above -> `None` (caller maps this to `entry_not_found`).
/// Never invents a password field: an entry with no secret at all is a
/// caller mistake, not a request to add one.
///
/// Why the otp exclusion on tier 3: tiers 1 and 2 can never match an otp
/// field (its `template_id` is never `tpl_password` and its `field_type` is
/// `"otp"`, never `"secret"`), but tier 3's bare `is_protected` check does
/// not look at `field_type` at all, and the built-in TOTP template IS
/// `is_protected = 1`. Without this exclusion, an entry whose only protected
/// field is its otp field would have `update_login` silently overwrite the
/// TOTP seed with the site's new password — permanent, silent data loss with
/// no error to notice by. Same exclusion rule as `pick_secret_field`.
pub fn pick_password_field(fields: &[kokos_core::entries::Field]) -> Option<String> {
    fields
        .iter()
        .find(|f| f.template_id.as_deref() == Some("tpl_password"))
        .map(|f| f.id.clone())
        .or_else(|| {
            fields
                .iter()
                .find(|f| f.field_type == "secret")
                .map(|f| f.id.clone())
        })
        .or_else(|| {
            fields
                .iter()
                .find(|f| {
                    f.is_protected
                        && f.field_type != "otp"
                        && f.template_id.as_deref() != Some("tpl_totp")
                })
                .map(|f| f.id.clone())
        })
}

/// Every field the entry currently has, carried forward by id so nothing is
/// deleted, with only the target field's value replaced. `reconcile_fields`
/// (kokos-core) DELETEs any existing row whose id is absent from the input
/// list -- this is the entire reason this function exists: a patch built any
/// other way (e.g. just the changed field) would silently delete every other
/// field on the entry. `FieldValue::Keep` on every non-target field means the
/// stored value is never read here and never resubmitted --
/// `reconcile_fields` leaves a `Keep`ed row's `value` column byte-untouched
/// in SQL. Order is preserved (mirrors the input slice's order, which is
/// `entries::get`'s own `sort_order ASC, id ASC`), and
/// `template_id`/`name`/`is_protected`/`field_type` are copied verbatim
/// -- `reconcile_fields`'s UPDATE always rewrites those four columns even
/// for a `Keep`ed value, so a slip here would silently retype or unprotect a
/// field on save.
pub fn update_patch_fields(
    fields: &[kokos_core::entries::Field],
    target_field_id: &str,
    new_password: &str,
) -> Vec<kokos_core::entries::FieldInput> {
    fields
        .iter()
        .map(|f| kokos_core::entries::FieldInput {
            id: Some(f.id.clone()),
            template_id: f.template_id.clone(),
            name: f.name.clone(),
            is_protected: f.is_protected,
            field_type: f.field_type.clone(),
            value: if f.id == target_field_id {
                kokos_core::entries::FieldValue::Set(new_password.to_string())
            } else {
                kokos_core::entries::FieldValue::Keep
            },
        })
        .collect()
}

/// `save_login`: creates a new entry at the vault root from a
/// browser-submitted login. Writes always confirm, even in `session_domain`
/// mode -- `grants::needs_confirm` enforces that unconditionally for
/// `save_login`/`update_login`. The entry does not exist yet at confirm time,
/// so `ConfirmReq.field` is always `None` here.
///
/// On success it emits `vault-changed` with the vault id, so an open window
/// refreshes and shows the new entry.
pub fn save_login(app: &tauri::AppHandle, req: &Request, origin: &str) -> Response {
    let args = match save_args(&req.payload) {
        Ok(a) => a,
        Err(e) => return Response::err(&req.id, e.code, &e.message),
    };

    let st = app.state::<crate::state::AppState>();
    // The vault this save is scoped to: captured before the confirmation
    // wait and used for the write, so a vault switch while the prompt is up
    // cannot redirect an approved save into a different vault.
    let target_vault: String = {
        let mut reg = match st.sessions.lock() {
            Ok(reg) => reg,
            Err(_) => return Response::err(&req.id, codes::LOCKED, "vault session is unavailable"),
        };
        match reg.active_mut() {
            None => return Response::err(&req.id, codes::NO_VAULT, "no vault is open"),
            Some(s) => match classify_access(s) {
                Access::Locked => return Response::err(&req.id, codes::LOCKED, "vault is locked"),
                Access::NoVault => return Response::err(&req.id, codes::NO_VAULT, "no vault is open"),
                Access::Open => {}
            },
        }
        match reg.active_id() {
            Some(id) => id.to_string(),
            None => return Response::err(&req.id, codes::NO_VAULT, "no vault is open"),
        }
    };

    let domain = domain_for(Some(&args.url), None);
    if !confirm(
        app,
        ConfirmReq {
            action: "save_login",
            origin,
            domain: &domain,
            title: &args.title,
            username: Some(&args.username),
            field: None,
            vault_id: &target_vault,
        },
    ) {
        let detail = format!("save_login@{domain}");
        let key = format!("confirm:{detail}");
        super::audit_denial(app, &key, &detail);
        return Response::err(&req.id, codes::DENIED, "confirmation was denied");
    }

    let (vid, mut v) = {
        let mut reg = match st.sessions.lock() {
            Ok(reg) => reg,
            Err(_) => return Response::err(&req.id, codes::LOCKED, "vault session is unavailable"),
        };
        let id = target_vault.clone();
        let Some(s) = reg.get_mut(&id) else {
            return Response::err(&req.id, codes::NO_VAULT, "no vault is open");
        };
        match classify_access(s) {
            Access::Locked => return Response::err(&req.id, codes::LOCKED, "vault is locked"),
            Access::NoVault => return Response::err(&req.id, codes::NO_VAULT, "no vault is open"),
            Access::Open => {}
        }
        let v = s
            .begin_borrow()
            .expect("Access::Open guarantees a vault is present");
        (id, v)
    };

    let now = kokos_core::db::now_unix();
    let new_entry = kokos_core::entries::NewEntry {
        title: args.title,
        folder_id: None,
        notes: None,
        entry_type: "login".into(),
        fields: new_login_fields(&args.url, &args.username, &args.password),
    };
    let outcome = kokos_core::entries::create(&v.conn, new_entry, now).and_then(|created| {
        kokos_core::vault::save(&mut v)?;
        Ok(created)
    });

    match st.sessions.lock() {
        Ok(mut reg) => match reg.get_mut(&vid) {
            Some(s) => s.end_borrow(v),
            None => return Response::err(&req.id, codes::INTERNAL, "vault session is unavailable"),
        },
        Err(_) => return Response::err(&req.id, codes::INTERNAL, "vault session is unavailable"),
    }

    match outcome {
        Ok(created) => {
            audit_event(app, "extension_login_saved", Some(&domain));
            use tauri::Emitter;
            let _ = app.emit("vault-changed", serde_json::json!({ "vault_id": vid }));
            Response::ok(&req.id, serde_json::json!({ "entry_id": created.id }))
        }
        Err(_) => Response::err(&req.id, codes::INTERNAL, "failed to save the entry"),
    }
}

/// Ends the borrow taken for `update_login`'s write and returns `early` --
/// unless the session mutex is itself poisoned, in which case the borrow
/// can no longer be returned at all and the same generic INTERNAL fold
/// every other end_borrow call site in this file already uses takes over
/// instead. Every early return of the post-confirm fresh-read / re-anchor
/// recheck (below) goes through this, so the session is never left
/// permanently borrowed on one of those exits (the app could then neither
/// lock nor close).
///
/// `vid` is the id `update_login` resolved when it took the borrow
/// (`reg.active_id()` at begin-borrow time) -- this returns the vault to THAT
/// SAME session via `reg.get_mut(vid)`, never a fresh `active_mut()`.
/// `update_login`'s post-confirm section (a re-read, the fresh-vs-stale field
/// comparison, the anchor re-check, and the actual write) all run between the
/// original begin-borrow and whichever exit reaches this function -- long
/// enough for a concurrent `switch_vault` to change which session is active.
/// A fresh `active_mut()` here would then hand a DIFFERENT (now-active)
/// session this vault's decrypted `OpenVault`, leaking one vault's contents
/// into another session's slot and stranding the original one
/// `borrowed = true` forever. Same `(vid, v)`-pinning discipline
/// `commands::save_vault` already uses via `resolve_vault_id`.
fn end_borrow_then(
    st: &crate::state::AppState,
    vid: &str,
    v: kokos_core::vault::OpenVault,
    early: Response,
) -> Response {
    match st.sessions.lock() {
        Ok(mut reg) => match reg.get_mut(vid) {
            Some(s) => {
                s.end_borrow(v);
                early
            }
            None => Response::err(&early.id, codes::INTERNAL, "vault session is unavailable"),
        },
        Err(_) => Response::err(&early.id, codes::INTERNAL, "vault session is unavailable"),
    }
}

/// `update_login`. Gate order is identical to `get_secret` (reuses
/// `secret_gate`, which itself reuses `scope_decision`): payload validation
/// -> locked/no_vault -> the existence-and-anchor decision
/// (`not_in_scope`/`entry_not_found`, existence oracle closed the same way)
/// -> pick the DISPLAY target field -> `confirm` (always, even in
/// `session_domain` mode) -> `denied` on refusal. See the module-level
/// field-survival test for the property `update_patch_fields` exists to
/// guarantee: a patch carrying only the changed field would silently delete
/// every other field on the entry (TOTP seeds, PINs, custom fields) --
/// `reconcile_fields` DELETEs any existing row whose id is absent from the
/// input list.
///
/// The field named in the confirm prompt must be the field actually written.
/// The target is picked TWICE -- once from `gate.fields` (pre-confirm, to
/// name it in the prompt) and once from `fresh.fields` (post-confirm, to
/// build the write) -- and if the two picks disagree the entry changed under
/// the wait, so the write is aborted rather than overwriting a field the
/// human never saw named.
pub fn update_login(
    app: &tauri::AppHandle,
    req: &Request,
    scope: &ConnScope,
    origin: &str,
) -> Response {
    let args = match update_args(&req.payload) {
        Ok(a) => a,
        Err(e) => return Response::err(&req.id, e.code, &e.message),
    };

    let gate = match secret_gate(app, req, scope, "update_login") {
        Ok(g) => g,
        Err(resp) => return resp,
    };

    let pre_field_id = match pick_password_field(&gate.fields) {
        Some(id) => id,
        None => return Response::err(&req.id, codes::ENTRY_NOT_FOUND, "no password field found"),
    };
    let field_name = field_name_of(&gate.fields, &pre_field_id);

    if !confirm(
        app,
        ConfirmReq {
            action: "update_login",
            origin,
            domain: &gate.domain,
            title: &gate.title,
            username: gate.username.as_deref(),
            field: field_name.as_deref(),
            vault_id: &gate.vault_id,
        },
    ) {
        let detail = format!("update_login@{}", gate.domain);
        let key = format!("confirm:{detail}");
        super::audit_denial(app, &key, &detail);
        return Response::err(&req.id, codes::DENIED, "confirmation was denied");
    }

    let st = app.state::<crate::state::AppState>();
    let (vid, mut v) = {
        let mut reg = match st.sessions.lock() {
            Ok(reg) => reg,
            Err(_) => return Response::err(&req.id, codes::LOCKED, "vault session is unavailable"),
        };
        let id = gate.vault_id.clone();
        let Some(s) = reg.get_mut(&id) else {
            return Response::err(&req.id, codes::NO_VAULT, "no vault is open");
        };
        match classify_access(s) {
            Access::Locked => return Response::err(&req.id, codes::LOCKED, "vault is locked"),
            Access::NoVault => return Response::err(&req.id, codes::NO_VAULT, "no vault is open"),
            Access::Open => {}
        }
        let v = s
            .begin_borrow()
            .expect("Access::Open guarantees a vault is present");
        (id, v)
    };

    let fresh = match kokos_core::entries::get(&v.conn, &args.entry_id) {
        Ok(Some(e)) => e,
        Ok(None) => {
            return end_borrow_then(
                &st,
                &vid,
                v,
                Response::err(&req.id, codes::ENTRY_NOT_FOUND, "entry not found"),
            );
        }
        Err(_) => {
            return end_borrow_then(
                &st,
                &vid,
                v,
                Response::err(&req.id, codes::INTERNAL, "failed to read the vault"),
            );
        }
    };

    let field_id = match pick_password_field(&fresh.fields) {
        Some(id) => id,
        None => {
            return end_borrow_then(
                &st,
                &vid,
                v,
                Response::err(&req.id, codes::ENTRY_NOT_FOUND, "no password field found"),
            );
        }
    };

    if field_id != pre_field_id {
        let resp = end_borrow_then(
            &st,
            &vid,
            v,
            Response::err(
                &req.id,
                codes::DENIED,
                "the entry changed during confirmation",
            ),
        );
        let detail = format!("update_login@{}", gate.domain);
        let key = format!("confirm:{detail}");
        super::audit_denial(app, &key, &detail);
        return resp;
    }

    let fresh_urls = entry_urls_of(&fresh.fields);
    let url = optional_url_arg(&req.payload).ok().flatten();
    if !anchored(scope, &args.entry_id, url.as_deref(), &fresh_urls) {
        let resp = end_borrow_then(
            &st,
            &vid,
            v,
            Response::err(
                &req.id,
                codes::NOT_IN_SCOPE,
                "entry is not in scope for this connection",
            ),
        );
        let denial = format!("update_login@{}", gate.domain);
        super::audit_denial(app, &denial, &denial);
        return resp;
    }

    let patch_fields = update_patch_fields(&fresh.fields, &field_id, &args.password);

    let now = kokos_core::db::now_unix();
    let patch = kokos_core::entries::EntryPatch {
        title: None,
        notes: None,
        is_favorite: None,
        folder_id: None,
        fields: Some(patch_fields),
    };
    let outcome = match kokos_core::entries::update(&v.conn, &args.entry_id, patch, now) {
        Ok(Some(_)) => kokos_core::vault::save(&mut v).map(|_| true),
        Ok(None) => Ok(false),
        Err(e) => Err(e),
    };

    match st.sessions.lock() {
        Ok(mut reg) => match reg.get_mut(&vid) {
            Some(s) => s.end_borrow(v),
            None => return Response::err(&req.id, codes::INTERNAL, "vault session is unavailable"),
        },
        Err(_) => return Response::err(&req.id, codes::INTERNAL, "vault session is unavailable"),
    }

    match outcome {
        Ok(true) => {
            audit_event(app, "extension_login_updated", Some(&gate.domain));
            use tauri::Emitter;
            let _ = app.emit("vault-changed", serde_json::json!({ "vault_id": vid }));
            Response::ok(&req.id, serde_json::json!({ "ok": true }))
        }
        Ok(false) => Response::err(&req.id, codes::ENTRY_NOT_FOUND, "entry not found"),
        Err(_) => Response::err(&req.id, codes::INTERNAL, "failed to update the entry"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_opts_are_read_with_sane_defaults_and_clamped() {
        let o = gen_opts(&serde_json::json!({ "length": 20 })).unwrap();
        assert_eq!(o.length, 20);
        assert!(
            o.lower && o.upper && o.digits,
            "an options-less request still generates a strong password"
        );

        let o = gen_opts(&serde_json::json!({ "length": 8, "options": { "symbols": false, "digits": true, "upper": false, "lower": true } })).unwrap();
        assert_eq!((o.length, o.symbols, o.upper), (8, false, false));

        assert!(
            gen_opts(&serde_json::json!({ "length": 0 })).is_err(),
            "0-length is a bad request"
        );
        assert!(
            gen_opts(&serde_json::json!({ "length": 5000 })).is_err(),
            "absurd length is a bad request"
        );
    }

    #[test]
    fn url_payload_must_carry_a_readable_url() {
        assert_eq!(
            url_arg(&serde_json::json!({ "url": "https://example.com" })).unwrap(),
            "https://example.com"
        );
        assert!(url_arg(&serde_json::json!({})).is_err());
        assert!(url_arg(&serde_json::json!({ "url": "about:blank" })).is_err());
    }

    #[test]
    fn item_cap_matches_the_spec() {
        assert_eq!(MAX_ITEMS, 50);
    }


    #[test]
    fn url_arg_distinguishes_bad_request_from_invalid_url() {
        let missing = url_arg(&serde_json::json!({})).unwrap_err();
        assert_eq!(
            missing.code,
            codes::BAD_REQUEST,
            "a missing url key is a caller bug, not an unreadable URL"
        );

        let unreadable = url_arg(&serde_json::json!({ "url": "about:blank" })).unwrap_err();
        assert_eq!(
            unreadable.code,
            codes::INVALID_URL,
            "a present but unparseable url must NOT share bad_request's code"
        );
    }


    #[test]
    fn gen_opts_defaults_apply_when_length_and_options_are_entirely_absent() {
        let o = gen_opts(&serde_json::json!({})).unwrap();
        assert_eq!(o.length, 20, "no length at all still defaults to 20");
        assert!(o.upper && o.lower && o.digits && o.symbols);
    }

    #[test]
    fn gen_opts_a_partial_options_object_only_overrides_the_key_it_names() {
        let o = gen_opts(&serde_json::json!({ "options": { "symbols": false } })).unwrap();
        assert!(!o.symbols);
        assert!(
            o.upper && o.lower && o.digits,
            "keys absent from a present options object keep their defaults"
        );
    }

    #[test]
    fn gen_opts_min_values_round_trip_from_the_payload() {
        let o = gen_opts(&serde_json::json!({
            "length": 30,
            "options": { "min_upper": 2, "min_lower": 3, "min_digits": 4, "min_symbols": 5 }
        }))
        .unwrap();
        assert_eq!(
            (o.min_upper, o.min_lower, o.min_digits, o.min_symbols),
            (2, 3, 4, 5)
        );
    }

    #[test]
    fn gen_opts_length_boundaries_4_and_256_are_accepted_3_and_257_rejected() {
        assert!(gen_opts(&serde_json::json!({ "length": 4 })).is_ok());
        assert!(gen_opts(&serde_json::json!({ "length": 256 })).is_ok());
        assert!(
            gen_opts(&serde_json::json!({ "length": 3 })).is_err(),
            "an off-by-one in the floor would ship silently without this"
        );
        assert!(
            gen_opts(&serde_json::json!({ "length": 257 })).is_err(),
            "an off-by-one in the ceiling would ship silently without this"
        );
    }


    #[test]
    fn gen_opts_rejects_a_min_that_is_not_a_non_negative_integer() {
        assert_eq!(
            gen_opts(&serde_json::json!({ "options": { "min_upper": -1 } }))
                .unwrap_err()
                .code,
            codes::BAD_REQUEST,
            "negative min_upper must not silently become 0"
        );
        assert_eq!(
            gen_opts(&serde_json::json!({ "options": { "min_upper": 2.5 } }))
                .unwrap_err()
                .code,
            codes::BAD_REQUEST,
            "non-integral float min_upper must be rejected"
        );
        assert_eq!(
            gen_opts(&serde_json::json!({ "options": { "min_upper": 5.0 } }))
                .unwrap_err()
                .code,
            codes::BAD_REQUEST,
            "an integral float (5.0) is still a JSON float, not an integer, per \
             serde_json::Number::as_u64 -- must be rejected, not silently accepted"
        );
        assert_eq!(
            gen_opts(&serde_json::json!({ "options": { "min_upper": "5" } }))
                .unwrap_err()
                .code,
            codes::BAD_REQUEST,
            "a string min_upper must be rejected"
        );
    }

    #[test]
    fn gen_opts_rejects_a_min_for_a_disabled_character_class() {
        let err = gen_opts(&serde_json::json!({
            "options": { "symbols": false, "min_symbols": 3 }
        }))
        .unwrap_err();
        assert_eq!(
            err.code,
            codes::BAD_REQUEST,
            "min_symbols > 0 with symbols disabled is unsatisfiable"
        );
    }

    #[test]
    fn gen_opts_rejects_a_single_min_exceeding_length() {
        let err = gen_opts(&serde_json::json!({
            "length": 5,
            "options": { "min_upper": 10 }
        }))
        .unwrap_err();
        assert_eq!(err.code, codes::BAD_REQUEST);
    }

    #[test]
    fn gen_opts_rejects_mins_that_individually_fit_but_sum_past_length() {
        let err = gen_opts(&serde_json::json!({
            "length": 10,
            "options": { "min_upper": 5, "min_lower": 5, "min_digits": 5, "min_symbols": 5 }
        }))
        .unwrap_err();
        assert_eq!(err.code, codes::BAD_REQUEST);
    }

    #[test]
    fn gen_opts_rejects_huge_min_upper_fast() {
        let start = std::time::Instant::now();
        let err = gen_opts(&serde_json::json!({
            "length": 10,
            "options": { "min_upper": u64::MAX }
        }))
        .unwrap_err();
        assert_eq!(err.code, codes::BAD_REQUEST);
        assert!(
            start.elapsed().as_millis() < 200,
            "min_upper: u64::MAX must be rejected immediately, took {:?}",
            start.elapsed()
        );

        let start = std::time::Instant::now();
        let err = gen_opts(&serde_json::json!({
            "length": 10,
            "options": { "min_upper": 10_000_000 }
        }))
        .unwrap_err();
        assert_eq!(err.code, codes::BAD_REQUEST);
        assert!(
            start.elapsed().as_millis() < 200,
            "min_upper: 10_000_000 must be rejected immediately, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn gen_opts_accepts_a_satisfiable_min_combination_and_it_generates() {
        let o = gen_opts(&serde_json::json!({
            "length": 8,
            "options": { "min_upper": 2, "min_lower": 2, "min_digits": 2, "min_symbols": 2 }
        }))
        .unwrap();
        let pw = kokos_core::generator::generate(&o).unwrap();
        assert_eq!(pw.chars().count(), 8);
    }

    #[test]
    fn gen_opts_accepts_a_min_exactly_equal_to_length() {
        let o = gen_opts(&serde_json::json!({
            "length": 6,
            "options": { "upper": true, "lower": false, "digits": false, "symbols": false, "min_upper": 6 }
        }))
        .unwrap();
        let pw = kokos_core::generator::generate(&o).unwrap();
        assert_eq!(pw.chars().count(), 6);
        assert!(pw.chars().all(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn generate_password_end_to_end_rejects_a_huge_min_upper_fast() {
        let req = Request {
            id: "r-huge".into(),
            version: 1,
            action: "generate_password".into(),
            payload: serde_json::json!({
                "length": 10,
                "options": { "min_upper": 10_000_000 }
            }),
        };
        let start = std::time::Instant::now();
        let resp = generate_password(&req);
        let elapsed = start.elapsed();
        assert!(!resp.ok);
        assert_eq!(resp.error.unwrap().code, codes::BAD_REQUEST);
        assert!(
            elapsed.as_millis() < 200,
            "must reject before the generator's CSPRNG loop runs, took {elapsed:?}"
        );
    }


    #[test]
    fn generate_password_yields_a_password_of_the_requested_length() {
        let req = Request {
            id: "r1".into(),
            version: 1,
            action: "generate_password".into(),
            payload: serde_json::json!({ "length": 24 }),
        };
        let resp = generate_password(&req);
        assert!(resp.ok);
        let pw = resp.payload.unwrap()["password"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(pw.chars().count(), 24);
    }

    #[test]
    fn generate_password_rejects_an_impossible_combination_without_panicking() {
        let req = Request {
            id: "r2".into(),
            version: 1,
            action: "generate_password".into(),
            payload: serde_json::json!({
                "length": 10,
                "options": { "upper": false, "lower": false, "digits": false, "symbols": false }
            }),
        };
        let resp = generate_password(&req);
        assert!(!resp.ok);
        assert_eq!(resp.error.unwrap().code, codes::BAD_REQUEST);
    }


    #[test]
    fn gen_opts_rejects_a_non_object_options_value() {
        for bad_options in [
            serde_json::json!("strong"),
            serde_json::json!(5),
            serde_json::json!([1, 2, 3]),
            serde_json::json!(true),
        ] {
            let err = gen_opts(&serde_json::json!({ "options": bad_options })).unwrap_err();
            assert_eq!(
                err.code,
                codes::BAD_REQUEST,
                "a non-object options value must not be silently treated as absent"
            );
        }
    }

    #[test]
    fn gen_opts_options_absent_or_null_still_defaults() {
        assert!(gen_opts(&serde_json::json!({})).is_ok());
        assert!(gen_opts(&serde_json::json!({ "options": null })).is_ok());
    }


    #[test]
    fn gen_opts_rejects_a_non_bool_class_flag() {
        for key in ["upper", "lower", "digits", "symbols"] {
            for bad_value in [
                serde_json::json!(0),
                serde_json::json!("false"),
                serde_json::json!(["x"]),
                serde_json::json!({ "x": 1 }),
            ] {
                let mut opts = serde_json::Map::new();
                opts.insert(key.to_string(), bad_value);
                let payload = serde_json::json!({ "options": serde_json::Value::Object(opts) });
                let err = gen_opts(&payload).unwrap_err();
                assert_eq!(
                    err.code,
                    codes::BAD_REQUEST,
                    "a non-bool '{key}' must not be silently treated as its default"
                );
            }
        }
    }

    #[test]
    fn gen_opts_class_flag_absent_or_null_keeps_its_default() {
        let o = gen_opts(&serde_json::json!({ "options": {} })).unwrap();
        assert!(o.upper && o.lower && o.digits && o.symbols);

        let o = gen_opts(&serde_json::json!({
            "options": { "upper": null, "lower": null, "digits": null, "symbols": null }
        }))
        .unwrap();
        assert!(o.upper && o.lower && o.digits && o.symbols);
    }


    #[test]
    fn scope_replacement_never_leaks_the_previous_sites_candidates() {
        let mut scope = ConnScope {
            candidate_ids: vec!["a".to_string(), "b".to_string()],
            last_domain: Some("example.com".to_string()),
        };

        set_scope(&mut scope, vec![], "https://other.org");

        assert!(
            scope.candidate_ids.is_empty(),
            "the previous site's candidates must not survive an empty lookup for a new site"
        );
        assert_eq!(scope.last_domain.as_deref(), Some("other.org"));
    }


    #[test]
    fn clear_scope_resets_both_fields() {
        let mut scope = ConnScope {
            candidate_ids: vec!["a".to_string(), "b".to_string()],
            last_domain: Some("example.com".to_string()),
        };

        clear_scope(&mut scope);

        assert!(scope.candidate_ids.is_empty());
        assert_eq!(scope.last_domain, None);
    }

    #[test]
    fn clear_scope_wipes_a_previously_seeded_candidate_set() {
        let mut scope = ConnScope {
            candidate_ids: vec!["entry-a".to_string()],
            last_domain: Some("a.com".to_string()),
        };

        clear_scope(&mut scope);

        assert!(
            scope.candidate_ids.is_empty(),
            "a failing get_logins must not leave a stale, different-site candidate set live"
        );
        assert_eq!(scope.last_domain, None);
    }
}

#[cfg(test)]
mod anchor_tests {
    use super::*;

    fn scope_with(ids: &[&str], domain: &str) -> ConnScope {
        ConnScope {
            candidate_ids: ids.iter().map(|s| s.to_string()).collect(),
            last_domain: Some(domain.to_string()),
        }
    }

    #[test]
    fn an_entry_from_the_last_get_logins_is_in_scope() {
        let s = scope_with(&["e1", "e2"], "example.com");
        assert!(anchored(&s, "e1", None, &[]));
        assert!(
            !anchored(&s, "e9", None, &[]),
            "an id never offered to this connection is out of scope"
        );
    }


    #[test]
    fn a_candidate_set_entry_with_a_mismatched_explicit_url_is_not_anchored() {
        let s = scope_with(&["e1"], "bank.com");
        assert!(
            !anchored(&s, "e1", Some("https://attacker-chosen.example"), &[]),
            "an offered entry's candidacy must not override a url claiming a different site"
        );
    }

    #[test]
    fn a_candidate_set_entry_with_a_matching_explicit_url_is_anchored() {
        let s = scope_with(&["e1"], "bank.com");
        assert!(anchored(&s, "e1", Some("https://bank.com/login"), &[]));
    }

    #[test]
    fn a_candidate_set_entry_with_an_unreadable_url_is_not_anchored() {
        let s = scope_with(&["e1"], "bank.com");
        assert!(!anchored(&s, "e1", Some("about:blank"), &[]));
    }

    #[test]
    fn an_explicit_matching_url_also_anchors() {
        let s = ConnScope::default();
        let urls = vec!["https://accounts.example.com/x".to_string()];
        assert!(anchored(&s, "e1", Some("https://example.com/login"), &urls));
        assert!(!anchored(&s, "e1", Some("https://evil.com"), &urls));
        assert!(
            !anchored(&s, "e1", Some("https://example.com"), &[]),
            "entry has no url to match"
        );
    }

    #[test]
    fn picks_the_named_field_by_name_or_id_and_falls_back_to_the_first_secret() {
        let fields = vec![
            field("f-user", "Username", "text", false),
            field("f-pass", "Password", "secret", true),
            field("f-pin", "PIN", "secret", true),
        ];
        assert_eq!(
            pick_secret_field(&fields, None).unwrap(),
            "f-pass",
            "default = first secret field"
        );
        assert_eq!(
            pick_secret_field(&fields, Some("pin")).unwrap(),
            "f-pin",
            "by name, case-insensitive"
        );
        assert_eq!(
            pick_secret_field(&fields, Some("f-pin")).unwrap(),
            "f-pin",
            "by id"
        );
        assert!(
            pick_secret_field(&fields, Some("Username")).is_none(),
            "a non-secret field is not a secret"
        );
        assert!(pick_secret_field(&fields, Some("nope")).is_none());
    }

    fn field(id: &str, name: &str, ty: &str, protected: bool) -> kokos_core::entries::Field {
        kokos_core::entries::Field {
            id: id.into(),
            entry_id: "e1".into(),
            template_id: None,
            name: name.into(),
            value: None,
            is_protected: protected,
            field_type: ty.into(),
            sort_order: 0,
            strength: None,
        }
    }


    /// A richer field builder than `field()` above: `field()` always sets
    /// `value: None`, which is fine for anchoring/selection tests (they never
    /// read `.value`) but useless for `entry_urls_of`/`username_of`, which
    /// exist precisely to read it.
    fn mk_field(
        id: &str,
        template_id: Option<&str>,
        name: &str,
        ty: &str,
        protected: bool,
        value: Option<&str>,
    ) -> kokos_core::entries::Field {
        kokos_core::entries::Field {
            id: id.to_string(),
            entry_id: "e1".to_string(),
            template_id: template_id.map(|s| s.to_string()),
            name: name.to_string(),
            value: value.map(|s| s.to_string()),
            is_protected: protected,
            field_type: ty.to_string(),
            sort_order: 0,
            strength: None,
        }
    }


    #[test]
    fn an_unoffered_id_with_a_url_matching_a_different_entrys_urls_is_false() {
        let s = ConnScope::default();
        let e1_urls = vec!["https://mail.example.com".to_string()];
        assert!(!anchored(
            &s,
            "e1",
            Some("https://totally-unrelated.org"),
            &e1_urls
        ));
    }

    #[test]
    fn empty_entry_urls_never_anchors_even_with_a_matching_looking_url() {
        let s = ConnScope::default();
        assert!(!anchored(&s, "e1", Some("https://example.org"), &[]));
    }

    #[test]
    fn an_empty_or_unparseable_stored_url_never_matches() {
        let s = ConnScope::default();
        let urls = vec!["".to_string(), "not a url at all".to_string()];
        assert!(!anchored(&s, "e1", Some("https://example.com"), &urls));
    }

    #[test]
    fn about_blank_and_file_urls_never_anchor() {
        let s = ConnScope::default();
        let urls = vec!["https://example.com".to_string()];
        assert!(!anchored(&s, "e1", Some("about:blank"), &urls));
        assert!(!anchored(&s, "e1", Some("file:///x"), &urls));
    }

    #[test]
    fn a_subdomain_of_the_stored_url_still_anchors_same_etld_plus_one() {
        let s = ConnScope::default();
        let urls = vec!["https://accounts.example.com/x".to_string()];
        assert!(anchored(&s, "e1", Some("https://example.com/login"), &urls));
    }

    #[test]
    fn a_domain_suffix_trick_does_not_anchor() {
        let s = ConnScope::default();
        let urls = vec!["https://example.com".to_string()];
        assert!(
            !anchored(&s, "e1", Some("https://example.com.evil.com"), &urls),
            "example.com.evil.com must not be accepted as a subdomain of example.com"
        );
    }

    #[test]
    fn co_uk_style_suffixes_do_not_merge_via_a_last_two_labels_heuristic() {
        let s = ConnScope::default();
        let urls = vec!["https://example.co.uk".to_string()];
        assert!(
            !anchored(&s, "e1", Some("https://evil.co.uk"), &urls),
            "this is exactly why psl (not last-two-labels) is used"
        );
    }

    #[test]
    fn a_backslash_authority_url_does_not_anchor() {
        let s = ConnScope::default();
        let urls = vec!["https://example.com".to_string()];
        assert!(
            !anchored(&s, "e1", Some(r"https://evil.com\@example.com/"), &urls),
            "host_of must terminate the authority at a backslash -- anchored inherits it"
        );
    }


    #[test]
    fn a_non_secret_field_is_not_selectable_even_by_its_exact_id() {
        let fields = vec![
            field("f-user", "Username", "text", false),
            field("f-pass", "Password", "secret", true),
        ];
        assert!(
            pick_secret_field(&fields, Some("f-user")).is_none(),
            "a text field must not become selectable via its id"
        );
    }

    #[test]
    fn a_protected_url_field_is_eligible_by_the_is_protected_rule() {
        let fields = vec![field("f-url", "Recovery URL", "url", true)];
        assert_eq!(pick_secret_field(&fields, None).unwrap(), "f-url");
    }

    #[test]
    fn among_two_same_named_fields_only_the_eligible_one_is_selectable() {
        let fields = vec![
            field("f-1", "Code", "text", false),
            field("f-2", "Code", "secret", true),
        ];
        assert_eq!(pick_secret_field(&fields, Some("code")).unwrap(), "f-2");
    }

    #[test]
    fn field_name_matching_trims_and_lowercases_the_want_argument() {
        let fields = vec![field("f-pin", "PIN", "secret", true)];
        assert_eq!(
            pick_secret_field(&fields, Some("  pin  ")).unwrap(),
            "f-pin"
        );
    }

    #[test]
    fn an_empty_want_string_is_not_treated_as_absent() {
        let fields = vec![field("f-pass", "Password", "secret", true)];
        assert!(
            pick_secret_field(&fields, Some("")).is_none(),
            "an empty string must not fall back to \"first secret field\""
        );
    }


    #[test]
    fn pick_secret_field_never_selects_an_otp_field_even_as_the_only_protected_field() {
        let fields = vec![mk_field(
            "f-otp",
            Some("tpl_totp"),
            "TOTP",
            "otp",
            true,
            Some("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"),
        )];
        assert!(
            pick_secret_field(&fields, None).is_none(),
            "an otp field must not be selected by default even when it's the only \
             protected field on the entry"
        );
        assert!(
            pick_secret_field(&fields, Some("TOTP")).is_none(),
            "an otp field must not be selectable by name either"
        );
        assert!(
            pick_secret_field(&fields, Some("f-otp")).is_none(),
            "an otp field must not be selectable by id either"
        );
    }

    #[test]
    fn pick_secret_field_picks_the_password_over_an_otp_field_regardless_of_sort_order() {
        let otp_first = vec![
            mk_field("f-otp", Some("tpl_totp"), "TOTP", "otp", true, None),
            mk_field(
                "f-pass",
                Some("tpl_password"),
                "Password",
                "secret",
                true,
                None,
            ),
        ];
        assert_eq!(pick_secret_field(&otp_first, None).unwrap(), "f-pass");

        let pass_first = vec![
            mk_field(
                "f-pass",
                Some("tpl_password"),
                "Password",
                "secret",
                true,
                None,
            ),
            mk_field("f-otp", Some("tpl_totp"), "TOTP", "otp", true, None),
        ];
        assert_eq!(pick_secret_field(&pass_first, None).unwrap(), "f-pass");
    }


    #[test]
    fn field_arg_rejects_a_present_non_string_field() {
        for bad in [
            serde_json::json!({ "field": 5 }),
            serde_json::json!({ "field": true }),
            serde_json::json!({ "field": ["a"] }),
            serde_json::json!({ "field": { "x": 1 } }),
        ] {
            let e = field_arg(&bad).expect_err("a non-string field must be rejected");
            assert_eq!(e.code, codes::BAD_REQUEST);
        }
    }

    #[test]
    fn field_arg_absent_or_null_means_first_eligible_field() {
        assert_eq!(
            field_arg(&serde_json::json!({})).unwrap(),
            None,
            "absent 'field' -> no preference"
        );
        assert_eq!(
            field_arg(&serde_json::json!({ "field": null })).unwrap(),
            None,
            "explicit null 'field' -> no preference"
        );
        assert_eq!(
            field_arg(&serde_json::json!({ "field": "pin" })).unwrap(),
            Some("pin".to_string())
        );
    }


    #[test]
    fn entry_urls_of_only_picks_up_url_typed_fields() {
        let fields = vec![
            mk_field(
                "f-1",
                None,
                "URL",
                "url",
                false,
                Some("https://example.com"),
            ),
            mk_field(
                "f-2",
                None,
                "Notes",
                "text",
                false,
                Some("https://not-a-login-url.example"),
            ),
        ];
        assert_eq!(
            entry_urls_of(&fields),
            vec!["https://example.com".to_string()],
            "a text field must never be treated as a url field, even if its value looks like one"
        );
    }

    #[test]
    fn entry_urls_of_skips_a_protected_urls_withheld_value() {
        let fields = vec![mk_field("f-1", None, "URL", "url", true, None)];
        assert!(
            entry_urls_of(&fields).is_empty(),
            "entries::get withholds a protected value as None -- fail closed"
        );
    }

    #[test]
    fn entry_urls_of_skips_empty_string_values() {
        let fields = vec![mk_field("f-1", None, "URL", "url", false, Some(""))];
        assert!(entry_urls_of(&fields).is_empty());
    }


    #[test]
    fn domain_for_prefers_the_explicit_url_over_last_domain() {
        assert_eq!(
            domain_for(Some("https://example.com/login"), Some("other.com")),
            "example.com"
        );
    }

    #[test]
    fn domain_for_falls_back_to_last_domain_when_no_url_is_given() {
        assert_eq!(domain_for(None, Some("example.com")), "example.com");
    }

    #[test]
    fn domain_for_falls_back_to_unknown_when_neither_is_present() {
        assert_eq!(domain_for(None, None), "unknown");
    }

    #[test]
    fn domain_for_uses_the_bare_host_for_an_ip_or_localhost_instead_of_unknown() {
        assert_eq!(
            domain_for(Some("http://127.0.0.1:8080/x"), None),
            "127.0.0.1"
        );
        assert_eq!(
            domain_for(Some("http://localhost:3000/"), None),
            "localhost"
        );
    }


    #[test]
    fn an_unknown_id_never_offered_answers_not_in_scope() {
        assert_eq!(
            scope_decision(false, false, false),
            ScopeDecision::NotInScope
        );
    }

    #[test]
    fn an_unknown_id_that_was_offered_answers_entry_not_found() {
        assert_eq!(
            scope_decision(false, true, false),
            ScopeDecision::EntryNotFound
        );
    }

    #[test]
    fn a_known_but_unanchored_entry_answers_not_in_scope_not_entry_not_found() {
        assert_eq!(
            scope_decision(true, false, false),
            ScopeDecision::NotInScope
        );
    }

    #[test]
    fn a_known_and_anchored_entry_proceeds() {
        assert_eq!(scope_decision(true, false, true), ScopeDecision::Anchored);
        assert_eq!(scope_decision(true, true, true), ScopeDecision::Anchored);
    }

    #[test]
    fn the_oracle_is_closed_an_unanchored_known_id_and_an_unoffered_unknown_id_answer_identically()
    {
        assert_eq!(
            scope_decision(true, false, false),
            scope_decision(false, false, false)
        );
    }


    #[test]
    fn pick_otp_field_matches_by_field_type_or_by_the_totp_template() {
        let by_type = vec![mk_field("f-otp", None, "OTP", "otp", true, None)];
        assert_eq!(pick_otp_field(&by_type).unwrap(), "f-otp");

        let by_template = vec![mk_field(
            "f-totp",
            Some("tpl_totp"),
            "Authenticator",
            "secret",
            true,
            None,
        )];
        assert_eq!(pick_otp_field(&by_template).unwrap(), "f-totp");
    }

    #[test]
    fn pick_otp_field_is_none_when_the_entry_has_no_otp_field() {
        let fields = vec![mk_field("f-pass", None, "Password", "secret", true, None)];
        assert!(pick_otp_field(&fields).is_none());
    }


    #[test]
    fn username_of_reads_the_tpl_username_field() {
        let fields = vec![mk_field(
            "f-u",
            Some("tpl_username"),
            "Username",
            "text",
            false,
            Some("octocat"),
        )];
        assert_eq!(username_of(&fields).as_deref(), Some("octocat"));
    }

    #[test]
    fn username_of_is_none_when_the_username_field_is_protected() {
        let fields = vec![mk_field(
            "f-u",
            Some("tpl_username"),
            "Username",
            "text",
            true,
            None,
        )];
        assert!(username_of(&fields).is_none());
    }

    #[test]
    fn username_of_falls_back_to_an_email_field() {
        let templated = vec![mk_field("f-e", Some("tpl_email"), "Email", "email", false, Some("ann@example.com"))];
        assert_eq!(username_of(&templated).as_deref(), Some("ann@example.com"));

        let typed = vec![mk_field("f-e", None, "Email", "email", false, Some("bob@example.com"))];
        assert_eq!(username_of(&typed).as_deref(), Some("bob@example.com"));
    }

    #[test]
    fn username_of_prefers_the_username_over_an_email() {
        let fields = vec![
            mk_field("f-e", Some("tpl_email"), "Email", "email", false, Some("ann@example.com")),
            mk_field("f-u", Some("tpl_username"), "Username", "text", false, Some("ann")),
        ];
        assert_eq!(username_of(&fields).as_deref(), Some("ann"));
    }

    #[test]
    fn username_of_is_none_when_the_email_field_is_protected() {
        let fields = vec![mk_field("f-e", Some("tpl_email"), "Email", "email", true, None)];
        assert!(username_of(&fields).is_none());
    }


    #[test]
    fn a_fully_anchored_lookup_resolves_the_correct_secret_field_id() {
        let scope = scope_with(&["e1"], "example.com");
        let fields = vec![
            field("f-user", "Username", "text", false),
            field("f-pass", "Password", "secret", true),
            field("f-pin", "PIN", "secret", true),
        ];
        assert!(anchored(&scope, "e1", None, &entry_urls_of(&fields)));
        assert_eq!(
            pick_secret_field(&fields, Some("PIN")).unwrap(),
            "f-pin",
            "must resolve to the field's id, not its name or its position in the list"
        );
    }


    #[test]
    fn field_name_of_finds_the_matching_fields_name() {
        let fields = vec![
            mk_field("f-user", None, "Username", "text", false, None),
            mk_field("f-pin", None, "PIN", "secret", true, None),
        ];
        assert_eq!(field_name_of(&fields, "f-pin").as_deref(), Some("PIN"));
    }

    #[test]
    fn field_name_of_is_none_for_an_unknown_id() {
        let fields = vec![mk_field("f-pass", None, "Password", "secret", true, None)];
        assert!(field_name_of(&fields, "nope").is_none());
    }

    #[test]
    fn field_name_of_does_not_resolve_an_id_that_only_belongs_to_a_different_entry() {
        let other_entrys_fields = vec![mk_field(
            "shared-id",
            None,
            "Secret Note",
            "secret",
            true,
            None,
        )];
        assert_eq!(
            field_name_of(&other_entrys_fields, "shared-id").as_deref(),
            Some("Secret Note"),
            "positive control: the id genuinely is present in this slice"
        );

        let this_entrys_fields = vec![mk_field("f-pass", None, "Password", "secret", true, None)];
        assert!(
            field_name_of(&this_entrys_fields, "shared-id").is_none(),
            "the same id, looked up against an unrelated entry's fields, must not resolve"
        );
    }


    #[test]
    fn should_capture_grant_is_true_only_for_reads_allowed_in_session_domain_mode() {
        assert!(should_capture_grant("get_secret", "session_domain", true));
        assert!(should_capture_grant("get_totp", "session_domain", true));
    }

    #[test]
    fn should_capture_grant_is_false_for_writes_even_when_allowed_and_session_domain() {
        assert!(!should_capture_grant("save_login", "session_domain", true));
        assert!(!should_capture_grant(
            "update_login",
            "session_domain",
            true
        ));
    }

    #[test]
    fn should_capture_grant_is_false_when_the_confirmation_was_denied() {
        assert!(!should_capture_grant("get_secret", "session_domain", false));
        assert!(!should_capture_grant("get_totp", "session_domain", false));
    }

    #[test]
    fn should_capture_grant_is_false_outside_session_domain_mode() {
        assert!(!should_capture_grant("get_secret", "always", true));
        assert!(
            !should_capture_grant("get_secret", "bogus_mode", true),
            "an unrecognised mode must never capture a grant either"
        );
    }


    #[test]
    fn should_persist_grant_is_true_only_for_reads_allowed_remembered_in_remember_site_mode() {
        assert!(should_persist_grant("get_secret", "remember_site", true, true));
        assert!(should_persist_grant("get_totp", "remember_site", true, true));
    }

    #[test]
    fn should_persist_grant_is_false_for_a_write_even_when_allowed_remembered_remember_site() {
        assert!(!should_persist_grant(
            "save_login",
            "remember_site",
            true,
            true
        ));
        assert!(!should_persist_grant(
            "update_login",
            "remember_site",
            true,
            true
        ));
    }

    #[test]
    fn should_persist_grant_is_false_for_a_read_remembered_outside_remember_site_mode() {
        for mode in ["always", "session_domain", "trust_extension"] {
            assert!(
                !should_persist_grant("get_secret", mode, true, true),
                "get_secret must not persist a grant in mode {mode}"
            );
            assert!(
                !should_persist_grant("get_totp", mode, true, true),
                "get_totp must not persist a grant in mode {mode}"
            );
        }
    }

    #[test]
    fn should_persist_grant_is_false_when_the_confirmation_was_denied_even_if_remembered() {
        assert!(!should_persist_grant(
            "get_secret",
            "remember_site",
            false,
            true
        ));
        assert!(!should_persist_grant(
            "get_totp",
            "remember_site",
            false,
            true
        ));
    }

    #[test]
    fn should_persist_grant_is_false_without_the_remember_bit_even_when_allowed_and_remember_site()
    {
        assert!(!should_persist_grant(
            "get_secret",
            "remember_site",
            true,
            false
        ));
    }


    #[test]
    fn grant_ttl_converts_minutes_to_seconds() {
        assert_eq!(grant_ttl(5), std::time::Duration::from_secs(300));
    }

    #[test]
    fn grant_ttl_zero_makes_a_grant_dead_immediately() {
        let grants = crate::nmh::grants::Grants::new();
        let now = std::time::Instant::now();
        grants.allow("/vault/a.kokos", "origin", "example.com", grant_ttl(0), now);
        assert!(!grants.is_granted("/vault/a.kokos", "origin", "example.com", now));
    }

    #[test]
    fn grant_ttl_does_not_overflow_for_a_large_value() {
        let d = grant_ttl(u32::MAX);
        assert!(d.as_secs() > 0);
    }


    #[test]
    fn clamp_confirm_field_truncates_a_long_string_to_exactly_max_chars() {
        let s = "a".repeat(300);
        let clamped = clamp_confirm_field(&s, MAX_CONFIRM_FIELD_CHARS);
        assert_eq!(clamped.chars().count(), MAX_CONFIRM_FIELD_CHARS);
        assert_eq!(clamped, "a".repeat(MAX_CONFIRM_FIELD_CHARS));
    }

    #[test]
    fn clamp_confirm_field_leaves_a_short_string_unchanged() {
        let s = "octocat";
        assert_eq!(clamp_confirm_field(s, MAX_CONFIRM_FIELD_CHARS), s);
    }

    #[test]
    fn clamp_confirm_field_truncates_multibyte_chars_on_a_char_boundary() {
        let s = "🔒".repeat(10) + &"漢".repeat(10);
        let clamped = clamp_confirm_field(&s, 5);
        assert!(clamped.chars().count() <= 5);
        assert!(std::str::from_utf8(clamped.as_bytes()).is_ok());
    }

    #[test]
    fn clamp_confirm_field_leaves_an_exact_max_length_string_unchanged() {
        let s = "b".repeat(MAX_CONFIRM_FIELD_CHARS);
        assert_eq!(clamp_confirm_field(&s, MAX_CONFIRM_FIELD_CHARS), s);
    }
}

#[cfg(test)]
mod write_tests {
    use super::*;

    #[test]
    fn a_new_login_gets_url_username_password_on_the_builtin_templates() {
        let fields = new_login_fields("https://example.com/login", "octocat", "s3cret");
        let by_tpl = |t: &str| {
            fields
                .iter()
                .find(|f| f.template_id.as_deref() == Some(t))
                .expect("field present")
        };
        assert_eq!(
            by_tpl("tpl_url").value.as_deref(),
            Some("https://example.com/login")
        );
        assert_eq!(by_tpl("tpl_username").value.as_deref(), Some("octocat"));
        let pw = by_tpl("tpl_password");
        assert_eq!(pw.value.as_deref(), Some("s3cret"));
        assert!(pw.is_protected, "a password field must be protected");
        assert_eq!(pw.field_type, "secret");
        assert_eq!(fields.len(), 3, "nothing else is invented");
    }

    #[test]
    fn save_login_payload_validation() {
        assert!(save_args(
            &serde_json::json!({ "url": "https://a.com", "username": "u", "password": "p" })
        )
        .is_ok());
        assert!(
            save_args(&serde_json::json!({ "url": "https://a.com", "username": "u" })).is_err(),
            "password required"
        );
        assert!(save_args(
            &serde_json::json!({ "url": "about:blank", "username": "u", "password": "p" })
        )
        .is_err());
        let a = save_args(
            &serde_json::json!({ "url": "https://a.com", "username": "u", "password": "p" }),
        )
        .unwrap();
        assert_eq!(a.title, "a.com", "no title given -> host is the title");
    }

    #[test]
    fn update_login_requires_a_non_empty_password() {
        assert!(update_args(&serde_json::json!({ "entry_id": "e1", "password": "p" })).is_ok());
        assert!(update_args(&serde_json::json!({ "entry_id": "e1", "password": "" })).is_err());
        assert!(update_args(&serde_json::json!({ "password": "p" })).is_err());
    }


    #[test]
    fn new_login_fields_url_and_username_types_are_url_and_text() {
        let fields = new_login_fields("https://example.com", "octocat", "s3cret");
        let url_f = fields
            .iter()
            .find(|f| f.template_id.as_deref() == Some("tpl_url"))
            .unwrap();
        assert_eq!(url_f.field_type, "url");
        assert!(!url_f.is_protected);
        let user_f = fields
            .iter()
            .find(|f| f.template_id.as_deref() == Some("tpl_username"))
            .unwrap();
        assert_eq!(user_f.field_type, "text");
        assert!(!user_f.is_protected);
    }

    #[test]
    fn save_args_title_explicit_wins_over_the_host_default() {
        let a = save_args(&serde_json::json!({
            "url": "https://a.com", "username": "u", "password": "p", "title": "My Bank"
        }))
        .unwrap();
        assert_eq!(a.title, "My Bank");
    }

    #[test]
    fn save_args_a_blank_title_falls_back_to_the_host() {
        let a = save_args(&serde_json::json!({
            "url": "https://a.com", "username": "u", "password": "p", "title": "   "
        }))
        .unwrap();
        assert_eq!(a.title, "a.com", "a blank title is not a real title");
    }


    #[test]
    fn save_args_rejects_a_present_non_string_title() {
        for bad_title in [
            serde_json::json!(5),
            serde_json::json!(true),
            serde_json::json!(["x"]),
            serde_json::json!({ "x": 1 }),
        ] {
            let err = save_args(&serde_json::json!({
                "url": "https://a.com", "username": "u", "password": "p", "title": bad_title
            }))
            .err()
            .unwrap();
            assert_eq!(
                err.code,
                codes::BAD_REQUEST,
                "a non-string title must not be silently replaced by the host"
            );
        }
    }

    #[test]
    fn save_args_title_absent_or_null_falls_back_to_the_host() {
        let a = save_args(&serde_json::json!({
            "url": "https://a.com", "username": "u", "password": "p"
        }))
        .unwrap();
        assert_eq!(a.title, "a.com", "absent title falls back to the host");

        let a = save_args(&serde_json::json!({
            "url": "https://a.com", "username": "u", "password": "p", "title": null
        }))
        .unwrap();
        assert_eq!(
            a.title, "a.com",
            "explicit null title falls back to the host"
        );
    }

    #[test]
    fn save_args_accepts_an_empty_username() {
        assert!(save_args(
            &serde_json::json!({ "url": "https://a.com", "username": "", "password": "p" })
        )
        .is_ok());
    }

    #[test]
    fn save_args_rejects_a_non_string_url_username_or_password() {
        assert!(
            save_args(&serde_json::json!({ "url": 5, "username": "u", "password": "p" })).is_err()
        );
        assert!(save_args(
            &serde_json::json!({ "url": "https://a.com", "username": 5, "password": "p" })
        )
        .is_err());
        assert!(save_args(
            &serde_json::json!({ "url": "https://a.com", "username": "u", "password": 5 })
        )
        .is_err());
    }

    #[test]
    fn save_args_rejects_an_empty_password() {
        assert!(save_args(
            &serde_json::json!({ "url": "https://a.com", "username": "u", "password": "" })
        )
        .is_err());
    }

    #[test]
    fn update_args_rejects_a_non_string_password_or_entry_id() {
        assert!(update_args(&serde_json::json!({ "entry_id": "e1", "password": 5 })).is_err());
        assert!(update_args(&serde_json::json!({ "entry_id": 5, "password": "p" })).is_err());
    }


    fn w_field(
        id: &str,
        template_id: Option<&str>,
        name: &str,
        ty: &str,
        protected: bool,
    ) -> kokos_core::entries::Field {
        kokos_core::entries::Field {
            id: id.to_string(),
            entry_id: "e1".to_string(),
            template_id: template_id.map(|s| s.to_string()),
            name: name.to_string(),
            value: None,
            is_protected: protected,
            field_type: ty.to_string(),
            sort_order: 0,
            strength: None,
        }
    }

    #[test]
    fn pick_password_field_tier_1_prefers_tpl_password_even_when_a_pin_sorts_first() {
        let fields = vec![
            w_field("f-pin", Some("tpl_pin"), "PIN", "secret", true),
            w_field("f-pass", Some("tpl_password"), "Password", "secret", true),
        ];
        assert_eq!(
            pick_password_field(&fields).unwrap(),
            "f-pass",
            "tpl_password must win even though the PIN is listed (sorted) first"
        );
    }

    #[test]
    fn pick_password_field_tier_2_falls_back_to_the_first_secret_typed_field() {
        let fields = vec![
            w_field("f-note", None, "Notes", "text", false),
            w_field("f-code", None, "Recovery Code", "secret", true),
        ];
        assert_eq!(pick_password_field(&fields).unwrap(), "f-code");
    }

    #[test]
    fn pick_password_field_tier_3_falls_back_to_the_first_protected_field() {
        let fields = vec![
            w_field("f-note", None, "Notes", "text", false),
            w_field("f-link", None, "Private Link", "url", true),
        ];
        assert_eq!(pick_password_field(&fields).unwrap(), "f-link");
    }

    #[test]
    fn pick_password_field_is_none_when_the_entry_has_no_secret_at_all() {
        let fields = vec![w_field("f-note", None, "Notes", "text", false)];
        assert!(
            pick_password_field(&fields).is_none(),
            "must never invent a password field"
        );
    }


    #[test]
    fn pick_password_field_excludes_the_otp_field_from_the_is_protected_fallback() {
        let fields = vec![w_field("f-otp", Some("tpl_totp"), "TOTP", "otp", true)];
        assert!(
            pick_password_field(&fields).is_none(),
            "an entry whose only protected field is otp must answer None, not the otp field \
             -- the caller maps this to entry_not_found instead of destroying the seed"
        );
    }

    #[test]
    fn pick_password_field_picks_the_password_over_an_otp_field_regardless_of_sort_order() {
        let otp_first = vec![
            w_field("f-otp", Some("tpl_totp"), "TOTP", "otp", true),
            w_field("f-pass", Some("tpl_password"), "Password", "secret", true),
        ];
        assert_eq!(pick_password_field(&otp_first).unwrap(), "f-pass");

        let pass_first = vec![
            w_field("f-pass", Some("tpl_password"), "Password", "secret", true),
            w_field("f-otp", Some("tpl_totp"), "TOTP", "otp", true),
        ];
        assert_eq!(pick_password_field(&pass_first).unwrap(), "f-pass");
    }


    #[test]
    fn update_patch_fields_carries_every_field_forward_with_one_set_and_the_rest_keep() {
        let fields = vec![
            w_field("f-1", Some("tpl_username"), "Username", "text", false),
            w_field("f-2", Some("tpl_password"), "Password", "secret", true),
            w_field("f-3", None, "PIN", "secret", true),
        ];
        let inputs = update_patch_fields(&fields, "f-2", "new-pw");

        assert_eq!(
            inputs.len(),
            fields.len(),
            "count must equal the input count"
        );
        for (i, (input, original)) in inputs.iter().zip(fields.iter()).enumerate() {
            assert_eq!(
                input.id.as_deref(),
                Some(original.id.as_str()),
                "field {i} must keep its original id"
            );
            assert_eq!(
                input.template_id, original.template_id,
                "field {i} template_id must be copied verbatim"
            );
            assert_eq!(
                input.name, original.name,
                "field {i} name must be copied verbatim"
            );
            assert_eq!(
                input.is_protected, original.is_protected,
                "field {i} is_protected must be copied verbatim"
            );
            assert_eq!(
                input.field_type, original.field_type,
                "field {i} field_type must be copied verbatim"
            );
        }

        let set_count = inputs
            .iter()
            .filter(|f| matches!(f.value, kokos_core::entries::FieldValue::Set(_)))
            .count();
        assert_eq!(set_count, 1, "exactly one field must be Set");
        match &inputs[1].value {
            kokos_core::entries::FieldValue::Set(v) => assert_eq!(v, "new-pw"),
            other => panic!("expected Set(\"new-pw\") on the target field, got {other:?}"),
        }
        let keep_count = inputs
            .iter()
            .filter(|f| matches!(f.value, kokos_core::entries::FieldValue::Keep))
            .count();
        assert_eq!(
            keep_count,
            fields.len() - 1,
            "every other field must be Keep"
        );
    }


    /// A realistic migrated-vault entry: URL, username, a protected
    /// password, a protected PIN with no template (a hand-added custom
    /// field), and a TOTP field.
    fn five_field_login_entry(password: &str) -> kokos_core::entries::NewEntry {
        kokos_core::entries::NewEntry {
            title: "Migrated Login".to_string(),
            folder_id: None,
            notes: None,
            entry_type: "login".into(),
            fields: vec![
                kokos_core::entries::NewField {
                    template_id: Some("tpl_url".into()),
                    name: "URL".into(),
                    value: Some("https://example.com".into()),
                    is_protected: false,
                    field_type: "url".into(),
                },
                kokos_core::entries::NewField {
                    template_id: Some("tpl_username".into()),
                    name: "Username".into(),
                    value: Some("octocat".into()),
                    is_protected: false,
                    field_type: "text".into(),
                },
                kokos_core::entries::NewField {
                    template_id: Some("tpl_password".into()),
                    name: "Password".into(),
                    value: Some(password.to_string()),
                    is_protected: true,
                    field_type: "secret".into(),
                },
                kokos_core::entries::NewField {
                    template_id: None,
                    name: "PIN".into(),
                    value: Some("1234".into()),
                    is_protected: true,
                    field_type: "secret".into(),
                },
                kokos_core::entries::NewField {
                    template_id: Some("tpl_totp".into()),
                    name: "TOTP".into(),
                    value: Some("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".into()),
                    is_protected: true,
                    field_type: "otp".into(),
                },
            ],
        }
    }

    #[test]
    fn update_login_survives_a_real_reconcile_every_other_field_untouched() {
        let conn = kokos_core::db::create_fresh().expect("fresh in-memory vault");
        let now = kokos_core::db::now_unix();

        let created = kokos_core::entries::create(&conn, five_field_login_entry("old-pw"), now)
            .expect("create succeeds");
        assert_eq!(created.fields.len(), 5);
        let original_ids: Vec<String> = created.fields.iter().map(|f| f.id.clone()).collect();
        let original_order: Vec<i32> = created.fields.iter().map(|f| f.sort_order).collect();

        let entry = kokos_core::entries::get(&conn, &created.id)
            .unwrap()
            .unwrap();
        let field_id = pick_password_field(&entry.fields).expect("a password field must be found");
        let target = entry.fields.iter().find(|f| f.id == field_id).unwrap();
        assert_eq!(
            target.template_id.as_deref(),
            Some("tpl_password"),
            "must resolve to the actual password field, not the PIN"
        );

        let patch_fields = update_patch_fields(&entry.fields, &field_id, "new-pw");
        let patch = kokos_core::entries::EntryPatch {
            title: None,
            notes: None,
            is_favorite: None,
            folder_id: None,
            fields: Some(patch_fields),
        };
        kokos_core::entries::update(&conn, &created.id, patch, now + 1)
            .expect("update succeeds")
            .expect("the entry still exists");

        let after = kokos_core::entries::get(&conn, &created.id)
            .unwrap()
            .unwrap();
        assert_eq!(
            after.fields.len(),
            5,
            "no field may be deleted or duplicated by the update"
        );
        let after_ids: Vec<String> = after.fields.iter().map(|f| f.id.clone()).collect();
        assert_eq!(
            after_ids, original_ids,
            "every field must keep its original id -- nothing was deleted and reinserted"
        );
        let after_order: Vec<i32> = after.fields.iter().map(|f| f.sort_order).collect();
        assert_eq!(after_order, original_order, "sort_order must be unchanged");

        let raw = |fid: &str| {
            kokos_core::entries::reveal_field(&conn, &created.id, fid)
                .unwrap()
                .unwrap()
        };

        let pw_field = after
            .fields
            .iter()
            .find(|f| f.template_id.as_deref() == Some("tpl_password"))
            .unwrap();
        assert_eq!(
            raw(&pw_field.id),
            "new-pw",
            "the password field now holds the new value"
        );
        assert!(
            pw_field.is_protected,
            "the password field must still be protected after the update"
        );
        assert_eq!(
            pw_field.field_type, "secret",
            "the password field's field_type must be unchanged"
        );

        let pin_field = after.fields.iter().find(|f| f.name == "PIN").unwrap();
        assert_eq!(
            raw(&pin_field.id),
            "1234",
            "the PIN field must still hold its original value -- this is the assertion \
             the whole test exists for"
        );
        assert!(
            pin_field.is_protected,
            "the PIN field must still be protected -- an unprotect-on-save regression \
             must be caught here, not only by the pure update_patch_fields unit test"
        );
        assert_eq!(
            pin_field.field_type, "secret",
            "the PIN field's field_type must be unchanged"
        );

        let totp_field = after.fields.iter().find(|f| f.name == "TOTP").unwrap();
        assert_eq!(
            raw(&totp_field.id),
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
            "the TOTP field must still hold its original otpauth string"
        );
        assert_eq!(
            totp_field.field_type, "otp",
            "the TOTP field's field_type must be unchanged"
        );

        let username_field = after
            .fields
            .iter()
            .find(|f| f.template_id.as_deref() == Some("tpl_username"))
            .unwrap();
        assert_eq!(raw(&username_field.id), "octocat", "username is unchanged");

        let url_field = after
            .fields
            .iter()
            .find(|f| f.template_id.as_deref() == Some("tpl_url"))
            .unwrap();
        assert_eq!(
            raw(&url_field.id),
            "https://example.com",
            "url is unchanged"
        );

        let history = kokos_core::entries::list_field_history(&conn, &created.id, "Password")
            .expect("history read succeeds");
        assert_eq!(history.len(), 1, "exactly one history row must be written");
        assert_eq!(
            history[0].value.as_deref(),
            Some("old-pw"),
            "the history row must hold the OLD password, not the new one"
        );
    }

    #[test]
    fn a_bare_patch_missing_a_field_deletes_it_proving_the_trap_is_real() {
        let conn = kokos_core::db::create_fresh().expect("fresh in-memory vault");
        let now = kokos_core::db::now_unix();

        let created = kokos_core::entries::create(&conn, five_field_login_entry("old-pw"), now)
            .expect("create succeeds");
        let entry = kokos_core::entries::get(&conn, &created.id)
            .unwrap()
            .unwrap();
        let field_id = pick_password_field(&entry.fields).unwrap();

        let bare_patch = vec![kokos_core::entries::FieldInput {
            id: Some(field_id),
            template_id: Some("tpl_password".into()),
            name: "Password".into(),
            is_protected: true,
            field_type: "secret".into(),
            value: kokos_core::entries::FieldValue::Set("new-pw".into()),
        }];
        kokos_core::entries::update(
            &conn,
            &created.id,
            kokos_core::entries::EntryPatch {
                title: None,
                notes: None,
                is_favorite: None,
                folder_id: None,
                fields: Some(bare_patch),
            },
            now + 1,
        )
        .expect("update succeeds")
        .expect("the entry still exists");

        let after = kokos_core::entries::get(&conn, &created.id)
            .unwrap()
            .unwrap();
        assert_eq!(
            after.fields.len(),
            1,
            "every field but the one named in the patch must be gone"
        );
        assert!(
            !after.fields.iter().any(|f| f.name == "PIN"),
            "the PIN field must be deleted by a bare patch -- proving the trap is real"
        );
        assert!(
            !after.fields.iter().any(|f| f.name == "TOTP"),
            "the TOTP field must be deleted by a bare patch -- proving the trap is real"
        );
    }


    #[test]
    fn update_login_would_refuse_rather_than_overwrite_an_entrys_only_otp_field() {
        let conn = kokos_core::db::create_fresh().expect("fresh in-memory vault");
        let now = kokos_core::db::now_unix();

        let entry_only_otp = kokos_core::entries::NewEntry {
            title: "2FA-only entry".to_string(),
            folder_id: None,
            notes: None,
            entry_type: "login".into(),
            fields: vec![
                kokos_core::entries::NewField {
                    template_id: Some("tpl_url".into()),
                    name: "URL".into(),
                    value: Some("https://example.com".into()),
                    is_protected: false,
                    field_type: "url".into(),
                },
                kokos_core::entries::NewField {
                    template_id: Some("tpl_totp".into()),
                    name: "TOTP".into(),
                    value: Some("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".into()),
                    is_protected: true,
                    field_type: "otp".into(),
                },
            ],
        };
        let created =
            kokos_core::entries::create(&conn, entry_only_otp, now).expect("create succeeds");
        let entry = kokos_core::entries::get(&conn, &created.id)
            .unwrap()
            .unwrap();

        assert!(
            pick_password_field(&entry.fields).is_none(),
            "the only protected field on this entry is otp -- update_login must refuse, \
             not overwrite it"
        );

        let totp_field = entry
            .fields
            .iter()
            .find(|f| f.template_id.as_deref() == Some("tpl_totp"))
            .unwrap();
        assert_eq!(
            kokos_core::entries::reveal_field(&conn, &created.id, &totp_field.id)
                .unwrap()
                .unwrap(),
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"
        );
    }


    /// Deletes the entry's PIN field and adds a new "Recovery Code" field,
    /// carrying every other field forward untouched (id-keyed Keep) -- an
    /// ordinary in-app edit, not a browser-shaped patch. Returns the patch
    /// plus the PIN field's (about-to-be-deleted) id, so callers can check
    /// whether it comes back.
    fn mid_wait_edit_patch(
        base_fields: &[kokos_core::entries::Field],
    ) -> (Vec<kokos_core::entries::FieldInput>, String) {
        let pin_id = base_fields
            .iter()
            .find(|f| f.name == "PIN")
            .expect("fixture has a PIN field")
            .id
            .clone();
        let mut patch: Vec<kokos_core::entries::FieldInput> = base_fields
            .iter()
            .filter(|f| f.id != pin_id)
            .map(|f| kokos_core::entries::FieldInput {
                id: Some(f.id.clone()),
                template_id: f.template_id.clone(),
                name: f.name.clone(),
                is_protected: f.is_protected,
                field_type: f.field_type.clone(),
                value: kokos_core::entries::FieldValue::Keep,
            })
            .collect();
        patch.push(kokos_core::entries::FieldInput {
            id: None,
            template_id: None,
            name: "Recovery Code".to_string(),
            is_protected: true,
            field_type: "secret".to_string(),
            value: kokos_core::entries::FieldValue::Set("rc-999".to_string()),
        });
        (patch, pin_id)
    }

    #[test]
    fn a_fresh_read_patch_survives_an_edit_made_during_the_confirm_wait() {
        let conn = kokos_core::db::create_fresh().expect("fresh in-memory vault");
        let now = kokos_core::db::now_unix();

        let created = kokos_core::entries::create(&conn, five_field_login_entry("old-pw"), now)
            .expect("create succeeds");
        let stale = kokos_core::entries::get(&conn, &created.id)
            .unwrap()
            .unwrap()
            .fields;

        let (mid_wait_patch, _pin_id) = mid_wait_edit_patch(&stale);
        kokos_core::entries::update(
            &conn,
            &created.id,
            kokos_core::entries::EntryPatch {
                title: None,
                notes: None,
                is_favorite: None,
                folder_id: None,
                fields: Some(mid_wait_patch),
            },
            now + 1,
        )
        .expect("mid-wait edit succeeds")
        .expect("entry still exists");

        let fresh = kokos_core::entries::get(&conn, &created.id)
            .unwrap()
            .unwrap();
        let field_id = pick_password_field(&fresh.fields).expect("password field found");
        let fresh_patch = update_patch_fields(&fresh.fields, &field_id, "new-pw");
        kokos_core::entries::update(
            &conn,
            &created.id,
            kokos_core::entries::EntryPatch {
                title: None,
                notes: None,
                is_favorite: None,
                folder_id: None,
                fields: Some(fresh_patch),
            },
            now + 2,
        )
        .expect("update succeeds")
        .expect("entry still exists");

        let after = kokos_core::entries::get(&conn, &created.id)
            .unwrap()
            .unwrap();
        assert!(
            after.fields.iter().any(|f| f.name == "Recovery Code"),
            "a field added during the confirm wait must survive a fresh-read patch"
        );
        assert!(
            !after.fields.iter().any(|f| f.name == "PIN"),
            "a field deleted during the confirm wait must stay deleted, not be resurrected"
        );
        let pw_id = after
            .fields
            .iter()
            .find(|f| f.template_id.as_deref() == Some("tpl_password"))
            .unwrap()
            .id
            .clone();
        assert_eq!(
            kokos_core::entries::reveal_field(&conn, &created.id, &pw_id)
                .unwrap()
                .unwrap(),
            "new-pw",
            "the target field still gets the new password"
        );
    }

    #[test]
    fn negative_control_a_stale_snapshot_patch_destroys_the_mid_wait_edit() {
        let conn = kokos_core::db::create_fresh().expect("fresh in-memory vault");
        let now = kokos_core::db::now_unix();

        let created = kokos_core::entries::create(&conn, five_field_login_entry("old-pw"), now)
            .expect("create succeeds");
        let stale = kokos_core::entries::get(&conn, &created.id)
            .unwrap()
            .unwrap()
            .fields;
        let (mid_wait_patch, pin_id) = mid_wait_edit_patch(&stale);
        kokos_core::entries::update(
            &conn,
            &created.id,
            kokos_core::entries::EntryPatch {
                title: None,
                notes: None,
                is_favorite: None,
                folder_id: None,
                fields: Some(mid_wait_patch),
            },
            now + 1,
        )
        .expect("mid-wait edit succeeds")
        .expect("entry still exists");

        let field_id = pick_password_field(&stale).expect("password field found in stale snapshot");
        let stale_patch = update_patch_fields(&stale, &field_id, "new-pw");
        kokos_core::entries::update(
            &conn,
            &created.id,
            kokos_core::entries::EntryPatch {
                title: None,
                notes: None,
                is_favorite: None,
                folder_id: None,
                fields: Some(stale_patch),
            },
            now + 2,
        )
        .expect("update succeeds")
        .expect("entry still exists");

        let after = kokos_core::entries::get(&conn, &created.id)
            .unwrap()
            .unwrap();
        assert!(
            !after.fields.iter().any(|f| f.name == "Recovery Code"),
            "a stale-snapshot patch silently destroys a field added during the confirm wait"
        );
        let resurrected = after.fields.iter().find(|f| f.name == "PIN").expect(
            "a stale-snapshot patch resurrects the deleted PIN field \
                 -- this is the bug the post-confirm fresh read exists to close",
        );
        assert_ne!(
            resurrected.id, pin_id,
            "the resurrected PIN field has a NEW id -- it was re-inserted, not restored"
        );
        assert_eq!(
            kokos_core::entries::reveal_field(&conn, &created.id, &resurrected.id)
                .unwrap()
                .unwrap(),
            "",
            "the resurrected PIN field comes back BLANK -- Keep on an id no longer in the \
             entry has no prior value to keep"
        );
    }


    #[test]
    fn pick_password_field_agrees_across_a_re_read_when_the_entry_is_unchanged() {
        let conn = kokos_core::db::create_fresh().expect("fresh in-memory vault");
        let now = kokos_core::db::now_unix();

        let created = kokos_core::entries::create(&conn, five_field_login_entry("old-pw"), now)
            .expect("create succeeds");

        let pre = kokos_core::entries::get(&conn, &created.id)
            .unwrap()
            .unwrap();
        let pre_field_id =
            pick_password_field(&pre.fields).expect("a password field must be found");

        let fresh = kokos_core::entries::get(&conn, &created.id)
            .unwrap()
            .unwrap();
        let fresh_field_id =
            pick_password_field(&fresh.fields).expect("a password field must be found");

        assert_eq!(
            pre_field_id, fresh_field_id,
            "an unchanged entry must resolve to the SAME target both times -- this is what \
             lets update_login's guard pass through the common case without falsely aborting"
        );
    }

    #[test]
    fn negative_control_pick_password_field_disagrees_once_the_password_field_is_deleted() {
        let conn = kokos_core::db::create_fresh().expect("fresh in-memory vault");
        let now = kokos_core::db::now_unix();

        let created = kokos_core::entries::create(&conn, five_field_login_entry("old-pw"), now)
            .expect("create succeeds");
        let pre = kokos_core::entries::get(&conn, &created.id)
            .unwrap()
            .unwrap();
        let pre_field_id =
            pick_password_field(&pre.fields).expect("a password field must be found");

        let mut patch: Vec<kokos_core::entries::FieldInput> = pre
            .fields
            .iter()
            .filter(|f| f.id != pre_field_id)
            .map(|f| kokos_core::entries::FieldInput {
                id: Some(f.id.clone()),
                template_id: f.template_id.clone(),
                name: f.name.clone(),
                is_protected: f.is_protected,
                field_type: f.field_type.clone(),
                value: kokos_core::entries::FieldValue::Keep,
            })
            .collect();
        patch.push(kokos_core::entries::FieldInput {
            id: None,
            template_id: Some("tpl_password".to_string()),
            name: "Password".to_string(),
            is_protected: true,
            field_type: "secret".to_string(),
            value: kokos_core::entries::FieldValue::Set("mid-wait-pw".to_string()),
        });
        kokos_core::entries::update(
            &conn,
            &created.id,
            kokos_core::entries::EntryPatch {
                title: None,
                notes: None,
                is_favorite: None,
                folder_id: None,
                fields: Some(patch),
            },
            now + 1,
        )
        .expect("mid-wait edit succeeds")
        .expect("entry still exists");

        let fresh = kokos_core::entries::get(&conn, &created.id)
            .unwrap()
            .unwrap();
        let fresh_field_id =
            pick_password_field(&fresh.fields).expect("a password field must still be found");

        assert_ne!(
            pre_field_id, fresh_field_id,
            "the password field was deleted and recreated under a new id -- the two picks \
             must disagree, or update_login's abort-on-change guard could never fire"
        );
    }


    #[test]
    fn nmh_get_logins_lookup_is_scoped_to_the_active_vault_only() {
        use crate::session_registry::SessionRegistry;
        use kokos_core::crypto::Argon2Params;
        use kokos_core::session::Session;

        const FAST: Argon2Params = Argon2Params {
            memory_kib: 19_456,
            time_cost: 2,
            parallelism: 1,
        };

        let dir_a = tempfile::tempdir().expect("tempdir A");
        let dir_b = tempfile::tempdir().expect("tempdir B");
        let vault_a = kokos_core::vault::create(
            &dir_a.path().join("a.kokos"),
            b"password-a",
            "hint-a",
            FAST,
            None,
        )
        .expect("vault A creates");
        let vault_b = kokos_core::vault::create(
            &dir_b.path().join("b.kokos"),
            b"password-b",
            "hint-b",
            FAST,
            None,
        )
        .expect("vault B creates");

        let url = "https://example.com/login";
        let now = kokos_core::db::now_unix();
        let entry_a = kokos_core::entries::create(
            &vault_a.conn,
            kokos_core::entries::NewEntry {
                title: "Example (vault A)".to_string(),
                folder_id: None,
                notes: None,
                entry_type: "login".into(),
                fields: new_login_fields(url, "user-a", "secret-a"),
            },
            now,
        )
        .expect("insert the A-only login into vault A");
        let entry_b = kokos_core::entries::create(
            &vault_b.conn,
            kokos_core::entries::NewEntry {
                title: "Example (vault B)".to_string(),
                folder_id: None,
                notes: None,
                entry_type: "login".into(),
                fields: new_login_fields(url, "user-b", "secret-b"),
            },
            now,
        )
        .expect("insert the B-only login into vault B");

        let mut reg = SessionRegistry::new();
        let mut session_a = Session::new();
        session_a.vault = Some(vault_a);
        let mut session_b = Session::new();
        session_b.vault = Some(vault_b);
        reg.insert("vault-a".to_string(), session_a);
        reg.insert("vault-b".to_string(), session_b);
        assert!(reg.set_active("vault-a"));

        let ids_while_a_active: Vec<String> = {
            let v = reg
                .active_mut()
                .expect("A is active")
                .vault
                .as_ref()
                .expect("A's vault is open");
            kokos_core::logins::for_url(&v.conn, url, MAX_ITEMS)
                .expect("lookup against the active (A) vault")
                .into_iter()
                .map(|h| h.id)
                .collect()
        };
        assert_eq!(
            ids_while_a_active,
            vec![entry_a.id.clone()],
            "active=A must return ONLY A's entry"
        );
        assert!(
            !ids_while_a_active.contains(&entry_b.id),
            "B's login, present only in the non-active vault, must never be returned"
        );

        assert!(reg.set_active("vault-b"));
        let ids_while_b_active: Vec<String> = {
            let v = reg
                .active_mut()
                .expect("B is active")
                .vault
                .as_ref()
                .expect("B's vault is open");
            kokos_core::logins::for_url(&v.conn, url, MAX_ITEMS)
                .expect("lookup against the active (B) vault")
                .into_iter()
                .map(|h| h.id)
                .collect()
        };
        assert_eq!(
            ids_while_b_active,
            vec![entry_b.id.clone()],
            "active=B must return ONLY B's entry -- flipping set_active must flip the result"
        );
        assert!(
            !ids_while_b_active.contains(&entry_a.id),
            "A's login, now the non-active vault, must never be returned"
        );
    }
}
