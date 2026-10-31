//! Google Drive v3 client for the app-private `appDataFolder`. Stores the
//! encrypted vault as a single file; the sync ordering triple lives in the
//! file's `appProperties` (rev/modified/device — non-secret), letting us probe
//! "who's newer" without downloading. Base URLs are injectable for tests.

use kokos_core::sync::SyncMeta;

pub const FILE_NAME: &str = "vault.kokos";
const API_BASE: &str = "https://www.googleapis.com/drive/v3";
const UPLOAD_BASE: &str = "https://www.googleapis.com/upload/drive/v3";
/// Drive's appProperties limit: each entry's KEY + VALUE combined must be
/// <=124 bytes — NOT 124 bytes per value. Callers clamp a value to
/// `APP_PROPERTIES_LIMIT - key.len()` via `clamp_bytes` before inserting it.
const APP_PROPERTIES_LIMIT: usize = 124;

/// Truncates `s` to at most `max` bytes, backing off to the nearest UTF-8
/// char boundary so a multi-byte codepoint is never split.
fn clamp_bytes(s: &str, max: usize) -> &str {
    if s.len() <= max { return s; }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) { end -= 1; }
    &s[..end]
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RemoteFile {
    pub id: String,
    pub name: String,
    pub modified_time: String,
    pub size: Option<u64>,
    pub vault_name: Option<String>,
    pub note: Option<String>,
}

pub struct DriveClient {
    access_token: String,
    /// A refresh_token Google returned on the last refresh that DIFFERS from
    /// the one we sent (Google may rotate). The orchestrator persists it to the
    /// keyring. `None` when unchanged/absent or when built via `with_bases`.
    rotated_refresh: Option<String>,
    /// This vault's filename in appDataFolder (per-vault; see
    /// `sync_config::remote_name_for_device`). `find_file`/`create` key off THIS, not
    /// the shared `FILE_NAME` const — that is only the legacy/None fallback the
    /// orchestrator passes for older records.
    file_name: String,
    base: String,
    upload_base: String,
    /// This vault's filename (with extension), written into appProperties.vault_name
    /// on push. Empty = don't write that key (see `create`/`update`).
    vault_name: String,
    /// User-set backup note, written into appProperties.note on push. Empty =
    /// don't write that key.
    note: String,
}

impl DriveClient {
    /// Build from a stored refresh_token by minting a fresh access_token.
    /// Networked (blocking) — callers run it inside `spawn_blocking`.
    pub fn new(refresh_token: &str, file_name: &str) -> Result<Self, String> {
        let tok = crate::gdrive::oauth::refresh_access_token(refresh_token).map_err(|e| e.to_string())?;
        let rotated_refresh = tok.refresh_token.filter(|new| new != refresh_token);
        Ok(Self { access_token: tok.access_token, rotated_refresh, file_name: file_name.to_string(), base: API_BASE.into(), upload_base: UPLOAD_BASE.into(), vault_name: String::new(), note: String::new() })
    }
    /// Test constructor with injectable base URLs + name (never rotates).
    #[cfg(test)]
    pub fn with_bases(access_token: String, file_name: String, base: String, upload_base: String) -> Self {
        Self { access_token, rotated_refresh: None, file_name, base, upload_base, vault_name: String::new(), note: String::new() }
    }
    /// A rotated refresh_token to persist, if Google returned a new one.
    pub fn rotated_refresh(&self) -> Option<&str> { self.rotated_refresh.as_deref() }

    /// Attach the display labels written into each upload's appProperties.
    /// Empty strings mean "don't write that key" (see create/update).
    pub fn with_labels(mut self, vault_name: String, note: String) -> Self {
        self.vault_name = vault_name;
        self.note = note;
        self
    }

    fn client() -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new())
    }
    fn bearer(&self) -> String { format!("Bearer {}", self.access_token) }

    /// The appDataFolder file id, if our vault file already exists.
    pub fn find_file(&self) -> Result<Option<String>, String> {
        let url = format!("{}/files?spaces=appDataFolder&fields=files(id,name)&q={}",
            self.base, urlencoding::encode(&format!("name = '{}'", self.file_name)));
        let resp = Self::client().get(url).header("Authorization", self.bearer())
            .send().map_err(|e| e.to_string())?;
        if !resp.status().is_success() { return Err(resp.text().unwrap_or_default()); }
        let v: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
        Ok(v["files"].as_array().and_then(|a| a.first()).and_then(|f| f["id"].as_str()).map(|s| s.to_string()))
    }

    /// Ordering triple from the file's appProperties (None if unset).
    pub fn get_meta(&self, file_id: &str) -> Result<Option<SyncMeta>, String> {
        let url = format!("{}/files/{}?fields=appProperties", self.base, file_id);
        let resp = Self::client().get(url).header("Authorization", self.bearer())
            .send().map_err(|e| e.to_string())?;
        if !resp.status().is_success() { return Err(resp.text().unwrap_or_default()); }
        let v: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
        let ap = &v["appProperties"];
        let rev = ap["rev"].as_str().and_then(|s| s.parse().ok());
        match rev {
            Some(rev) => Ok(Some(SyncMeta {
                rev,
                modified: ap["modified"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0),
                device: ap["device"].as_str().unwrap_or("").to_string(),
            })),
            None => Ok(None),
        }
    }

    /// Multipart create in appDataFolder. Returns the new file id.
    pub fn create(&self, bytes: &[u8], meta: &SyncMeta) -> Result<String, String> {
        let mut app = serde_json::Map::new();
        app.insert("rev".into(), meta.rev.to_string().into());
        app.insert("modified".into(), meta.modified.to_string().into());
        app.insert("device".into(), meta.device.clone().into());
        if !self.vault_name.is_empty() { app.insert("vault_name".into(), clamp_bytes(&self.vault_name, APP_PROPERTIES_LIMIT - "vault_name".len()).into()); }
        if !self.note.is_empty() { app.insert("note".into(), clamp_bytes(&self.note, APP_PROPERTIES_LIMIT - "note".len()).into()); }
        let metadata = serde_json::json!({
            "name": self.file_name,
            "parents": ["appDataFolder"],
            "appProperties": app,
        });
        let url = format!("{}/files?uploadType=multipart&fields=id", self.upload_base);
        let form = multipart_body(&metadata, bytes);
        let resp = Self::client().post(url)
            .header("Authorization", self.bearer())
            .header("Content-Type", "multipart/related; boundary=kokosB")
            .body(form).send().map_err(|e| e.to_string())?;
        if !resp.status().is_success() { return Err(resp.text().unwrap_or_default()); }
        let v: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
        v["id"].as_str().map(|s| s.to_string()).ok_or_else(|| "no id in create response".into())
    }

    /// Multipart update: replace media + refresh appProperties on an existing file.
    pub fn update(&self, file_id: &str, bytes: &[u8], meta: &SyncMeta) -> Result<(), String> {
        let mut app = serde_json::Map::new();
        app.insert("rev".into(), meta.rev.to_string().into());
        app.insert("modified".into(), meta.modified.to_string().into());
        app.insert("device".into(), meta.device.clone().into());
        if !self.vault_name.is_empty() { app.insert("vault_name".into(), clamp_bytes(&self.vault_name, APP_PROPERTIES_LIMIT - "vault_name".len()).into()); }
        if !self.note.is_empty() { app.insert("note".into(), clamp_bytes(&self.note, APP_PROPERTIES_LIMIT - "note".len()).into()); }
        let metadata = serde_json::json!({
            "appProperties": app,
        });
        let url = format!("{}/files/{}?uploadType=multipart", self.upload_base, file_id);
        let form = multipart_body(&metadata, bytes);
        let resp = Self::client().patch(url)
            .header("Authorization", self.bearer())
            .header("Content-Type", "multipart/related; boundary=kokosB")
            .body(form).send().map_err(|e| e.to_string())?;
        if !resp.status().is_success() { return Err(resp.text().unwrap_or_default()); }
        Ok(())
    }

    /// Update ONLY the note appProperty on an existing backup file, without
    /// re-uploading the vault body. Drive merges appProperties by key, so this
    /// preserves rev/modified/device/vault_name. Sends JSON (no multipart media).
    pub fn patch_app_properties(&self, file_id: &str, note: &str) -> Result<(), String> {
        let note = clamp_bytes(note, APP_PROPERTIES_LIMIT - "note".len());
        let body = serde_json::json!({ "appProperties": { "note": note } });
        let url = format!("{}/files/{}?fields=id", self.base, file_id);
        let resp = Self::client().patch(url)
            .header("Authorization", self.bearer())
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send().map_err(|e| e.to_string())?;
        if !resp.status().is_success() { return Err(resp.text().unwrap_or_default()); }
        Ok(())
    }

    /// Download the raw media (encrypted vault bytes) for a file id.
    pub fn download(&self, file_id: &str) -> Result<Vec<u8>, String> {
        let url = format!("{}/files/{}?alt=media", self.base, file_id);
        let resp = Self::client().get(url).header("Authorization", self.bearer())
            .send().map_err(|e| e.to_string())?;
        if !resp.status().is_success() { return Err(resp.text().unwrap_or_default()); }
        Ok(resp.bytes().map_err(|e| e.to_string())?.to_vec())
    }

    /// List every file in appDataFolder (newest first). Unlike `find_file` this
    /// ignores `self.file_name` — the restore flow needs ALL vault files so the
    /// user can pick which lineage to bootstrap. Drive returns `size` as a
    /// string; parse best-effort (absent for some files -> None).
    pub fn list_appdata_files(&self) -> Result<Vec<RemoteFile>, String> {
        let url = format!(
            "{}/files?spaces=appDataFolder&fields=files(id,name,modifiedTime,size,appProperties)&orderBy=modifiedTime%20desc&pageSize=100",
            self.base);
        let resp = Self::client().get(url).header("Authorization", self.bearer())
            .send().map_err(|e| e.to_string())?;
        if !resp.status().is_success() { return Err(resp.text().unwrap_or_default()); }
        let v: serde_json::Value = resp.json().map_err(|e| e.to_string())?;
        let arr = v["files"].as_array().cloned().unwrap_or_default();
        if arr.len() >= 100 {
            eprintln!("kokos: appDataFolder list hit the 100-file page cap; older files not shown");
        }
        Ok(arr.iter().filter_map(|f| {
            let id = f["id"].as_str()?.to_string();
            let name = f["name"].as_str().unwrap_or("").to_string();
            let modified_time = f["modifiedTime"].as_str().unwrap_or("").to_string();
            let size = f["size"].as_str().and_then(|s| s.parse().ok());
            let ap = &f["appProperties"];
            let vault_name = ap["vault_name"].as_str().filter(|s| !s.is_empty()).map(|s| s.to_string());
            let note = ap["note"].as_str().filter(|s| !s.is_empty()).map(|s| s.to_string());
            Some(RemoteFile { id, name, modified_time, size, vault_name, note })
        }).collect())
    }
}

/// Binds a `DriveClient` to a concrete file id and satisfies the core
/// `SyncRemote` transport trait — the sync orchestrator drives metadata-probe /
/// download / upload through this (using `DriveClient` directly only for the
/// bootstrap `find_file` / `create`). String errors from the HTTP layer map to
/// `VaultError::SyncNetwork`.
pub struct GdriveRemote {
    pub client: DriveClient,
    pub file_id: String,
}

impl kokos_core::sync::SyncRemote for GdriveRemote {
    fn remote_meta(&self) -> kokos_core::error::Result<Option<SyncMeta>> {
        self.client.get_meta(&self.file_id).map_err(kokos_core::error::VaultError::SyncNetwork)
    }
    fn pull(&self) -> kokos_core::error::Result<Vec<u8>> {
        self.client.download(&self.file_id).map_err(kokos_core::error::VaultError::SyncNetwork)
    }
    fn push(&self, bytes: &[u8], meta: &SyncMeta) -> kokos_core::error::Result<()> {
        self.client.update(&self.file_id, bytes, meta).map_err(kokos_core::error::VaultError::SyncNetwork)
    }
}

/// Build a `multipart/related` body (JSON metadata part + binary media part).
fn multipart_body(metadata: &serde_json::Value, media: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(b"--kokosB\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n");
    body.extend_from_slice(metadata.to_string().as_bytes());
    body.extend_from_slice(b"\r\n--kokosB\r\nContent-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(media);
    body.extend_from_slice(b"\r\n--kokosB--\r\n");
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stub_server() -> (String, std::thread::JoinHandle<()>) {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = match server.server_addr() { tiny_http::ListenAddr::IP(a) => a.port(), _ => unreachable!() };
        let base = format!("http://127.0.0.1:{port}");
        let h = std::thread::spawn(move || {
            for req in server.incoming_requests() {
                let url = req.url().to_string();
                let body = if url.contains("/files/FID") {
                    r#"{"appProperties":{"rev":"5","modified":"1700","device":"DEV"}}"#.to_string()
                } else if url.contains("/files?") || url.contains("spaces=appDataFolder") {
                    r#"{"files":[{"id":"FID"}]}"#.to_string()
                } else { "{}".to_string() };
                let _ = req.respond(tiny_http::Response::from_string(body)
                    .with_header("Content-Type: application/json".parse::<tiny_http::Header>().unwrap()));
                break;
            }
        });
        (base, h)
    }

    #[test]
    fn get_meta_parses_appproperties() {
        let (base, h) = stub_server();
        let c = DriveClient::with_bases("AT".into(), FILE_NAME.into(), base.clone(), base);
        let m = c.get_meta("FID").unwrap().unwrap();
        assert_eq!(m.rev, 5);
        assert_eq!(m.modified, 1700);
        assert_eq!(m.device, "DEV");
        h.join().unwrap();
    }

    #[test]
    fn find_file_returns_first_id() {
        let (base, h) = stub_server();
        let c = DriveClient::with_bases("AT".into(), FILE_NAME.into(), base.clone(), base);
        assert_eq!(c.find_file().unwrap().as_deref(), Some("FID"));
        h.join().unwrap();
    }

    #[test]
    fn gdrive_remote_meta_via_trait() {
        use kokos_core::sync::SyncRemote;
        let (base, h) = stub_server();
        let c = DriveClient::with_bases("AT".into(), FILE_NAME.into(), base.clone(), base);
        let r = GdriveRemote { client: c, file_id: "FID".into() };
        let m = r.remote_meta().unwrap().unwrap();
        assert_eq!(m.rev, 5);
        assert_eq!(m.device, "DEV");
        h.join().unwrap();
    }

    #[test]
    fn gdrive_remote_push_pull_roundtrips_via_trait() {
        use kokos_core::sync::{SyncRemote, SyncMeta};
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = match server.server_addr() { tiny_http::ListenAddr::IP(a) => a.port(), _ => unreachable!() };
        let base = format!("http://127.0.0.1:{port}");
        let store = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let s2 = store.clone();
        let h = std::thread::spawn(move || {
            let mut count = 0;
            for mut req in server.incoming_requests() {
                let url = req.url().to_string();
                if url.contains("alt=media") {
                    let body = s2.lock().unwrap().clone();
                    let _ = req.respond(tiny_http::Response::from_data(body));
                } else {
                    let mut buf = Vec::new();
                    let _ = req.as_reader().read_to_end(&mut buf);
                    *s2.lock().unwrap() = buf;
                    let _ = req.respond(tiny_http::Response::from_string(r#"{"id":"FID"}"#));
                }
                count += 1;
                if count >= 2 { break; }
            }
        });
        let r = GdriveRemote {
            client: DriveClient::with_bases("AT".into(), FILE_NAME.into(), base.clone(), base),
            file_id: "FID".into(),
        };
        r.push(b"CIPHERTEXT", &SyncMeta { rev: 2, modified: 9, device: "D".into() }).unwrap();
        let got = r.pull().unwrap();
        assert!(got.windows(b"CIPHERTEXT".len()).any(|w| w == b"CIPHERTEXT"),
            "media bytes must survive push -> server -> pull");
        h.join().unwrap();
    }

    #[test]
    fn find_file_queries_the_per_vault_name_not_the_shared_const() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = match server.server_addr() { tiny_http::ListenAddr::IP(a) => a.port(), _ => unreachable!() };
        let base = format!("http://127.0.0.1:{port}");
        let h = std::thread::spawn(move || {
            let mut count = 0;
            for req in server.incoming_requests() {
                let url = req.url().to_string();
                let body = if url.contains("alice-11111111") { r#"{"files":[{"id":"AID"}]}"# }
                    else if url.contains("bob-22222222") { r#"{"files":[{"id":"BID"}]}"# }
                    else { r#"{"files":[]}"# };
                let _ = req.respond(tiny_http::Response::from_string(body)
                    .with_header("Content-Type: application/json".parse::<tiny_http::Header>().unwrap()));
                count += 1;
                if count >= 2 { break; }
            }
        });
        let a = DriveClient::with_bases("AT".into(), "alice-11111111.kokos".into(), base.clone(), base.clone());
        let b = DriveClient::with_bases("AT".into(), "bob-22222222.kokos".into(), base.clone(), base);
        assert_eq!(a.find_file().unwrap().as_deref(), Some("AID"), "vault A matches only its own remote file");
        assert_eq!(b.find_file().unwrap().as_deref(), Some("BID"), "vault B matches only its own remote file");
        h.join().unwrap();
    }

    #[test]
    fn list_appdata_files_parses_all_rows() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = match server.server_addr() { tiny_http::ListenAddr::IP(a) => a.port(), _ => unreachable!() };
        let base = format!("http://127.0.0.1:{port}");
        let h = std::thread::spawn(move || {
            for req in server.incoming_requests() {
                let body = r#"{"files":[
                    {"id":"A","name":"kokos-dev-a.kokos","modifiedTime":"2026-07-27T10:00:00.000Z","size":"184320"},
                    {"id":"B","name":"vault.kokos","modifiedTime":"2026-07-20T08:00:00.000Z"}
                ]}"#;
                let _ = req.respond(tiny_http::Response::from_string(body)
                    .with_header("Content-Type: application/json".parse::<tiny_http::Header>().unwrap()));
                break;
            }
        });
        let c = DriveClient::with_bases("AT".into(), FILE_NAME.into(), base.clone(), base);
        let files = c.list_appdata_files().unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].id, "A");
        assert_eq!(files[0].name, "kokos-dev-a.kokos");
        assert_eq!(files[0].size, Some(184320));
        assert_eq!(files[1].size, None, "missing size parses to None, not an error");
        h.join().unwrap();
    }

    #[test]
    fn create_writes_labels_and_list_parses_them_back() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = match server.server_addr() { tiny_http::ListenAddr::IP(a) => a.port(), _ => unreachable!() };
        let base = format!("http://127.0.0.1:{port}");
        let captured = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let cap2 = captured.clone();
        let h = std::thread::spawn(move || {
            let mut count = 0;
            for mut req in server.incoming_requests() {
                let url = req.url().to_string();
                if url.contains("uploadType=multipart") {
                    let mut buf = Vec::new();
                    let _ = req.as_reader().read_to_end(&mut buf);
                    *cap2.lock().unwrap() = String::from_utf8_lossy(&buf).to_string();
                    let _ = req.respond(tiny_http::Response::from_string(r#"{"id":"NEWID"}"#));
                } else {
                    let body = r#"{"files":[{"id":"NEWID","name":"kokos-dev.kokos","modifiedTime":"2026-08-04T00:00:00.000Z","size":"100","appProperties":{"rev":"1","modified":"1","device":"D","vault_name":"passwords.kokos","note":"From my Macbook"}}]}"#;
                    let _ = req.respond(tiny_http::Response::from_string(body)
                        .with_header("Content-Type: application/json".parse::<tiny_http::Header>().unwrap()));
                }
                count += 1;
                if count >= 2 { break; }
            }
        });
        let c = DriveClient::with_bases("AT".into(), "kokos-dev.kokos".into(), base.clone(), base)
            .with_labels("passwords.kokos".into(), "From my Macbook".into());
        let meta = SyncMeta { rev: 1, modified: 1, device: "D".into() };
        c.create(b"CIPHERTEXT", &meta).unwrap();

        let sent = captured.lock().unwrap().clone();
        assert!(sent.contains(r#""vault_name":"passwords.kokos""#), "create must write vault_name into appProperties: {sent}");
        assert!(sent.contains(r#""note":"From my Macbook""#), "create must write note into appProperties: {sent}");

        let files = c.list_appdata_files().unwrap();
        assert_eq!(files[0].vault_name.as_deref(), Some("passwords.kokos"));
        assert_eq!(files[0].note.as_deref(), Some("From my Macbook"));
        h.join().unwrap();
    }

    #[test]
    fn list_with_empty_client_labels_and_no_appproperties_parses_to_none() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = match server.server_addr() { tiny_http::ListenAddr::IP(a) => a.port(), _ => unreachable!() };
        let base = format!("http://127.0.0.1:{port}");
        let h = std::thread::spawn(move || {
            for req in server.incoming_requests() {
                let body = r#"{"files":[{"id":"OLD","name":"vault.kokos","modifiedTime":"2026-01-01T00:00:00.000Z","size":"10"}]}"#;
                let _ = req.respond(tiny_http::Response::from_string(body)
                    .with_header("Content-Type: application/json".parse::<tiny_http::Header>().unwrap()));
                break;
            }
        });
        let c = DriveClient::with_bases("AT".into(), FILE_NAME.into(), base.clone(), base);
        let files = c.list_appdata_files().unwrap();
        assert_eq!(files[0].vault_name, None);
        assert_eq!(files[0].note, None);
        h.join().unwrap();
    }

    #[test]
    fn patch_app_properties_targets_base_not_upload_base() {
        let base_server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let base_port = match base_server.server_addr() { tiny_http::ListenAddr::IP(a) => a.port(), _ => unreachable!() };
        let base = format!("http://127.0.0.1:{base_port}");

        let upload_server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let upload_port = match upload_server.server_addr() { tiny_http::ListenAddr::IP(a) => a.port(), _ => unreachable!() };
        let upload_base = format!("http://127.0.0.1:{upload_port}");

        let captured_url = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let captured_body = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let (cu, cb) = (captured_url.clone(), captured_body.clone());
        let base_thread = std::thread::spawn(move || {
            if let Ok(Some(mut req)) = base_server.recv_timeout(std::time::Duration::from_secs(2)) {
                *cu.lock().unwrap() = req.url().to_string();
                let mut buf = Vec::new();
                let _ = req.as_reader().read_to_end(&mut buf);
                *cb.lock().unwrap() = String::from_utf8_lossy(&buf).to_string();
                let _ = req.respond(tiny_http::Response::from_string(r#"{"id":"FID"}"#));
            }
        });
        let upload_thread = std::thread::spawn(move || {
            match upload_server.recv_timeout(std::time::Duration::from_millis(500)) {
                Ok(Some(req)) => {
                    let _ = req.respond(tiny_http::Response::from_string(
                        r#"{"error":{"code":400,"message":"Required parameter is missing: uploadType"}}"#)
                        .with_status_code(400));
                    true
                }
                _ => false,
            }
        });

        let c = DriveClient::with_bases("AT".into(), FILE_NAME.into(), base.clone(), upload_base);
        c.patch_app_properties("FID", "From my Dell").unwrap();

        base_thread.join().unwrap();
        let upload_got_a_request = upload_thread.join().unwrap();
        assert!(!upload_got_a_request, "patch_app_properties must NOT hit upload_base (metadata-only PATCH belongs on base)");

        let url = captured_url.lock().unwrap().clone();
        assert!(!url.is_empty(), "base listener never received the PATCH");
        assert!(url.contains("/files/FID"), "must target files/{{file_id}} on base: {url}");
        let body = captured_body.lock().unwrap().clone();
        assert!(!body.contains("kokosB"), "must be a plain JSON body, not multipart: {body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v, serde_json::json!({ "appProperties": { "note": "From my Dell" } }),
            "metadata-only PATCH must send ONLY note, not rev/modified/device/vault_name");
    }

    /// Drive's appProperties limit is 124 bytes for KEY+VALUE COMBINED, not 124
    /// per value. Builds an over-length `vault_name` (cap 124-10=114) and
    /// `note` (cap 124-4=120) using a 1-byte ASCII prefix + a run of a 2-byte
    /// Cyrillic char, chosen so the byte cap does NOT land on a char boundary
    /// (forcing genuine backoff, not a lucky even split) — proves both fields
    /// are clamped AND the clamp never splits a codepoint.
    #[test]
    fn create_clamps_vault_name_and_note_to_appproperties_byte_limit() {
        let long_name = format!("x{}", "б".repeat(80));
        let long_note = format!("y{}", "б".repeat(80));

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = match server.server_addr() { tiny_http::ListenAddr::IP(a) => a.port(), _ => unreachable!() };
        let base = format!("http://127.0.0.1:{port}");
        let captured = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let cap2 = captured.clone();
        let h = std::thread::spawn(move || {
            if let Ok(Some(mut req)) = server.recv_timeout(std::time::Duration::from_secs(2)) {
                let mut buf = Vec::new();
                let _ = req.as_reader().read_to_end(&mut buf);
                *cap2.lock().unwrap() = String::from_utf8_lossy(&buf).to_string();
                let _ = req.respond(tiny_http::Response::from_string(r#"{"id":"NEWID"}"#));
            }
        });
        let c = DriveClient::with_bases("AT".into(), "kokos-dev.kokos".into(), base.clone(), base)
            .with_labels(long_name, long_note);
        let meta = SyncMeta { rev: 1, modified: 1, device: "D".into() };
        c.create(b"CIPHERTEXT", &meta).unwrap();
        h.join().unwrap();

        let sent = captured.lock().unwrap().clone();
        let header_marker = "charset=UTF-8\r\n\r\n";
        let json_start = sent.find(header_marker).map(|i| i + header_marker.len())
            .expect("multipart body must contain the JSON metadata part header");
        let json_end = sent[json_start..].find("\r\n--kokosB").map(|i| json_start + i).unwrap_or(sent.len());
        let meta_json: serde_json::Value = serde_json::from_str(&sent[json_start..json_end])
            .expect("metadata part must be valid JSON");
        let vault_name_sent = meta_json["appProperties"]["vault_name"].as_str().expect("vault_name must be present");
        let note_sent = meta_json["appProperties"]["note"].as_str().expect("note must be present");

        assert!(vault_name_sent.len() <= APP_PROPERTIES_LIMIT - "vault_name".len(),
            "vault_name must be clamped to {} bytes (key+value<=124), got {} bytes: {vault_name_sent:?}",
            APP_PROPERTIES_LIMIT - "vault_name".len(), vault_name_sent.len());
        assert!(note_sent.len() <= APP_PROPERTIES_LIMIT - "note".len(),
            "note must be clamped to {} bytes (key+value<=124), got {} bytes: {note_sent:?}",
            APP_PROPERTIES_LIMIT - "note".len(), note_sent.len());
        assert!(vault_name_sent.starts_with('x'));
        assert!(note_sent.starts_with('y'));
    }

    #[test]
    fn update_clamps_vault_name_and_note_to_appproperties_byte_limit() {
        let long_name = format!("x{}", "б".repeat(80));
        let long_note = format!("y{}", "б".repeat(80));

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = match server.server_addr() { tiny_http::ListenAddr::IP(a) => a.port(), _ => unreachable!() };
        let base = format!("http://127.0.0.1:{port}");
        let captured = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let cap2 = captured.clone();
        let h = std::thread::spawn(move || {
            if let Ok(Some(mut req)) = server.recv_timeout(std::time::Duration::from_secs(2)) {
                let mut buf = Vec::new();
                let _ = req.as_reader().read_to_end(&mut buf);
                *cap2.lock().unwrap() = String::from_utf8_lossy(&buf).to_string();
                let _ = req.respond(tiny_http::Response::from_string(r#"{"id":"FID"}"#));
            }
        });
        let c = DriveClient::with_bases("AT".into(), "kokos-dev.kokos".into(), base.clone(), base)
            .with_labels(long_name, long_note);
        let meta = SyncMeta { rev: 2, modified: 9, device: "D".into() };
        c.update("FID", b"CIPHERTEXT", &meta).unwrap();
        h.join().unwrap();

        let sent = captured.lock().unwrap().clone();
        let json_start = sent.find("{\"appProperties\"").expect("multipart body must contain the JSON metadata part");
        let json_end = sent[json_start..].find("\r\n--kokosB").map(|i| json_start + i).unwrap_or(sent.len());
        let meta_json: serde_json::Value = serde_json::from_str(&sent[json_start..json_end])
            .expect("metadata part must be valid JSON");
        let vault_name_sent = meta_json["appProperties"]["vault_name"].as_str().expect("vault_name must be present");
        let note_sent = meta_json["appProperties"]["note"].as_str().expect("note must be present");

        assert!(vault_name_sent.len() <= APP_PROPERTIES_LIMIT - "vault_name".len(),
            "vault_name must be clamped, got {} bytes", vault_name_sent.len());
        assert!(note_sent.len() <= APP_PROPERTIES_LIMIT - "note".len(),
            "note must be clamped, got {} bytes", note_sent.len());
    }

    #[test]
    fn patch_app_properties_clamps_note_to_appproperties_byte_limit() {
        let long_note = format!("y{}", "б".repeat(80));

        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = match server.server_addr() { tiny_http::ListenAddr::IP(a) => a.port(), _ => unreachable!() };
        let base = format!("http://127.0.0.1:{port}");
        let captured = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let cap2 = captured.clone();
        let h = std::thread::spawn(move || {
            if let Ok(Some(mut req)) = server.recv_timeout(std::time::Duration::from_secs(2)) {
                let mut buf = Vec::new();
                let _ = req.as_reader().read_to_end(&mut buf);
                *cap2.lock().unwrap() = String::from_utf8_lossy(&buf).to_string();
                let _ = req.respond(tiny_http::Response::from_string(r#"{"id":"FID"}"#));
            }
        });
        let c = DriveClient::with_bases("AT".into(), FILE_NAME.into(), base.clone(), base);
        c.patch_app_properties("FID", &long_note).unwrap();
        h.join().unwrap();

        let body = captured.lock().unwrap().clone();
        let v: serde_json::Value = serde_json::from_str(&body).expect("plain JSON body");
        let note_sent = v["appProperties"]["note"].as_str().expect("note must be present");
        assert!(note_sent.len() <= APP_PROPERTIES_LIMIT - "note".len(),
            "note must be clamped to {} bytes (key+value<=124), got {} bytes", APP_PROPERTIES_LIMIT - "note".len(), note_sent.len());
        assert!(note_sent.starts_with('y'));
    }
}
