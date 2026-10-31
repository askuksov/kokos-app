# Kokos — Threat Model

## Scope & assumptions

Kokos is a local-first, offline-capable password manager (Rust/Tauri desktop
app, workspace crates `kokos-core`, `kokos-nmh`, `src-tauri`). It stores an
encrypted vault file on disk and optionally syncs the ciphertext through a
folder (iCloud/Dropbox/etc.) or Google Drive, and optionally exposes a
read/write interface to a companion browser extension via a native-messaging
host.

Adversaries considered in scope:

- **Malware running as the same OS user.** Kokos does not attempt to defend
  the decrypted vault (in-memory key/plaintext) against a process with the
  same OS-user privileges as itself — that is the OS's job, not the app's.
  What it does defend: secrets at rest, secrets in logs/Debug output, and
  narrowing what a same-user process can *reach* without also having the
  master password (e.g. the vault file's ciphertext is useless without it).
- **A network attacker on the sync transport** (folder-sync client or the
  Google Drive API channel).
- **A malicious or compromised browser extension** talking to the native
  messaging host.
- **A malicious import file** (KDBX, JSON, or a crafted `otpauth://` URI).
- **Someone with the encrypted vault file at rest**, or a stolen locked
  device.

Out of scope: OS-level compromise (kernel exploits, root access), physical
keyloggers, and — by a deliberate scope decision — code signing/notarization
and an auto-updater (no Apple/Windows signing infrastructure is available to
the project).

## Assets

| Asset | Where it lives | Protection |
|---|---|---|
| Master password | Never persisted in plaintext; typed by the user or retrieved via keychain/Touch ID | Argon2id-derived key stands in for it everywhere else; the keychain/Touch ID copies are OS-protected (see boundary 7) |
| Argon2id-derived key | In memory only, while a vault is open (`OpenVault.key`, `kokos-core/src/vault.rs`) | `Zeroizing<[u8; 32]>` — wiped on drop/lock/close (`kokos-core/src/session.rs`); redacted in `Debug` (`OpenVault`'s hand-written `impl Debug`) |
| Decrypted vault data (SQLite image) | In memory only, inside the `rusqlite::Connection` held by `OpenVault` | Never written to disk in plaintext; re-encrypted and written atomically on every save (`kokos-core/src/format/atomic.rs`) |
| Optional key file | User-supplied file on disk; only its SHA-256 digest is mixed into the KDF input (`kokos-core/src/keyfile.rs`) | The file's raw bytes are read into a `Zeroizing<Vec<u8>>` and never stored by Kokos |
| TOTP seeds | Inside the encrypted vault; decoded only in `kokos-core/src/totp.rs` | The raw secret never crosses the Rust↔JS IPC boundary — only the current 6/8-digit code and remaining-seconds leave `kokos-core` |
| Keychain-stored master password (macOS fast unlock) | macOS Keychain, service `Kokos` (`src-tauri/src/keyring_store.rs`) | OS Keychain ACL, pinned to the calling binary's code signature (see boundary 7) |
| Touch-ID-gated secret | A separate macOS Keychain item, service `Kokos-Biometric` (`src-tauri/src/biometric_macos.rs`) | `SecAccessControl` with `BIOMETRY_CURRENT_SET`, protection class `AccessibleWhenPasscodeSetThisDeviceOnly` (device-bound, no iCloud sync) |

## Trust boundaries

### 1. Rust ↔ JS IPC

Enforced in `src-tauri/src/commands.rs`. The frontend (WebView/JS) is treated
as untrusted for authorization: every `#[tauri::command]` re-checks state
itself (e.g. `crate::paths::is_allowed(&state.allowed_paths, &path)` before
`create_vault`/`open_vault`/`get_vault_header_info` will touch a path) rather
than trusting anything the caller claims. All decryption, KDF, and session
state live in Rust; the frontend only ever sees derived data (`VaultInfo`,
decrypted field values it's authorized to read, etc.).

Tauri v2's IPC layer does auto-convert a command's **outer argument keys**
from JS camelCase to the Rust parameter's snake_case name. For example, the
frontend calls
`invoke("create_vault", { path, password, hint, kdf, keyfilePath })`
(`src/ipc/commands.ts`) against a Rust signature
`create_vault(..., keyfile_path: Option<String>)` (`commands.rs`), and this
is the mechanism the whole command surface relies on. This does **not**
extend to fields nested one level down inside a single JSON payload argument
— those are plain serde and must already be snake_case on the wire. Two
tests pin this exact failure mode as a deliberate wire contract:
`search_filters_camelcase_multiword_key_is_silently_ignored` and
`gen_opts_camelcase_min_key_is_silently_ignored` (`commands.rs`) assert that
a camelCase key inside a nested payload (`favoritesOnly`, `minUpper`) is
**silently ignored** by serde, not converted — the field quietly keeps its
`#[serde(default)]` value. In short: camelCase → snake_case conversion holds
for outer command arguments only. The nested-payload behavior is the opposite
and an easy trap for anyone adding a new command.

### 2. Crypto core

- `kokos-core/src/crypto.rs`: Argon2id KDF (default params: 65536 KiB
  memory, time cost 3, parallelism 4 — validated range 1024–1,048,576 KiB /
  1–100 iterations / parallelism ≥1) and XChaCha20-Poly1305 AEAD, no AAD.
  Keys are `Zeroizing<[u8; 32]>`. Known-answer tests cross-check both the KDF
  and the AEAD against independently-generated Go reference vectors, so a
  silent drift in algorithm, parameter mapping, or version would fail these
  specific tests (not just the round-trip tests, which would stay green even
  under a self-consistent regression).
- Nonce handling: a fresh random 24-byte XChaCha20 nonce is generated at
  vault creation and again on **every** `vault::save` call
  (`v.header.nonce = crypto::random_nonce()` — comment: "never reuse a
  nonce") and on `change_password`. Nonces are never derived or reused
  across saves.
- `kokos-core/src/format/header.rs`: unencrypted header (magic, version,
  flags, hint, KDF params, salt, nonce); `CURRENT_VERSION = 3`, dual-accepts
  the legacy `VAULTDB\0` magic on read for backward compatibility.
- `kokos-core/src/format/atomic.rs`: save = write to a temp file in the same
  directory, harden its permission bits to match (or 0600 for a new file),
  `sync_all`, rename, then `sync_all` the containing directory — so a crash
  between temp-write and rename leaves the original file intact, and a save
  never widens a vault's file permissions.
- `kokos-core/src/keyfile.rs`: KDF input material is `password || SHA256(keyfile bytes)`.
- `kokos-core/src/vault.rs`: `OpenVault`'s `Debug` impl is **hand-written**,
  not derived, specifically to redact the key field (`"<redacted>"`) —
  the doc comment explicitly warns never to replace it with
  `#[derive(Debug)]`. `verify_password` re-derives the candidate key and
  compares it to the live key with a constant-time XOR-fold (not `==`),
  used to gate credential rotation without re-opening the vault.
- `kokos-core/src/session.rs`: the session holds the only live copy of the
  key/decrypted DB; `lock()`/`close()` drop `OpenVault`, wiping the
  `Zeroizing` key on drop. A `begin_borrow`/`end_borrow` pair (needed
  because `spawn_blocking` requires an owned `OpenVault`) tracks a
  lock/close requested while the vault is temporarily "on loan," so a
  race can't resurrect a vault the user just told the app to lock.

### 3. NMH (browser native messaging)

A 2-hop bridge with no network loopback: browser extension → stdio →
`kokos-nmh` host binary → a local IPC channel → the app. The channel is a
Unix-domain socket on macOS/Linux
(`~/Library/Application Support/dev.kuksov.kokos/nmh.sock`) and a named pipe
on Windows (`\\.\pipe\dev.kuksov.kokos`). Everything above the transport —
framing, origin authentication, the whitelist gate, grants, the token
handshake — is literally the same code on both platforms; only the transport
and the access-control primitives it can use differ.

- `kokos-nmh/src/main.rs` is a dumb proxy: it does no crypto,
  vault, or policy work, and its own doc comment states it deliberately does
  **no logging** because stdout is the protocol channel. It frames/deframes
  JSON (`kokos-nmh/src/framing.rs`, 1 MiB cap enforced on the length prefix
  *before* allocating, in both directions) and forwards to the socket.
- Origin authentication: `kokos-nmh/src/origin.rs::from_args` derives the
  caller's identity from the **launch arguments** the browser supplies
  (`chrome-extension://<id>/` for Chrome; a manifest path + extension id for
  Firefox) — an extension itself cannot pass these; only the browser can.
  This is sent to the app in a `Hello` frame (`kokos-nmh/src/protocol.rs`)
  over the socket, *not* as part of the stdio protocol the extension speaks,
  so an extension cannot forge it via a crafted message.
- The app-side gate is `canonical_origin`/`is_allowed_origin`
  (`src-tauri/src/nmh/mod.rs`): both the stored whitelist entry and the
  incoming origin are reduced to a canonical key before comparing (never a
  raw-string compare) — this specifically prevents an extension from
  impersonating a whitelisted id by appending it as a trailing path
  segment (e.g. `chrome-extension://evil/<whitelisted-id>`). An unparsable
  or absent origin yields `None` → denied; this is fail-closed by
  construction, not by a fallback branch.
- Domain matching is strict eTLD+1 equality via a compiled-in public suffix
  list (`kokos-core/src/url_match.rs::etld_plus_one`/`same_site`) — it is not a "last two labels" heuristic (handles `co.uk`, `github.io`
  correctly per its own tests) and that it treats a backslash as an
  authority terminator (blocks a `evil.com\@example.com` userinfo spoof).
- Per-site grants: `kokos-core/src/nmh_grants.rs` is the **persistent**
  tier (`origin`, `domain`) surviving app restart, keyed by exact
  `(origin, domain)` — a different origin on the same domain does
  NOT inherit a grant (dedicated negative-control test).
  `src-tauri/src/nmh/grants.rs` is the **session** tier
  ("once per site per session"). Both are gated behind a native
  confirmation dialog (`handlers::confirm`) for anything not already
  granted; `save_login`/`update_login` always confirm regardless of any
  grant, per that module's doc comment.
- The socket directory is created `0700` and the socket file `0600`
  (`src-tauri/src/nmh/mod.rs`). Two defense-in-depth peer checks sit on top of
  those permissions: a `getpeereid(2)` same-uid gate at accept, and
  a rotating shared-secret token the host must echo in `Hello`. See the
  UDS peer-auth entry under "Accepted / deferred risks" for exactly what these
  do and do not buy against a same-user attacker.
- **Windows has no file permissions to set here**, so the equivalent controls
  live on the pipe itself (`kokos-nmh/src/transport/named_pipe.rs`): an
  explicit *protected* security descriptor whose DACL is a single ACE granting
  only the current user's SID (never a NULL DACL, which would grant everyone),
  `PIPE_REJECT_REMOTE_CLIENTS` so the name is not reachable over SMB, and
  `FILE_FLAG_FIRST_PIPE_INSTANCE` so a squatter cannot pre-create the name and
  receive connections meant for the app. The kernel enforces the DACL on every
  open, before any of our code runs, which makes it the structural counterpart
  of the `0600` socket. The rotating token is unchanged and platform-neutral.
  What has NO counterpart today is the `getpeereid(2)` gate — see the Windows
  peer-auth entry under "Accepted / deferred risks".

### 4. Sync providers

`kokos-core/src/sync.rs` holds only the ordering logic (`resolve_lww`) and a
`SyncRemote` trait; its own doc comment states the trait "never sees
plaintext." The same holds in the Google Drive client
(`src-tauri/src/gdrive/api.rs`): `DriveClient::create`/`update`/`download`
take/return raw `bytes: &[u8]` and build a `multipart/related` body around
them with no encryption or decryption step in that file — the bytes handed
to `reqwest` are exactly the ciphertext blob `vault::save` already produced.
Reconciliation (`resolve_lww`, tie-broken by `rev` → `modified` →
`device`, lexicographically) runs against the ordering triple
(`OpenVault::sync_meta`) after the vault is already open and decrypted
locally — a pre-decrypt step cannot perform last-writer-wins, so the
comparison itself never touches plaintext either.
`src-tauri/src/sync_config.rs` persists only a Drive file id, revision
number, and last-sync timestamp per vault (`sync.json`, 0600) — its own
comment states it "never holds secrets"; OAuth tokens live in the OS
keyring instead. `src-tauri/src/synced_folder.rs` only detects sibling
conflict-copy files and whether a path looks like it's under a known
synced folder — it has no encryption/decryption logic to check.

### 5. Untrusted-input parsers

- `kokos-core/src/kdbx.rs`: KeePass import via `keepass 0.8.7`. Confirmed
  the panic-safety wrap: `open()` calls `std::panic::catch_unwind` around
  the library's own database-open call, with a comment explaining exactly
  why — `keepass` 0.8.7 indexes the header unchecked in places, so a
  truncated-but-magic-valid file can panic mid-parse; since the input is
  untrusted and no profile sets `panic = "abort"`, the panic is caught and
  mapped to `VaultError::KdbxCorrupt` (fail closed) rather than aborting the
  process. `KdbxEntry`/`KdbxField` have hand-written `Debug` impls that
  redact `password`/`totp_raw`/`value` fields. A dedicated test
  (`import_is_additive_and_never_touches_nmh_grants`) confirms KDBX import
  never writes to the grants table. The KeePass Recycle Bin's entries are
  explicitly skipped at import (treated as user-deleted, not live) — this
  closes a previously-known gap (recycle-bin entries importing as live).
- `kokos-core/src/portable.rs`: JSON import/export. `portable.rs` never
  references `nmh_grants` at all — import only touches vault entries,
  folders, and tags, so it cannot mint or restore a browser-extension
  grant either. Real file attachments are intentionally excluded from the
  export bundle (only live in the encrypted `.kokos` file).
- `kokos-core/src/format/header.rs`: vault-file header parse — bounded reads
  via a `Reader` that checks slice bounds with `checked_add`/`.get(..)`
  (no panics on a truncated/hostile header), capped at a 4096-byte read
  window (`HEADER_READ_LIMIT`) so a malicious file can't force reading past
  the header before the magic/version are even known.
- `kokos-core/src/totp.rs`: `otpauth://` URI / bare-base32 parsing. Bad
  base32 is a typed `VaultError::TotpParse`, not a panic;
  `code_at` explicitly guards `period=0` (would divide by zero) and
  `digits≥10` (would overflow `10u32.pow`) — both are pinned by tests
  (`code_at_survives_zero_period`, `code_at_survives_large_digits`).

### 6. Multivault per-tab isolation

`src-tauri/src/session_registry.rs::SessionRegistry` holds N `Session`s
keyed by canonical absolute path (`VaultId = String`); `resolve()` fails
closed on an unknown explicit id (returns `None` rather than silently
falling back to the active vault). `src-tauri/src/state.rs::AppState` holds
one such registry behind a single `Mutex`. `src-tauri/src/autolock.rs`
itself is a small pure decision function (`should_lock`); the registry's
own `lock_all()` iterates every entry and locks each one — this
is an all-vaults operation, not per-tab, so the global idle watcher that
calls it locks every open vault together. `src-tauri/src/settings.rs`'s
`Settings.open_vaults: Vec<String>` / `active_vault: Option<String>` are the
only restore-related fields — both are plain path strings; there is no key
or password field anywhere in `Settings`, so a restored tab always reopens **locked**.

Residual risk named here: cross-vault leakage between tabs is bounded by
`SessionRegistry` being keyed and resolved per-id everywhere sampled
(`create_vault`/`open_vault` in `commands.rs` re-check state scoped to the
one path/id in question) — but the full command surface (`commands.rs` is
~5,000 lines) was not re-checked command-by-command when this section was
written; the later audits listed under "Audit history" covered multi-vault
session isolation and the full IPC surface.

### 7. macOS platform

- The keychain item (service `Kokos`, `src-tauri/src/keyring_store.rs`,
  backed by the `keyring` crate) has its "Always Allow" ACL pinned to the
  calling binary's code signature. As a consequence, an unsigned/ad-hoc dev
  rebuild re-prompts on every launch (each rebuild has a fresh signature),
  while a build signed with a stable identity does not.
- Touch ID: `src-tauri/src/biometric_macos.rs` stores the master password
  behind a **separate** Keychain service, `Kokos-Biometric`, gated by a
  `SecAccessControl` created with `BIOMETRY_CURRENT_SET` (requires the
  *currently* enrolled fingerprint set — re-enrolling invalidates the item)
  and protection class `AccessibleWhenPasscodeSetThisDeviceOnly` (excluded
  from iCloud Keychain sync/backup; destroyed if the device login password
  is removed). Reading the item's data is what makes the OS itself present
  the Touch ID sheet (`SecItemCopyMatching` with `kSecReturnData`) — the
  gate is OS-enforced, not an app-level check. Every failure mode (no
  entry, wrong finger, cancelled, biometry locked out) collapses to one
  generic error message via `unlock_biometric`'s single `map_err`
  arm — no oracle for which failure occurred.

### 8. Local AI (model download, embedding, text import)

The `kokos-ai` crate holds the local-AI features: semantic search over entry
metadata, and an optional generative text-file import. It depends on `ort`
(ONNX Runtime) and `tokenizers` for embeddings, and on `candle-core` /
`candle-transformers` for pure-Rust CPU inference of a quantized GGUF model
for text import. **Crate isolation:** `kokos-ai` is a dependency of the app
(`src-tauri`) only; none of these runtimes is a dependency of `kokos-core` or
of the native-messaging host `kokos-nmh`, so the heavy/native surface never
enters the tiny NMH binary or the crypto core (checkable with
`cargo tree -e no-dev -i ort` / `-i tokenizers`).

- **Network egress (the only one besides sync).** The only network calls in
  these features are the model downloads, all of which go through
  `kokos-ai/src/download.rs::download_verified` (blocking `reqwest`). The
  embedding model is fetched only by the `ai_model_download` command, which
  the user reaches through a button naming the size, not through the feature
  switch. Downloading and enabling are deliberately separate: consent is given
  to a specific transfer, and `ai_enable` performs no network call at all (it
  refuses with `model_missing` unless the files are already on disk). The
  text-import model is downloaded the same way, by its own opt-in command in
  `src-tauri/src/text_import.rs`, and additionally requires AI to be enabled.
  Every download streams a URL **pinned to a specific Hugging Face commit**,
  hashing as the bytes arrive, and is **SHA-256-verified before the file is
  accepted**: bytes go to a `.part` temp that is renamed onto the destination
  only on a digest match and deleted otherwise, so a mismatch never lands at
  the destination and leaves no temp behind — fail-closed. A ceiling (3 GiB)
  is enforced against both the advertised `Content-Length` and the bytes
  actually received. An empty URL or empty expected hash would also fail
  closed (HTTP error before any write; a 64-char digest can never equal
  `""`), and a test (`every_model_is_fully_pinned`) enforces that every
  registry entry is fully pinned. After download the features are **fully
  offline** — no per-query network, no telemetry. Inference is **CPU-only**.
- **Build-time supply chain.** On macOS and Linux, `ort`'s default
  `download-binaries` feature fetches the ONNX Runtime **native library at
  build time** and links it statically (not pinned by us; `ort-sys`
  self-verifies the download against a baked hmac-sha256). On Windows, ONNX
  Runtime is instead loaded dynamically at runtime from `onnxruntime.dll`
  when an embedding session is first built; a missing or too-old DLL degrades
  to a failing embedder, not a crashing app. Either way this is a
  build/packaging surface rather than a runtime network one, and correct
  bundling of the runtime library is checked at release packaging, not here.
- **Opt-in + audited.** `Settings.ai_enabled` defaults **false** (a
  backward-compat test confirms a pre-existing `settings.json` loads with AI
  off). Enabling, disabling, and model downloads are audited into the active
  vault (`ai_enabled` / `ai_disabled` / `ai_model_downloaded` /
  `ai_gen_model_downloaded`); audit is best-effort and never fails the
  command. `commands::set_settings` accepts a full `Settings` object from the
  frontend, but `settings::preserve_backend_managed` overwrites `ai_enabled`
  and `ai_model` (along with `open_vaults`/`active_vault`) with the backend's
  cached values before saving, so the WebView cannot flip AI on or change the
  model by that route — toggles go only through the audited
  `ai_enable`/`ai_disable` commands. A unit test pins this.
- **Embedding input chokepoint.** `kokos-ai/src/meta.rs::embedding_input` is a
  whitelist: it can only emit the entry title, URL domain, folder name, tag
  names, and entry type — never a password, an `is_protected` value, `notes`,
  a TOTP seed, a PIN, or a card number. A boundary test
  (`embedding_input_whitelists_metadata_and_never_leaks_a_secret`) feeds an
  entry carrying each of those and asserts none reaches the output.
- **Vector storage.** Embeddings live in a per-vault, per-machine sidecar
  (`kokos-ai/src/store.rs`) sealed with XChaCha20-Poly1305 under a subkey
  derived from the vault key (`crypto::derive_subkey` with a domain-separation
  label). It is **not** synced and **not** part of the `.kokos` container. A
  corrupt, truncated, or wrong-key sidecar fails authentication and degrades
  to an empty store that is rebuilt, rather than an error.
- **Generative text import.** Unlike embeddings, text import necessarily feeds
  the full content of a user-chosen plaintext file (up to 4 MiB) to the local
  model, since that file is the credentials being imported. The model's output
  is never trusted as data: every proposed field value must be a **verbatim
  span of the source text**, and `kokos-ai/src/text_import/integrity.rs::validate`
  rejects any span that is out of bounds, off a character boundary, or whose
  echoed value disagrees with the source. The deterministic (LLM-free)
  heuristic importer goes through the same guard. Proposals are shown for
  review before anything is written to the vault. File contents, names, and
  paths are never logged; the audit trail records counts only.

MSRV note: adding local AI raised the workspace `rust-version` from 1.77 to
1.85 (`ort`/`tokenizers` pull `edition2024` transitive deps, e.g.
`rand_pcg 0.10`), and later dependency updates raised it to 1.88 (`ort`
2.0.0-rc.13, `image`, `time`, `plist`, `darling`). The workspace crates are not
published to crates.io (`publish = false`), so there are no external MSRV
consumers.

## Risks & mitigations

| Risk | Boundary | Likelihood / impact | Mitigation | Status |
|---|---|---|---|---|
| Master-password brute force | Crypto core | Low likelihood (requires the vault file) / high impact | Argon2id, default 64 MiB memory / 3 iterations / parallelism 4, tunable up to 1 GiB memory / 100 iterations | Mitigated |
| Crafted `.kokos` KDF cost bomb (DoS on open) | Crypto core / file format | Low likelihood (victim must open a hostile file) / low (transient hang, not compromise) | Open-time ceiling rejects an unauthenticated header asking for >256 MiB or >10 iterations *before* Argon2 runs (`Argon2Params::within_open_budget`), distinct from `validate()`'s wider create-time bounds (kept compatible with the reference implementation) | Mitigated |
| Nonce reuse (AEAD) | Crypto core | Very low / high (nonce reuse breaks XChaCha20-Poly1305 confidentiality) | Fresh random 24-byte nonce generated on every `save`/`change_password`, never reused or derived | Mitigated |
| Secret in logs/Debug output | Crypto core, KDBX parser, sync | Low / high | Hand-written redacting `Debug` impls on `OpenVault`, `PendingRestore`, `KdbxEntry`, `KdbxField`; TOTP/NMH host explicitly never logs | Mitigated |
| Phishing via loose domain match | NMH | Medium / medium | Strict eTLD+1 equality (public suffix list), not a "last two labels" heuristic; backslash-authority spoof blocked | Mitigated |
| Malicious extension origin spoof | NMH | Medium / high | Origin comes from the browser's launch args, not the extension's messages; canonicalized whitelist compare closes the trailing-path impersonation gap | Mitigated |
| Malicious import file crash/DoS | Untrusted-input parsers | Medium / low (crash, not compromise) | `catch_unwind` around the KeePass parser; bounds-checked header reader; guarded TOTP math (no div-by-zero/overflow panics) | Mitigated |
| Cross-vault leak (multivault) | Multivault isolation | Low / medium | Per-id `SessionRegistry` keyed by canonical path; fail-closed `resolve()` on unknown id | Mitigated (partially verified — see boundary 6 residual note) |
| Tampered or substituted AI model download | Local AI | Low / medium | Opt-in download from commit-pinned URLs; SHA-256 verified before the file is accepted, fail-closed with no temp left behind; 3 GiB size ceiling | Mitigated |
| Vault secrets reaching the embedding index | Local AI | Low / high | Whitelist-only `embedding_input` (title, domain, folder, tags, entry type), pinned by a boundary test; vector sidecar AEAD-encrypted under a vault-key subkey, never synced | Mitigated |
| AI output injecting values not present in an imported text file | Local AI | Medium / medium | Integrity guard accepts only verbatim spans of the source text; proposals are reviewed before being committed to the vault | Mitigated |
| Sync server sees plaintext | Sync providers | Low / high | Only ciphertext bytes are ever handed to the Drive/folder transport; LWW reconcile runs post-decrypt, locally | Mitigated |
| Clipboard exposure | N/A (OS clipboard) | Medium / medium | Auto-clear after `clipboard_seconds` (default 30s, user-configurable), plus clear-on-exit; unconditional clear on read failure | Accepted residual |
| Vault file stolen at rest | Crypto core / file format | Medium / high | File is fully AEAD-encrypted; header carries no secret material; atomic-save file permissions never widen (0600 for a new vault) | Mitigated |
| Keychain re-prompt / ACL | macOS platform | High (dev builds) / low (annoyance, not a break) | Keychain ACL is pinned to the binary's code signature (see boundary 7); a stable code-signing identity for release builds avoids the re-prompt | Mitigated (dev-mode limitation documented, not fixed) |
| UDS peer-auth gap | NMH | Low / low (same-user access already compromises the vault) | `getpeereid(2)` same-uid gate + rotating shared-secret token in `Hello`; both defense-in-depth over the `0600` socket — see below | Mitigated (defense-in-depth) |

## Accepted / deferred risks

- **UDS peer-auth gap (MITIGATED — defense-in-depth):** `nmh.sock`
  is reachable by filesystem permissions alone (directory `0700`, socket file
  `0600`), so any process running as the same user can connect and present a
  whitelisted origin in `Hello` — the origin is proven only at the *host's*
  launch-args, never to the app across the socket. Two peer checks now sit on
  the handshake (`src-tauri/src/nmh/mod.rs`):
    1. **`getpeereid(2)` same-uid gate** — `serve()` rejects, before reading a
       byte, any peer whose effective uid is not the app's own. The `0600`
       socket already blocks *other* users from connecting at all; this
       additionally rejects a same-path peer with a *different* euid, the only
       realistic instance of which is a `root` process that bypassed the file
       permissions.
    2. **Rotating shared-secret token** — the app writes a random token to a
       `0600` `nmh.token` file at each listener start (rotated per generation),
       the host reads it (same-user FS access) and echoes it in `Hello`, and
       the app rejects any peer that cannot present the current token
       (`token_matches`).
  **What this does NOT buy (stated plainly, so the mitigation is not
  oversold):** both layers are defense-in-depth *redundant with the `0600`
  socket permission* against the original same-user threat. A same-user
  attacker has the same FS access as the host, so it reads the `0600`
  `nmh.token` file exactly as the host does — and, more to the point, a process
  already running as this user can read the vault, the OS keychain entry, or
  the app's own memory directly. No application-level mechanism defends against
  same-user code execution; only OS-level process isolation would. The token
  binds a connection to the current listener generation and raises the bar a
  step; the uid gate closes the narrow root-bypass case. Plain
  (non-constant-time) token comparison is deliberate: a same-user attacker can
  read the token outright, so a timing side channel here would defend nothing.
  Contrast: KeePassXC uses a libsodium `crypto_box` handshake + key-pinned
  association — a higher bar, but likewise no defense against same-user code
  execution on a single-user account.
- **Windows peer-auth is one notch weaker than unix (ACCEPTED; follow-ups
  named in the code):** the pipe DACL restricts connections to this user's SID
  and the rotating token still binds a connection to the current listener
  generation, but two unix protections have no Windows counterpart yet:
    1. **No peer-SID comparison.** `serve` refuses only a peer it cannot
       identify at all (`peer_is_identifiable`, via
       `GetNamedPipeClientProcessId`); it does not compare the client's user
       against its own. A process holding an elevated token — the rough
       analogue of `root` here — therefore reaches the listener where the
       `getpeereid(2)` gate would have stopped it. Closing it needs
       `OpenProcessToken`/`GetTokenInformation` or
       `ImpersonateNamedPipeClient`; the intended home is named in the code as
       `client_is_same_user()` beside `client_process_id`.
    2. **The token file is not `0600`.**
       `%APPDATA%\dev.kuksov.kokos\nmh.token` inherits the roaming-profile
       ACL, which grants the user, SYSTEM *and* Administrators — strictly
       wider than the unix `0600`. Tightening it with `SetNamedSecurityInfoW`
       is the named follow-up.
  Both sit inside the same concession as the UDS entry above: a process
  running with the user's own rights can read the vault, the credential store
  or the app's memory directly, and no application-level mechanism changes
  that. The honest difference is that unix closes the narrow elevated-bypass
  case and Windows currently does not — a real gap in defense-in-depth rather
  than a cosmetic one.
- **Clipboard exposure:** copying a secret places it on the OS clipboard;
  mitigated by auto-clear after `clipboard_seconds` (default 30s,
  `src-tauri/src/settings.rs`) and an unconditional clear on read failure
  (`commands.rs::clear_clipboard_if_unchanged`). Accepted residual — no OS
  API lets an app fully prevent another app from having already read the
  clipboard in that window.
- **Frontend XSS surface:** limited — no remote content is loaded; CSP is
  `default-src 'self'; script-src 'self'; ...; img-src 'self' data:; ...;
  object-src 'none'; form-action 'none'` (`src-tauri/tauri.conf.json`).

## Audit history

**2026-08 — deep adversarial audit.** Scope: the crypto core, the
native-messaging protocol, multi-vault session isolation, the secret boundary,
and the untrusted parsers. Method: an independent finder pass per surface, with
every candidate finding refuted by a separate reviewer before it was accepted.
Five findings:

- Session grants issued to the browser extension leaked across open vaults.
  Fixed by invalidating in-memory grants on every active-vault change — switch,
  open and create — rather than on an explicit switch alone.
- An out-of-set template field type aborted an entire portable import. Fixed.
- Attacker-controlled KDF parameters were accepted from an unauthenticated
  vault header at open time, allowing resource exhaustion via a crafted file.
  Closed by an open-time ceiling of 256 MiB and 10 iterations, enforced before
  key derivation (see the risk table above).
- The vault header is not AEAD-authenticated. **Accepted** — this matches the
  reference implementation and is not exploitable for disclosure or for
  authentication bypass; only the cosmetic hint field is silently rewritable.
- The Unix-domain socket had no peer authentication. **Mitigated** with two
  defence-in-depth checks: a `getpeereid(2)` same-uid gate, and a rotating
  shared-secret token echoed in the handshake. Both are redundant with the
  `0600` socket mode against a same-user attacker, and are documented as such.

The secret-boundary surface came back clean.

**2026-08 — static application security testing.** Scope: the crypto core; the
backend and its full IPC surface (121 commands at the time); the native-messaging
boundary; sync and the untrusted parsers (OAuth, portable import and export,
KDBX, HIBP); and the frontend. The browser extension was covered separately, as
a requirements specification checked against its own source. Method: audit
only, a finder pass followed by an independent refute-by-default verification
pass, with dismissed candidates recorded alongside the reason for dismissal.

As found: **15 findings — 0 critical, 4 high, 6 medium, 4 low, 1
informational.** The four high-severity findings were a TOTP seed and live code
leaking through a derived debug implementation; a password-change backup that
remained decryptable under the rotated-away password; an uncatchable native
stack overflow on a deeply nested KDBX group, which defeated the documented
fail-closed parser boundary and terminated every open vault; and a clipboard
force-clear on lock that could be starved, letting a copied secret outlive a
lock.

All four high findings, all six medium findings and all four low findings have
been remediated. The KDBX parser is vendored and patched with an in-parser
depth guard covering entry and history recursion. Each backend fix carries a
regression test written failing-first. Three minor trade-offs introduced by the
remediation itself are accepted and recorded: an interaction between the
password-change fix and a pre-migration backup, a best-effort unlink that is
non-fatal when it fails, and a generator bound that is now slightly
over-strict at the class-minimum edge.

**Current posture: low.** No finding from either audit remains open. The one
accepted risk — the unauthenticated vault header — is described above.
