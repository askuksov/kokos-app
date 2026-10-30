# Kokos

A local-first, encrypted password manager for the desktop.

A vault is a single `.kokos` file on your own disk, encrypted with
XChaCha20-Poly1305 under a key derived from your master password with Argon2id.
There is no Kokos account and no Kokos server. Nothing leaves your machine unless
you turn on synchronisation or the breach check yourself; both are off by default.

Kokos is a Rust core behind a Tauri 2 shell, with a React and TypeScript
interface. It runs on macOS, Linux and Windows.

## Features

- **One encrypted file per vault.** Optional key file as a second secret. No
  password recovery: the master password never leaves the device.
- **Several vaults at once,** each in its own tab, locked independently.
- **Entry types.** Login, card, secure note and Wi-Fi, with custom fields, field
  templates, attachments, edit history and live TOTP codes.
- **Search and command palette.** Instant full-text search, favourites, regex
  search, and ⌘K for every action.
- **Password generator** and **password health**: weak and reused passwords are
  found locally.
- **Breach check (opt-in)** against Have I Been Pwned with k-anonymity: only the
  first five characters of a SHA-1 hash are sent.
- **Sync (opt-in)** through a folder you already sync, or your own Google Drive
  app-data folder. Only the encrypted file is uploaded.
- **Import and export.** Kokos JSON, encrypted `.kokos` copies, KeePass `.kdbx`,
  and AI-assisted import of passwords kept in plain text files. The AI model runs
  locally; nothing you import is sent anywhere.
- **Browser extension** for saving and filling logins, over a local
  native-messaging bridge with per-site permission:
  [kokos-extension](https://github.com/askuksov/kokos-extension).
- **Auto-lock and clipboard auto-clear.** Optional Touch ID or keychain unlock
  on macOS.

## Install

Releases will be published on the
[Releases](https://github.com/askuksov/kokos-app/releases) page.

## Build from source

You need Rust (stable), Node.js 20.19 or later, and the
[Tauri prerequisites](https://tauri.app/start/prerequisites/) for your platform.

```sh
npm install
npm run tauri dev     # run in development
npm run tauri build   # build installers for this platform
```

A self-build is not byte-identical to a released binary, and Google Drive sync
needs an OAuth client of your own. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security and privacy

- Report vulnerabilities privately, as [SECURITY.md](SECURITY.md) describes.
  Never in a public issue.
- [PRIVACY.md](PRIVACY.md) lists every case in which Kokos sends data off your
  device.

## Contributing

Bug reports, feature requests and design questions are welcome as issues. Pull
requests are not accepted; [CONTRIBUTING.md](CONTRIBUTING.md) explains why.

## Licence

MIT License. See [LICENSE](LICENSE).

The licence covers the code, not the name. "Kokos" and the Kokos logo are not
licensed: a fork or a derivative may not be distributed under this name or a
confusingly similar one.
