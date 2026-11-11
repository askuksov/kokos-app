# Privacy Policy

_Last updated: 2026-11-11_

Kokos Password Manager is a local-first password manager. Your vault is a single
encrypted file on your own disk. There is no Kokos account, no Kokos server, and
no subscription. The developer never receives your data, because there is
nowhere for it to be sent.

**One part of the vault file is not encrypted: its header.** The header holds
bookkeeping a device needs before the file can even be opened — including the
optional password hint, if you set one. Anyone who holds the vault file can
read that header, hint included, without your master password. Everything
else in the file — every entry, folder, tag, and attachment — is encrypted and
unreadable without it. If you share, back up, or sync a copy of a vault file
somewhere else, treat its hint as visible to whoever ends up with the file.

This document describes every case in which Kokos causes data to leave your
device. All of them are optional and all of them are off unless you turn them
on.

## What Kokos never does

- It does not collect telemetry, analytics, crash reports, or usage statistics.
- It does not contain advertising or third-party tracking of any kind.
- It never transmits your master password, your key file, or the decrypted
  contents of your vault.
- It does not phone home on launch or on any schedule.

## What leaves your device, and only if you enable it

### Cloud sync to your own Google Drive

If you enable Google Drive sync, Kokos uploads your **encrypted** vault file to
your own Google Drive account. The vault contents are encrypted before they
leave the device and Google receives no key.

To obtain access tokens for Drive sync, Kokos sends the stored Google OAuth
refresh token to Google's token endpoint.

Drive sync also writes the vault file name and your backup note as plaintext
Drive metadata (`appProperties`). Kokos does not send the decrypted vault
contents to Google.

Sync also reads the app-private folder: it lists the backups stored there and
downloads the encrypted file when you restore a backup or sync from another
device.

Kokos requests the `drive.appdata` scope only. That scope grants access to an
application-private folder in your Drive and gives Kokos **no ability to read,
list, or modify any other file in your Drive**. You can revoke the access at any
time in your Google Account security settings.

Kokos's use of information received from Google APIs adheres to the
[Google API Services User Data Policy](https://developers.google.com/terms/api-services-user-data-policy),
including the Limited Use requirements.

If you instead use the synced-folder option, Kokos writes the encrypted vault to
a directory you choose. Whatever service syncs that directory — Dropbox,
iCloud Drive, OneDrive, Syncthing — receives the encrypted file and is governed
by its own privacy policy, not this one.

### Breach checking against Have I Been Pwned

If you run a password health check with breach detection enabled, Kokos queries
the Have I Been Pwned range API at `api.pwnedpasswords.com`.

It uses k-anonymity: Kokos computes the SHA-1 hash of the password locally and
sends **only the first five characters** of that hash. The service returns every
known breached hash sharing that prefix, and the comparison happens on your
device. The password itself, and the remaining 35 characters of its hash, never
leave your device, and the service cannot determine which password was checked.

### Downloading the local AI model

The optional AI features run on a model file that is downloaded on first use
rather than shipped inside the application.

Text import downloads its model from `huggingface.co`. The download is pinned to a specific repository revision and verified against a known SHA-256 hash before the file is used.

Semantic search and category suggestions share a separate embedding model that is
not yet published. No download location is pinned for it, so enabling those
features currently fails at the download step rather than fetching anything. When
that model is pinned it will be fetched from `huggingface.co` on the same terms.

Only the download request leaves your device. **The models then run entirely
locally.** No entry, no password, and no text you import is ever sent to any AI
service.

### The browser extension

The Kokos browser extension (for Chrome and Firefox) talks to the desktop
application over a local native-messaging channel on your own machine. The
native-messaging host that serves it has no network capability at all — it
carries no HTTP client and cannot make an outbound request even in principle.
The extension itself makes no network request either, and sends nothing to the
developer or to any third party.

What the extension reads, and where it goes:

- **The address of the active tab.** It is read when you switch tabs or open the
  extension, to show whether Kokos is enabled on that site and to look up
  matching logins. It is passed only to the Kokos app on your machine.
- **Login forms on sites you enabled.** The extension runs on a site only after
  you enable it there, one site at a time. On those sites it reads the username
  and password you submit, to offer saving them, and writes a login into the
  form when you ask it to fill. A submitted login is held in the extension's
  memory until you save it or dismiss the offer, and for two minutes at most,
  then passed to the Kokos app or discarded. So that it does not offer the same
  login twice, the extension remembers the site, the username and a short
  checksum of the password, at most until the browser closes; this record is never
  written to disk.
- **Logins from your vault.** Usernames, passwords and one-time codes come only
  from the Kokos app. By default the app asks you to confirm before it reveals a
  password or code to the extension.

The extension stores two lists in the browser's local extension storage: the
sites you enabled and the sites where you turned off save offers. It stores no
password, username or other secret. Removing the extension removes both lists.

## Where your data lives

| Data | Location |
| --- | --- |
| Vault contents | the encrypted `.kokos` file, wherever you saved it |
| Master password | never stored; held in memory only while the vault is unlocked |
| Master password, if you enable convenience unlock | your operating system's keychain or credential store, under your OS account's protection |
| Google Drive refresh token, if you enable Drive sync | your operating system's keychain or credential store |
| Application settings, the full paths to your open and recent vault files, and any browser-extension ids you've approved | your operating system's standard application-configuration directory |
| The sites you enabled in the browser extension, and the sites where you turned off its save offers | the browser's local storage for the extension |
| Sync bookkeeping — the synced folder's path, or your Drive backup's file reference and any note you typed for it — if you enable sync | your operating system's standard application-configuration directory |
| How many times a failed unlock attempt happened recently, and when | your operating system's standard application-configuration directory, deliberately kept outside the vault — the vault is still locked when an attempt fails, so it cannot be written there |
| The activity log of what happened inside a vault (unlocks, entry changes, and similar events) | inside your encrypted vault |
| The AI model you downloaded, and an encrypted embedding index built from your entries, if you enable AI features | your operating system's standard application-data directory |

## Children

Kokos is not directed at children and collects no data from anyone.

## Changes

Any change to this policy will be published with the release that makes it, and
the date at the top will be updated.

## Contact

Oleksandr Kuksov. Questions about this policy go to the
project's issue tracker on GitHub (github.com/askuksov/kokos-app/issues); a
security concern goes through a private vulnerability report, as SECURITY.md
describes.
