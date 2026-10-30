# Security Policy

Kokos guards credentials, so a security report matters more here than almost any
other kind of issue. Thank you for taking the time.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report it privately through GitHub: open the repository's **Security** tab and
choose **Report a vulnerability**. Only the maintainers see the report. Include:

- a description of the issue and why you believe it is exploitable,
- the steps to reproduce it,
- the Kokos version and the operating system you saw it on,
- anything you are willing to share about impact.

Never include a real vault file, a real password, or a real key file in a
report. A synthetic reproduction is always sufficient.

## What to expect

| Stage | Target |
| --- | --- |
| Acknowledgement of your report | within 5 days |
| An initial assessment | within 14 days |
| Status updates while a fix is in progress | at least every 14 days |

If a report is confirmed, the fix ships in the next release and the advisory
names you as the reporter unless you ask otherwise.

## Scope

In scope: the desktop application, the native-messaging host, the browser
extension, the vault file format, and the packaging channels themselves — for
example a corrupted or tampered package, or a vulnerability in how a package
is put together.

Out of scope: attacks requiring OS-level compromise — kernel exploits or root —
and physical keyloggers. Kokos decrypts the vault into memory while it is
unlocked and does not attempt to defend that in-memory state against a process
running as the same operating-system user; that is documented behaviour, shared
with comparable products, and a report restating it is not a vulnerability.

Also out of scope, matching the project's threat model (`docs/THREAT-MODEL.md`):
code signing and notarization, and the build-time supply chain. Signing is
still being set up for every platform, and Windows installers are not
code-signed yet, so a report that an installer is unsigned or a macOS build is
not notarized, while true, will not receive the acknowledgement schedule or fix
commitment above. The same applies to the
build-time supply chain (for instance how a build dependency fetches its own
native binaries at compile time), which the threat model documents as a
build/release-time concern reviewed at packaging time, not a runtime
vulnerability surface this policy tracks.

Other attacks by a same-user process ARE in scope: secrets at rest, secrets
reaching logs or debug output, and whatever a same-user process can reach
without the master password. See `docs/THREAT-MODEL.md` for the full model.

## Dependency audit

`npm audit` is usually the first command run after cloning this repository.
Run it two ways, because the two answers mean different things:

```sh
npm audit --omit=dev   # the dependencies that ship inside the application
npm audit              # the above, plus the toolchain that builds it
```

Kokos has four direct runtime JavaScript dependencies — `@tauri-apps/api`,
`pdfjs-dist`, `react` and `react-dom`. Everything else in the graph is build
tooling: Vite, Babel, TypeScript, the Tauri CLI and what those pull in. That
code runs on the machine performing the build and is not bundled into the
application.

Neither answer is meaningless. An advisory against a runtime dependency is
reachable by whatever the application processes, and is in scope for this
policy. An advisory against build tooling is not reachable at runtime — but a
build dependency that is genuinely compromised can still write into the
artifact it produces, so this is a narrower scope, not a dismissal. Where that
line falls for this project is set by the Scope section above, which places
the build-time supply chain outside the acknowledgement schedule.

The lockfile is refreshed while a release is prepared, not continuously.
Advisories are published constantly, so a published snapshot can report
build-tooling advisories that did not exist on the day it was published; that
on its own is expected and is not a security report. Worth a report: anything
affecting a runtime dependency, or a concrete path by which a build-time
advisory reaches the shipped application.

## Source access

The source is published for exactly this purpose, under the MIT
License (see LICENSE). If you need access to something that is not
published in order to complete a review, ask through a private vulnerability
report — access can be arranged under a separate written agreement.
