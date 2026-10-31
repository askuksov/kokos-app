# Sidecar binaries

`kokos-nmh` (the native-messaging host) ships beside the app binary.
Tauri resolves `externalBin: ["binaries/kokos-nmh"]` to
`binaries/kokos-nmh-<target-triple>`, so before building run:

    cargo build --release -p kokos-nmh
    TRIPLE=$(rustc -vV | sed -n 's/^host: //p')
    cp target/release/kokos-nmh "src-tauri/binaries/kokos-nmh-$TRIPLE"

On Windows (PowerShell) the binary has an `.exe` suffix:

    cargo build --release -p kokos-nmh
    $triple = (rustc -vV | Select-String '^host:').ToString().Split(' ')[1]
    Copy-Item target\release\kokos-nmh.exe "src-tauri\binaries\kokos-nmh-$triple.exe"

The copies are build artifacts — keep `src-tauri/binaries/kokos-nmh-*` out of
git (see .gitignore) and re-copy after every host change.

**This copy is required before ANY `cargo build -p kokos` / `cargo test -p
kokos` / `tauri dev` / `tauri build` of the `kokos` crate — there is no
dev-mode exemption.** Declaring `externalBin` makes Tauri's build script
(`copy_binaries`, tauri-build) run unconditionally whenever
`bundle.externalBin` is set, on every build of the `kokos` crate, debug or
release; it *copies* `binaries/kokos-nmh-<target-triple>` to
`target/debug/kokos-nmh` (stripping the triple suffix) — it does not read
`target/debug/kokos-nmh` as an alternative source. If the triple-suffixed
file is missing, the build fails outright with:

    resource path `binaries/kokos-nmh-<target-triple>` doesn't exist

This was verified empirically on 2026-07-29 (aarch64-apple-darwin): with the
sidecar absent, `cargo build -p kokos` failed with the error above (the same
debug build `tauri dev` triggers); after running the two commands above, the
same build succeeded.

**This is NOT a one-time-per-checkout step.** Because `copy_binaries` *copies*
`binaries/kokos-nmh-<target-triple>` over `target/debug/kokos-nmh` on every
single `cargo build -p kokos`, the two commands above must be re-run after
**every** change to `kokos-nmh` — not once when you first clone the repo.
Skip a re-copy after editing the host and the very next `cargo build -p
kokos` silently restores the stale binary over your change, with no error
anywhere; a live browser check then runs the old host.

## `onnxruntime.dll` (Windows only)

`src-tauri/tauri.windows.conf.json` declares this file as a bundle resource,
so — exactly like the sidecar above — a Windows build **fails outright when it
is missing**, with `resource path binaries/onnxruntime.dll doesn't exist`.
Stage it with:

    packaging\windows\fetch-onnxruntime.ps1

Why it exists at all: Windows is the one platform that does not link ONNX
Runtime statically. The prebuilt static build `ort` downloads runs BMI2
instructions from its C++ static initialisers, so on a pre-Haswell CPU every
binary linking `kokos-ai` died with STATUS_ILLEGAL_INSTRUCTION before `main`.
`kokos-ai` therefore selects ort's `load-dynamic` feature under cfg(windows),
and Microsoft's official DLL — which dispatches on CPUID at runtime — supplies
the runtime.

Unlike the sidecar, this one is NOT rebuilt from our sources: it is a pinned
upstream binary verified against digests in the fetch script, so it only needs
re-staging when that pinned version changes. It is gitignored for the same
reason the sidecar copies are — a 15 MB third-party binary does not belong in
the repo.
