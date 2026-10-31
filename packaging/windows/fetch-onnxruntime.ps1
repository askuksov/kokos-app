#!/usr/bin/env pwsh
# Stages the ONNX Runtime DLL the Windows bundle ships.
#
# Windows is the one platform that does NOT link ONNX Runtime statically: the
# prebuilt static build `ort` downloads executes BMI2 instructions from its C++
# static initialisers, so on any pre-Haswell CPU the app died before `main` —
# see kokos-ai/Cargo.toml. `kokos-ai` therefore selects ort's
# `load-dynamic` feature under cfg(windows), and something has to put a real
# DLL next to the binary. That is this script.
#
# Microsoft's official build is used rather than the one `ort` fetches because
# it dispatches on CPUID at runtime, which is exactly the property the static
# build lacks.
#
# The DLL is NOT vendored into git: it is a 15 MB third-party binary, and a
# password manager should not carry an opaque blob whose provenance is a commit
# message. It is fetched from the upstream release and checked against a pinned
# digest instead, so a compromised or swapped artifact fails the build rather
# than being bundled silently.
#
# Re-run only when ORT_VERSION below changes; the staged file is gitignored.
$ErrorActionPreference = 'Stop'

# `api-27` in kokos-ai/Cargo.toml is what fixes this floor: ORT_API_VERSION 27
# is answered by ONNX Runtime 1.27 and newer, and by nothing older.
$ORT_VERSION = '1.27.1'
$ZIP_SHA256  = '2E00414A63FDEF0914CD5A5EDE6C707844878E0C08E1B6693842F0451B2DF2A1'
$DLL_SHA256  = '79DF49BCBEFB604C019785925DAEF859C0348280616364E28103D73D4152F6D7'

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$dest     = Join-Path $repoRoot 'src-tauri\binaries\onnxruntime.dll'

if (Test-Path $dest) {
    $have = (Get-FileHash $dest -Algorithm SHA256).Hash
    if ($have -eq $DLL_SHA256) {
        Write-Output "onnxruntime.dll already staged and matches the pinned digest."
        exit 0
    }
    # A mismatch is not automatically an attack — most often it is a leftover
    # from a different ORT_VERSION — but it is never something to build on, so
    # it is replaced rather than trusted.
    Write-Output "staged DLL does not match the pinned digest; re-fetching."
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("kokos-ort-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $name = "onnxruntime-win-x64-$ORT_VERSION"
    $url  = "https://github.com/microsoft/onnxruntime/releases/download/v$ORT_VERSION/$name.zip"
    $zip  = Join-Path $work "$name.zip"

    Write-Output "downloading $url"
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing

    $got = (Get-FileHash $zip -Algorithm SHA256).Hash
    if ($got -ne $ZIP_SHA256) {
        throw "archive digest mismatch`n  expected $ZIP_SHA256`n  got      $got`nRefusing to stage it. If ORT_VERSION was just bumped, update the pinned digests deliberately."
    }

    Expand-Archive -Path $zip -DestinationPath $work -Force
    $src = Join-Path $work "$name\lib\onnxruntime.dll"
    if (-not (Test-Path $src)) { throw "archive did not contain lib/onnxruntime.dll" }

    $got = (Get-FileHash $src -Algorithm SHA256).Hash
    if ($got -ne $DLL_SHA256) {
        throw "DLL digest mismatch`n  expected $DLL_SHA256`n  got      $got"
    }

    Copy-Item $src $dest -Force
    Write-Output "staged $dest"
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
