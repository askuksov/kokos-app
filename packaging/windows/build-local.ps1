#!/usr/bin/env pwsh
# Full local Windows build: sidecar, dependencies, release binaries, NSIS installer.
#
# Usage (from the repo root):
#   powershell -ExecutionPolicy Bypass -File packaging/windows/build-local.ps1
#   powershell -ExecutionPolicy Bypass -File packaging/windows/build-local.ps1 -SkipInstaller
#
# Steps:
#   1. npm install (frontend dependencies)
#   2. fetch-onnxruntime.ps1 (the staged DLL the bundle ships; skipped when present)
#   3. cargo build --release -p kokos -p kokos-nmh, then stage the sidecar as
#      src-tauri/binaries/kokos-nmh-<triple>.exe (required by `externalBin`;
#      the staged copies are gitignored build artifacts)
#   4. npm run tauri build -- --bundles nsis (unless -SkipInstaller)
#
# The installer lands at target/release/bundle/nsis/Kokos_<version>_x64-setup.exe.
param([switch]$SkipInstaller)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $repoRoot

npm.cmd install
if ($LASTEXITCODE -ne 0) { throw "npm install failed" }

$dll = Join-Path $repoRoot 'src-tauri/binaries/onnxruntime.dll'
if (-not (Test-Path $dll)) {
  & (Join-Path $PSScriptRoot 'fetch-onnxruntime.ps1')
} else {
  Write-Host "onnxruntime.dll already staged, skipping fetch."
}

cargo build --release -p kokos -p kokos-nmh
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

$triple = (rustc -vV | Select-String '^host:').ToString().Split(' ')[1]
Copy-Item (Join-Path $repoRoot 'target/release/kokos-nmh.exe') `
  (Join-Path $repoRoot "src-tauri/binaries/kokos-nmh-$triple.exe") -Force
Write-Host "Staged sidecar for $triple."

if (-not $SkipInstaller) {
  npm.cmd run tauri build -- --bundles nsis
  if ($LASTEXITCODE -ne 0) { throw "tauri build failed" }
  Get-ChildItem (Join-Path $repoRoot 'target/release/bundle/nsis/*-setup.exe')
}
