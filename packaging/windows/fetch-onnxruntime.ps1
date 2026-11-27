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
# message. It is fetched from Microsoft's official NuGet package
# (Microsoft.ML.OnnxRuntime, which carries the same win-x64 DLL as the GitHub
# release archive), with the GitHub release as a fallback, and both the
# download and the DLL are checked against pinned digests, so a compromised or
# swapped artifact fails the build rather than being bundled silently.
#
# Re-run only when ORT_VERSION below changes; the staged file is gitignored.
$ErrorActionPreference = 'Stop'

# `api-27` in kokos-ai/Cargo.toml is what fixes this floor: ORT_API_VERSION 27
# is answered by ONNX Runtime 1.27 and newer, and by nothing older.
$ORT_VERSION = '1.27.1'
$NUPKG_SHA256 = '9359E46EBA4482DED00E678C98F22B68F51BB411D7934F5516D64050EDFA3383'
$ZIP_SHA256   = '2E00414A63FDEF0914CD5A5EDE6C707844878E0C08E1B6693842F0451B2DF2A1'
$DLL_SHA256   = '79DF49BCBEFB604C019785925DAEF859C0348280616364E28103D73D4152F6D7'

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

Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("kokos-ort-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null

# Each source: where to download, the pinned archive digest, and where the DLL
# sits inside the archive. Tried in order; any digest mismatch is fatal.
$sources = @(
    @{ Name   = 'NuGet Microsoft.ML.OnnxRuntime'
       Url    = "https://api.nuget.org/v3-flatcontainer/microsoft.ml.onnxruntime/$ORT_VERSION/microsoft.ml.onnxruntime.$ORT_VERSION.nupkg"
       Sha256 = $NUPKG_SHA256
       Inner  = 'runtimes/win-x64/native/onnxruntime.dll' },
    @{ Name   = 'GitHub release'
       Url    = "https://github.com/microsoft/onnxruntime/releases/download/v$ORT_VERSION/onnxruntime-win-x64-$ORT_VERSION.zip"
       Sha256 = $ZIP_SHA256
       Inner  = "onnxruntime-win-x64-$ORT_VERSION/lib/onnxruntime.dll" }
)

try {
    $staged = $false
    foreach ($s in $sources) {
        $zip = Join-Path $work ("ort-" + [System.Guid]::NewGuid().ToString('N') + ".zip")
        Write-Output "downloading $($s.Url)"
        try {
            Invoke-WebRequest -Uri $s.Url -OutFile $zip -UseBasicParsing
        } catch {
            # Unreachable source: try the next one. A digest mismatch below is
            # never retried this way.
            Write-Output "  unavailable from $($s.Name): $($_.Exception.Message)"
            continue
        }

        $got = (Get-FileHash $zip -Algorithm SHA256).Hash
        if ($got -ne $s.Sha256) {
            throw "archive digest mismatch ($($s.Name))`n  expected $($s.Sha256)`n  got      $got`nRefusing to stage it. If ORT_VERSION was just bumped, update the pinned digests deliberately."
        }

        # Extract only the DLL entry (zip entry names use '/'). A .nupkg is a
        # zip archive; reading it directly avoids Expand-Archive tripping over
        # package metadata such as `[Content_Types].xml`.
        $src = Join-Path $work 'onnxruntime.dll'
        $archive = [System.IO.Compression.ZipFile]::OpenRead($zip)
        try {
            $entry = $archive.Entries | Where-Object { $_.FullName -eq $s.Inner } | Select-Object -First 1
            if (-not $entry) { throw "archive from $($s.Name) did not contain $($s.Inner)" }
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $src, $true)
        } finally {
            $archive.Dispose()
        }

        $got = (Get-FileHash $src -Algorithm SHA256).Hash
        if ($got -ne $DLL_SHA256) {
            throw "DLL digest mismatch ($($s.Name))`n  expected $DLL_SHA256`n  got      $got"
        }

        Copy-Item $src $dest -Force
        Write-Output "staged $dest (from $($s.Name))"
        $staged = $true
        break
    }
    if (-not $staged) { throw "ONNX Runtime $ORT_VERSION could not be downloaded from any source" }
} finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
