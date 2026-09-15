[CmdletBinding()]
param(
    [string]$AppExe,
    [string]$OutputRoot,
    [string]$Image = 'ghcr.io/mrmamongo/gp-relay:latest',
    [switch]$Zip
)

# Portable-комплект: ТОЛЬКО exe. Docker-контекст (Dockerfile/dante.conf/entry.sh)
# вшит в бинарь, образ тянется из ghcr.io, а если реестр недоступен — собирается
# из вшитого контекста. Никаких docker-compose.yml и каталогов-спутников.

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($AppExe)) {
    $AppExe = Join-Path $projectRoot 'src-tauri\target\release\globalprotect-remote-gui.exe'
}
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $projectRoot 'packages'
}

$appSource = [System.IO.Path]::GetFullPath($AppExe)
if (-not (Test-Path -LiteralPath $appSource -PathType Leaf)) {
    throw "Release executable not found: $appSource. Run 'pnpm tauri build' first."
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$portableRoot = Join-Path ([System.IO.Path]::GetFullPath($OutputRoot)) "gp-relay-portable-windows-x64-$stamp"
New-Item -ItemType Directory -Path $portableRoot -Force | Out-Null

Copy-Item -LiteralPath $appSource -Destination (Join-Path $portableRoot 'GP Relay.exe')

@"
GP Relay portable for Windows x64

Single file: GP Relay.exe  (no installer, no docker/ folder, no compose file)

Requirements
  Docker Desktop (running). WebView2 Runtime is preinstalled on Windows 11.

What it does on first Connect
  1. docker inspect gp-relay - if the container runs, it is reused;
  2. otherwise the image $Image is pulled from the registry;
  3. if the registry is unreachable, the image is built on the spot from the
     docker context embedded inside this exe (Dockerfile + dante.conf + entry.sh);
  4. the container starts (NET_ADMIN + /dev/net/tun + SOCKS5 on 127.0.0.1:1080);
  5. openconnect runs inside it (docker exec + socat PTY) and asks for
     login / password / MFA / gateway selection directly in the GUI window.

Result
  SOCKS5 proxy: socks5h://127.0.0.1:1080  (dante inside the container)

Notes
  - Image size ~63 MB; no QEMU and no VM image are involved.
  - No SSH anywhere: the GUI talks to the container directly.
  - dante re-binds to the tunnel IP automatically once openconnect is up.
"@ | Set-Content -LiteralPath (Join-Path $portableRoot 'README.txt') -Encoding UTF8

$sums = Get-ChildItem -LiteralPath $portableRoot -File -Recurse |
    Where-Object { $_.Name -ne 'SHA256SUMS.txt' } |
    ForEach-Object {
        $rel = $_.FullName.Substring($portableRoot.Length + 1) -replace '\\', '/'
        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLower()
        "$hash  $rel"
    }
$sums | Set-Content -LiteralPath (Join-Path $portableRoot 'SHA256SUMS.txt') -Encoding UTF8

$exeBytes = [System.IO.File]::ReadAllBytes((Join-Path $portableRoot 'GP Relay.exe'))
if (-not ($exeBytes[0] -eq 0x4D -and $exeBytes[1] -eq 0x5A)) {
    throw 'GP Relay.exe is not a valid Windows PE executable'
}

$files = Get-ChildItem -LiteralPath $portableRoot -File -Recurse
$total = ($files | Measure-Object Length -Sum).Sum
Write-Host "Portable kit ready: $portableRoot"
Write-Host ("Files: {0}; total: {1:N1} MiB" -f $files.Count, ($total / 1MB))

if ($Zip) {
    $zipPath = "$portableRoot.zip"
    Compress-Archive -Path (Join-Path $portableRoot '*') -DestinationPath $zipPath -Force
    Write-Host ("Archive: {0} ({1:N1} MiB)" -f $zipPath, ((Get-Item -LiteralPath $zipPath).Length / 1MB))
}
