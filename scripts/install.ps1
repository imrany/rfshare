#Requires -Version 5.1
<#
.SYNOPSIS
    rfshare Windows installer

.DESCRIPTION
    Downloads the latest (or a pinned) rfshare release from GitHub Releases,
    verifies the SHA-256 checksum, then:
      - Tries the .msi installer first (proper Add/Remove Programs integration)
      - Falls back to the portable .zip if .msi is unavailable
    Installs to %LocalAppData%\rfshare with no admin rights required.

.PARAMETER Version
    Release tag to install, e.g. "v0.5.0".  Default: latest.

.PARAMETER BinaryOnly
    Skip the .msi; install the portable binary from the .zip directly.

.PARAMETER Uninstall
    Remove rfshare, PATH entry, Start Menu shortcut, and registry entry.

.EXAMPLE
    # One-liner (paste in PowerShell):
    irm https://raw.githubusercontent.com/imrany/rfshare/main/scripts/install.ps1 | iex

    # Pin a version:
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/imrany/rfshare/main/scripts/install.ps1))) -Version v0.5.0

    # Uninstall:
    & ([scriptblock]::Create((irm https://raw.githubusercontent.com/imrany/rfshare/main/scripts/install.ps1))) -Uninstall
#>
param(
    [string]$Version    = "",
    [switch]$BinaryOnly,
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Repo       = "imrany/rfshare"
$AppName    = "rfshare"
$Publisher  = "Imrany"
$InstallDir = Join-Path $env:LOCALAPPDATA "rfshare"
$ExePath    = Join-Path $InstallDir "rfshare.exe"
$IconDest   = Join-Path $InstallDir "rfshare.ico"
$StartMenu  = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
$Shortcut   = Join-Path $StartMenu "rfshare.lnk"
$RegKey     = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\rfshare"

# ── colours ───────────────────────────────────────────────────────────────────
function Green($s)  { Write-Host $s -ForegroundColor Green  -NoNewline }
function Cyan($s)   { Write-Host $s -ForegroundColor Cyan   -NoNewline }
function Yellow($s) { Write-Host $s -ForegroundColor Yellow -NoNewline }
function Gray($s)   { Write-Host $s -ForegroundColor DarkGray -NoNewline }
function NL()       { Write-Host "" }

function Say($msg)  { Green "==> "; Write-Host $msg }
function Info($msg) { Gray  "    $msg"; NL }
function Warn($msg) { Yellow "  ! "; Write-Host $msg }
function Header($msg) { NL; Cyan $msg; NL }

# ── helpers ───────────────────────────────────────────────────────────────────
function Set-UserPath([string]$dir) {
    $cur = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($cur -notlike "*$dir*") {
        [Environment]::SetEnvironmentVariable("PATH", "$cur;$dir", "User")
        $env:PATH = "$env:PATH;$dir"
        Say "Added $dir to user PATH"
    }
}
function Remove-UserPath([string]$dir) {
    $cur = [Environment]::GetEnvironmentVariable("PATH", "User")
    $upd = ($cur -split ';' | Where-Object { $_ -ne $dir }) -join ';'
    [Environment]::SetEnvironmentVariable("PATH", $upd, "User")
}
function New-AppShortcut([string]$target, [string]$dest, [string]$iconPath) {
    $wsh  = New-Object -ComObject WScript.Shell
    $link = $wsh.CreateShortcut($dest)
    $link.TargetPath       = $target
    $link.Description      = "Fast, encrypted LAN file transfers"
    $link.IconLocation     = "$iconPath,0"
    $link.WorkingDirectory = Split-Path $target
    $link.Save()
}
function Get-Github-Latest {
    $api  = "https://api.github.com/repos/$Repo/releases/latest"
    $resp = Invoke-RestMethod -Uri $api -Headers @{ "User-Agent" = "rfshare-installer" }
    return $resp.tag_name
}
function Download-File([string]$url, [string]$dest) {
    Info "Downloading $(Split-Path $url -Leaf)…"
    $ProgressPreference = 'SilentlyContinue'   # much faster in PowerShell 5
    Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
    $ProgressPreference = 'Continue'
}
function Verify-Checksum([string]$filePath, [string]$shaUrl) {
    $shaPath = "$filePath.sha256"
    try {
        Download-File $shaUrl $shaPath
    } catch {
        Warn "Checksum file not found — skipping verification."
        return
    }
    $expected = (Get-Content $shaPath -Raw).Trim() -replace '\s.*', ''
    $actual   = (Get-FileHash -Algorithm SHA256 $filePath).Hash.ToLower()
    if ($expected.ToLower() -ne $actual) {
        Write-Error "Checksum mismatch!`n  expected: $expected`n  actual:   $actual`nDelete the temp file and retry."
        exit 1
    }
    Info "✓ Checksum verified ($($actual.Substring(0,16))…)"
}
function Test-UrlExists([string]$url) {
    try {
        $r = Invoke-WebRequest -Uri $url -Method Head -UseBasicParsing -ErrorAction Stop
        return $r.StatusCode -eq 200
    } catch { return $false }
}
function Register-ARP([string]$ver, [string]$iconPath) {
    if (-not (Test-Path $RegKey)) { New-Item -Path $RegKey -Force | Out-Null }
    $uninstallCmd = "powershell -NoProfile -ExecutionPolicy Bypass -Command `"& ([scriptblock]::Create((irm https://raw.githubusercontent.com/$Repo/main/scripts/install.ps1))) -Uninstall`""
    $props = @{
        DisplayName     = "rfshare"
        DisplayVersion  = $ver
        Publisher       = $Publisher
        InstallLocation = $InstallDir
        DisplayIcon     = "$iconPath,0"
        UninstallString = $uninstallCmd
        URLInfoAbout    = "https://rfshare.imrany.dev"
        HelpLink        = "https://github.com/$Repo/issues"
        NoModify        = [int]1
        NoRepair        = [int]1
    }
    foreach ($k in $props.Keys) {
        $v = $props[$k]
        if ($v -is [int]) { Set-ItemProperty -Path $RegKey -Name $k -Value $v -Type DWord }
        else               { Set-ItemProperty -Path $RegKey -Name $k -Value $v }
    }
    Say "Registered in Add/Remove Programs"
}

# ── uninstall ─────────────────────────────────────────────────────────────────
if ($Uninstall) {
    Header "Uninstalling rfshare"
    Get-Process -Name "rfshare" -ErrorAction SilentlyContinue | Stop-Process -Force
    if (Test-Path $InstallDir) {
        Remove-Item -Recurse -Force $InstallDir
        Say "Removed $InstallDir"
    }
    if (Test-Path $Shortcut)  { Remove-Item -Force $Shortcut; Say "Removed Start Menu shortcut" }
    Remove-UserPath $InstallDir
    if (Test-Path $RegKey)    { Remove-Item -Path $RegKey -Force }
    Say "rfshare uninstalled."
    exit 0
}

# ── resolve version ───────────────────────────────────────────────────────────
if ([string]::IsNullOrWhiteSpace($Version)) {
    Info "Fetching latest release from GitHub…"
    $Version = Get-Github-Latest
    if ([string]::IsNullOrWhiteSpace($Version)) {
        Write-Error "Could not determine latest version. Pass -Version vX.Y.Z manually."
        exit 1
    }
}
if (-not $Version.StartsWith("v")) { $Version = "v$Version" }
$VerNum  = $Version.TrimStart("v")
$BaseUrl = "https://github.com/$Repo/releases/download/$Version"

Header "rfshare $Version · Windows x64"

# ── temp dir ─────────────────────────────────────────────────────────────────
$Tmp = Join-Path $env:TEMP "rfshare-install-$(Get-Random)"
New-Item -ItemType Directory -Path $Tmp | Out-Null

try {
    $MsiName = "rfshare-$Version-windows-x64.msi"
    $MsiUrl  = "$BaseUrl/$MsiName"
    $MsiPath = Join-Path $Tmp $MsiName

    $UseMsi = $false
    if (-not $BinaryOnly) {
        Info "Checking for .msi installer…"
        $UseMsi = Test-UrlExists $MsiUrl
    }

    if ($UseMsi) {
        # ── Install via .msi ──────────────────────────────────────────────────
        Say "Installing via .msi (recommended)"
        Download-File $MsiUrl $MsiPath
        Verify-Checksum $MsiPath "$MsiUrl.sha256"

        Say "Running Windows Installer (msiexec)…"
        # /qb- = basic UI, no modal at finish; ALLUSERS="" = per-user install
        $msiArgs = @(
            "/i", $MsiPath,
            "/qb-",
            "ALLUSERS=`"`"",
            "/norestart"
        )
        $proc = Start-Process msiexec -ArgumentList $msiArgs -Wait -PassThru
        if ($proc.ExitCode -ne 0) {
            Warn "msiexec exited with code $($proc.ExitCode) — falling back to binary install."
            $UseMsi = $false
        } else {
            Say "rfshare $Version installed via .msi"
        }
    }

    if (-not $UseMsi) {
        # ── Install portable .zip binary ──────────────────────────────────────
        Say "Installing portable binary from .zip"
        $ZipName = "rfshare-windows-$Version.zip"
        $ZipUrl  = "$BaseUrl/$ZipName"
        $ZipPath = Join-Path $Tmp $ZipName

        Download-File $ZipUrl $ZipPath
        Verify-Checksum $ZipPath "$ZipUrl.sha256"

        Say "Extracting…"
        Expand-Archive -Path $ZipPath -DestinationPath $Tmp -Force

        $BinSrc = Get-ChildItem -Path $Tmp -Filter "rfshare.exe" -Recurse |
                  Select-Object -First 1 -ExpandProperty FullName
        if (-not $BinSrc) {
            Write-Error "rfshare.exe not found inside $ZipName"
            exit 1
        }

        if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir | Out-Null }
        Copy-Item -Force $BinSrc $ExePath
        Say "Binary  ->  $ExePath"

        # Download icon
        $IconUrl = "https://raw.githubusercontent.com/$Repo/main/assets/icon.ico"
        try { Download-File $IconUrl $IconDest } catch { Warn "Could not download icon." }

        # PATH
        Set-UserPath $InstallDir

        # Start Menu shortcut
        if (-not (Test-Path $StartMenu)) { New-Item -ItemType Directory -Path $StartMenu | Out-Null }
        $ico = if (Test-Path $IconDest) { $IconDest } else { $ExePath }
        New-AppShortcut -target $ExePath -dest $Shortcut -iconPath $ico
        Say "Start Menu shortcut  ->  $Shortcut"

        # ARP entry
        $ico = if (Test-Path $IconDest) { $IconDest } else { $ExePath }
        Register-ARP -ver $VerNum -iconPath $ico

        # Copy this script into install dir for future -Uninstall
        try {
            $me = $MyInvocation.MyCommand.Path
            if ($me) { Copy-Item -Force $me (Join-Path $InstallDir "install.ps1") }
        } catch {}
    }

} finally {
    Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}

# ── PATH hint ─────────────────────────────────────────────────────────────────
if (-not (Get-Command "rfshare" -ErrorAction SilentlyContinue)) {
    NL
    Warn "rfshare is not in your PATH yet."
    Warn "Restart your terminal, or run: $InstallDir\rfshare.exe"
}

NL
Green "  ✓ "; Write-Host "rfshare $Version installed"
NL
Cyan  "  Run:       "; Write-Host "rfshare"
Cyan  "  Uninstall: "; Gray "Settings > Apps > rfshare  (or run & ([scriptblock]::Create((irm https://raw.githubusercontent.com/imrany/rfshare/main/scripts/install.ps1))) -Uninstall)"; NL
NL
