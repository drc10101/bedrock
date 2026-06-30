<#
.SYNOPSIS
    Install Bedrock — Identity-Based Security Framework
.DESCRIPTION
    Installs infill-bedrock, creates a desktop shortcut and Start Menu entry.
    Requires Python 3.11+ and pip.
.USAGE
    irm https://infill.systems/install/bedrock.ps1 | iex
    OR
    ./install_bedrock.ps1
#>

param(
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$AppName = "Bedrock"
$AppCmd = "python -m bedrock serve"
$AppPkg = "infill-bedrock"
$BatName = "bedrock.bat"
$IconUrl = "https://infill.systems/assets/bedrock-icon.ico"

# --- Uninstall ---
if ($Uninstall) {
    Write-Host "Uninstalling Bedrock..." -ForegroundColor Yellow
    $DesktopShortcut = "$env:PUBLIC\Desktop\Bedrock.lnk"
    $StartShortcut = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Bedrock.lnk"
    if (Test-Path $DesktopShortcut) { Remove-Item $DesktopShortcut -Force; Write-Host "  Removed desktop shortcut" }
    if (Test-Path $StartShortcut) { Remove-Item $StartShortcut -Force; Write-Host "  Removed Start Menu shortcut" }
    $ScriptsDir = pip show $AppPkg 2>$null | Select-String "Location:" | ForEach-Object { ($_ -split ": ")[1] }
    if ($ScriptsDir) {
        $BatPath = Join-Path $ScriptsDir "..\Scripts\$BatName"
        if (Test-Path $BatPath) { Remove-Item $BatPath -Force; Write-Host "  Removed launcher" }
    }
    Write-Host "Bedrock uninstalled." -ForegroundColor Green
    return
}

# --- Check Python ---
Write-Host ""
Write-Host "  Bedrock — Build your app. Inherit the security." -ForegroundColor Cyan
Write-Host ""

$python = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "3\.(\d+)") {
            $minor = [int]$Matches[1]
            if ($minor -ge 11) { $python = $cmd; break }
        }
    } catch {}
}

if (-not $python) {
    Write-Host "  ERROR: Python 3.11+ not found." -ForegroundColor Red
    Write-Host "  Install Python: https://www.python.org/downloads/" -ForegroundColor White
    Write-Host "  Make sure to check 'Add Python to PATH' during install." -ForegroundColor White
    exit 1
}

$pyVer = & $python --version 2>&1
Write-Host "  Using $pyVer" -ForegroundColor Green

# --- Install package ---
Write-Host "  Installing $AppPkg..." -ForegroundColor Cyan
& $python -m pip install --upgrade $AppPkg
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: pip install failed." -ForegroundColor Red
    exit 1
}

# --- Find Scripts directory ---
$SitePackages = & $python -c "import site; print(site.getsitepackages()[0])" 2>&1
$ScriptsDir = Join-Path (Split-Path $SitePackages -Parent) "Scripts"

# --- Write launcher .bat to Scripts dir ---
$BatContent = @"
@echo off
title Bedrock — Security Framework
echo.
echo  Starting Bedrock server...
echo.
python -m bedrock serve %*
if errorlevel 1 (
    echo.
    echo  Bedrock exited with an error.
    echo  Make sure infill-bedrock is installed: pip install infill-bedrock
    echo.
    pause
)
"@
$BatPath = Join-Path $ScriptsDir $BatName
Set-Content -Path $BatPath -Value $BatContent -Encoding ASCII
Write-Host "  Launcher: $BatPath" -ForegroundColor DarkGray

# --- Download icon (optional, non-blocking) ---
$IconPath = Join-Path $ScriptsDir "bedrock-icon.ico"
try {
    Invoke-WebRequest -Uri $IconUrl -OutFile $IconPath -UseBasicParsing -ErrorAction Stop
} catch {
    Write-Host "  (Icon download skipped — no internet or icon not hosted yet)" -ForegroundColor DarkGray
    $IconPath = $null
}

# --- Create shortcuts ---
$WshShell = New-Object -ComObject WScript.Shell

function New-Shortcut {
    param([string]$Path, [string]$Target, [string]$Icon)
    $Shortcut = $WshShell.CreateShortcut($Path)
    $Shortcut.TargetPath = $Target
    $Shortcut.WorkingDirectory = $env:USERPROFILE
    if ($Icon) { $Shortcut.IconLocation = $Icon }
    $Shortcut.Save()
    Write-Host "  Shortcut: $Path" -ForegroundColor DarkGray
}

$DesktopShortcut = "$env:USERPROFILE\Desktop\Bedrock.lnk"
$StartShortcut = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Bedrock.lnk"

New-Shortcut $DesktopShortcut $BatPath $IconPath
New-Shortcut $StartShortcut $BatPath $IconPath

# --- Done ---
Write-Host ""
Write-Host "  Bedrock installed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "  Quick start:" -ForegroundColor White
Write-Host "    Desktop shortcut: double-click Bedrock" -ForegroundColor Cyan
Write-Host "    Command line:     python -m bedrock serve" -ForegroundColor Cyan
Write-Host "    Initialize:       python -m bedrock init ./my-project" -ForegroundColor Cyan
Write-Host "    Dev license:      python -m bedrock dev --licensee you@example.com" -ForegroundColor Cyan
Write-Host ""