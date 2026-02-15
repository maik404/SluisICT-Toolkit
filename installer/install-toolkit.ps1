# =========================================================================
# SluisICT Netwerk Toolkit - Installer
# =========================================================================
# Gebruik: PowerShell als Administrator, dan .\install-toolkit.ps1
# Detecteert automatisch waar de toolkit staat (portable).
# =========================================================================

param(
    [switch]$NoShortcut
)

$ErrorActionPreference = "Stop"

# Detecteer basepath (1 map omhoog van installer/)
$basePath = Split-Path -Parent $PSScriptRoot
if (-not $basePath) { $basePath = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " SluisICT Netwerk Toolkit v3.5 Installer" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Toolkit locatie: $basePath" -ForegroundColor White
Write-Host ""

$ok = [char]0x2705
$warn = [char]0x26A0
$fail = [char]0x274C
$info = [char]0x2139

# -----------------------------------------------------------------
# 1. Mapstructuur controleren / aanmaken
# -----------------------------------------------------------------
Write-Host "[1/5] Mapstructuur controleren..." -ForegroundColor Yellow

$requiredFolders = @(
    "$basePath\src",
    "$basePath\docs",
    "$basePath\output",
    "$basePath\Tools\Portable\SpeedtestCLI",
    "$basePath\Data\klanten"
)

$created = 0
foreach ($folder in $requiredFolders) {
    if (!(Test-Path $folder)) {
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        Write-Host "  + Aangemaakt: $folder" -ForegroundColor Gray
        $created++
    }
}
if ($created -eq 0) {
    Write-Host "  $ok Alle mappen bestaan al" -ForegroundColor Green
}
else {
    Write-Host "  $ok $created mappen aangemaakt" -ForegroundColor Green
}

# -----------------------------------------------------------------
# 2. Bronbestanden controleren
# -----------------------------------------------------------------
Write-Host "[2/5] Bronbestanden controleren..." -ForegroundColor Yellow

$requiredFiles = @(
    @{ Path = "src\netwerk-diagnose-v3_5.ps1"; Desc = "Hoofdscript" },
    @{ Path = "src\Invoke-SluisICT-AIAnalysis.ps1"; Desc = "AI module" },
    @{ Path = "src\patterns.json"; Desc = "AI patronen" },
    @{ Path = "src\netwerk-diagnose-v3_5-run.bat"; Desc = "Launcher" }
)

$missing = 0
foreach ($file in $requiredFiles) {
    $fullPath = Join-Path $basePath $file.Path
    if (Test-Path $fullPath) {
        Write-Host "  $ok $($file.Desc): $($file.Path)" -ForegroundColor Green
    }
    else {
        Write-Host "  $fail ONTBREEKT: $($file.Path)" -ForegroundColor Red
        $missing++
    }
}

if ($missing -gt 0) {
    Write-Host ""
    Write-Host "  $fail $missing bestand(en) ontbreken. Installatie kan niet doorgaan." -ForegroundColor Red
    Write-Host "  Pak de volledige toolkit zip opnieuw uit." -ForegroundColor Red
    exit 1
}

# -----------------------------------------------------------------
# 3. ExecutionPolicy instellen
# -----------------------------------------------------------------
Write-Host "[3/5] ExecutionPolicy controleren..." -ForegroundColor Yellow

$currentPolicy = Get-ExecutionPolicy -Scope CurrentUser
if ($currentPolicy -in @("RemoteSigned", "Unrestricted", "Bypass")) {
    Write-Host "  $ok ExecutionPolicy is al goed: $currentPolicy" -ForegroundColor Green
}
else {
    try {
        Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
        Write-Host "  $ok ExecutionPolicy ingesteld op RemoteSigned" -ForegroundColor Green
    }
    catch {
        Write-Host "  $warn ExecutionPolicy kon niet worden ingesteld." -ForegroundColor Yellow
        Write-Host "  Start PowerShell als Administrator en probeer opnieuw." -ForegroundColor Yellow
    }
}

# -----------------------------------------------------------------
# 4. Speedtest CLI controleren
# -----------------------------------------------------------------
Write-Host "[4/5] Speedtest CLI controleren..." -ForegroundColor Yellow

$speedtestExe = Join-Path $basePath "Tools\Portable\SpeedtestCLI\speedtest.exe"
if (Test-Path $speedtestExe) {
    $version = & $speedtestExe --version 2>&1 | Select-Object -First 1
    Write-Host "  $ok Speedtest CLI gevonden: $version" -ForegroundColor Green
}
else {
    Write-Host "  $warn Speedtest CLI niet gevonden" -ForegroundColor Yellow
    Write-Host "  $info Download van: https://www.speedtest.net/apps/cli" -ForegroundColor Cyan
    Write-Host "  $info Plaats speedtest.exe in: Tools\Portable\SpeedtestCLI\" -ForegroundColor Cyan
    Write-Host "  $info Zonder speedtest werkt de toolkit, maar zonder snelheidstest." -ForegroundColor Cyan
}

# -----------------------------------------------------------------
# 5. Desktop shortcut aanmaken
# -----------------------------------------------------------------
Write-Host "[5/5] Desktop shortcut..." -ForegroundColor Yellow

if ($NoShortcut) {
    Write-Host "  $info Overgeslagen (parameter -NoShortcut)" -ForegroundColor Cyan
}
else {
    try {
        $batPath = Join-Path $basePath "src\netwerk-diagnose-v3_5-run.bat"
        $shortcutPath = Join-Path $env:USERPROFILE "Desktop\SluisICT Diagnose.lnk"

        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($shortcutPath)
        $Shortcut.TargetPath = $batPath
        $Shortcut.WorkingDirectory = Join-Path $basePath "src"
        $Shortcut.Description = "SluisICT Netwerk Diagnose v3.5"
        $Shortcut.Save()

        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($WshShell) | Out-Null

        Write-Host "  $ok Desktop shortcut aangemaakt" -ForegroundColor Green
    }
    catch {
        Write-Host "  $warn Shortcut kon niet worden aangemaakt: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# -----------------------------------------------------------------
# Samenvatting
# -----------------------------------------------------------------
Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " $ok Installatie voltooid" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Toolkit:  $basePath" -ForegroundColor White
Write-Host "Launcher: src\netwerk-diagnose-v3_5-run.bat" -ForegroundColor White
Write-Host "Shortcut: Desktop\SluisICT Diagnose.lnk" -ForegroundColor White
Write-Host ""
Write-Host "Gebruik:" -ForegroundColor Yellow
Write-Host "  1. Dubbelklik op de desktop shortcut" -ForegroundColor White
Write-Host "  2. Kies Quick (1) of Full (2)" -ForegroundColor White
Write-Host "  3. Resultaat staat in output\ map" -ForegroundColor White
Write-Host ""
