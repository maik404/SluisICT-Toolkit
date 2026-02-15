# =========================================================================
# SluisICT Toolkit - Build Distribution ZIP
# =========================================================================
# Maakt een schone distributie-zip voor uitrol op klant-/veld-laptops.
# Sluit git, output, data en development bestanden uit.
#
# Gebruik: .\build-distribution.ps1
# Output:  E:\SluisICT\dist\SluisICT-Toolkit-v35.zip
# =========================================================================

$ErrorActionPreference = "Stop"

$basePath = Split-Path -Parent $PSScriptRoot
if (-not $basePath) { $basePath = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }

$version  = "v35"
$distDir  = Join-Path $basePath "dist"
$tempDir  = Join-Path $distDir "SluisICT"
$zipName  = "SluisICT-Toolkit-$version.zip"
$zipPath  = Join-Path $distDir $zipName

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " SluisICT Distribution Builder" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Bron:   $basePath" -ForegroundColor White
Write-Host "Output: $zipPath" -ForegroundColor White
Write-Host ""

# Opruimen
if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force }
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

# Bestanden kopieren
$includes = @(
    @{ Src = "src";       Dest = "src" },
    @{ Src = "docs";      Dest = "docs" },
    @{ Src = "installer"; Dest = "installer" }
)

foreach ($item in $includes) {
    $srcPath  = Join-Path $basePath $item.Src
    $destPath = Join-Path $tempDir $item.Dest
    if (Test-Path $srcPath) {
        Copy-Item $srcPath $destPath -Recurse
        Write-Host "  + $($item.Src)\" -ForegroundColor Green
    }
}

# Lege mappen aanmaken (die de installer ook maakt)
@("output", "Tools\Portable\SpeedtestCLI", "Data\klanten") | ForEach-Object {
    New-Item -ItemType Directory -Path (Join-Path $tempDir $_) -Force | Out-Null
}
Write-Host "  + Lege mappen (output, Tools, Data)" -ForegroundColor Green

# Speedtest meenemen als die er is
$speedtestSrc = Join-Path $basePath "Tools\Portable\SpeedtestCLI\speedtest.exe"
if (Test-Path $speedtestSrc) {
    Copy-Item $speedtestSrc (Join-Path $tempDir "Tools\Portable\SpeedtestCLI\speedtest.exe")
    Write-Host "  + speedtest.exe (meegeleverd)" -ForegroundColor Green
} else {
    Write-Host "  - speedtest.exe niet gevonden (niet meegeleverd)" -ForegroundColor Yellow
}

# Individuele bestanden uit root
@("WHATS_NEW_V35.md") | ForEach-Object {
    $src = Join-Path $basePath $_
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $tempDir $_)
        Write-Host "  + $_" -ForegroundColor Green
    }
}

# ZIP maken
Write-Host ""
Write-Host "ZIP aanmaken..." -ForegroundColor Yellow
Compress-Archive -Path $tempDir -DestinationPath $zipPath -Force
Write-Host ""

# Opruimen temp
Remove-Item $tempDir -Recurse -Force

# Resultaat
$zipSize = [math]::Round((Get-Item $zipPath).Length / 1MB, 1)
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host " Klaar: $zipName ($zipSize MB)" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Distributie stappen:" -ForegroundColor Yellow
Write-Host "  1. Kopieer $zipName naar USB/laptop" -ForegroundColor White
Write-Host "  2. Pak uit naar een willekeurige schijf (bijv. C:\ of E:\)" -ForegroundColor White
Write-Host "  3. Open PowerShell, navigeer naar SluisICT\installer\" -ForegroundColor White
Write-Host "  4. Run: .\install-toolkit.ps1" -ForegroundColor White
Write-Host ""
