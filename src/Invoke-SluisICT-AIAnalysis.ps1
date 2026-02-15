# =========================================================================
# SluisICT - AI Analyse Module v3.5
# =========================================================================
# Leest diagnostische output bestanden en voert regelgebaseerde analyse uit
# op basis van patterns.json. Produceert 98_ai_analyse.txt en vult
# 99_advies.txt aan met TOP 3 aanbevelingen.
#
# INCLUSIEF: Evidence lines - citeert bronbestand + matchende regel
#
# Wordt aangeroepen door netwerk-diagnose-v3_5.ps1 in dezelfde map.
# =========================================================================

param(
    [Parameter(Mandatory = $true)]
    [string]$DiagnosticsPath,

    [string]$ClientName = ""
)

$ErrorActionPreference = "SilentlyContinue"

# Projectroot = een niveau boven src/
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $projectRoot -or $projectRoot -eq "") { $projectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }
if (-not $projectRoot -or $projectRoot -eq "") { $projectRoot = "E:\SluisICT" }

$patternsFile = Join-Path $PSScriptRoot "patterns.json"
$dataPath = Join-Path $projectRoot "Data"
$benchFile = Join-Path $dataPath "ai-benchmarks.json"

# Status iconen
$iOK = [char]0x2705
$iWarn = [char]0x26A0
$iFail = [char]0x274C

# =========================================================================
# HELPER: Lees bestand veilig
# =========================================================================

function Read-DiagFile {
    param([string]$FileName)
    $path = Join-Path $DiagnosticsPath $FileName
    if (Test-Path $path) {
        return (Get-Content -Path $path -Encoding UTF8 -Raw -ErrorAction SilentlyContinue)
    }
    return $null
}

function Read-DiagFileLines {
    param([string]$FileName)
    $path = Join-Path $DiagnosticsPath $FileName
    if (Test-Path $path) {
        return @(Get-Content -Path $path -Encoding UTF8 -ErrorAction SilentlyContinue)
    }
    return @()
}

# =========================================================================
# HELPER: Evidence verzamelen
# =========================================================================

function Find-Evidence {
    param(
        [string]$FileName,
        [string]$Pattern,
        [int]$MaxLines = 3
    )
    $evidence = @()
    $lines = Read-DiagFileLines -FileName $FileName
    $count = 0
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match $Pattern) {
            $evidence += @{
                File = $FileName
                Line = $i + 1
                Text = $lines[$i].Trim()
            }
            $count++
            if ($count -ge $MaxLines) { break }
        }
    }
    return $evidence
}

# =========================================================================
# LAAD PATTERNS
# =========================================================================

if (-not (Test-Path $patternsFile)) {
    Write-Host "    [i] AI: patterns.json niet gevonden ($patternsFile)" -ForegroundColor DarkGray
    return
}

try {
    $patternsData = Get-Content -Path $patternsFile -Raw -Encoding UTF8 | ConvertFrom-Json
}
catch {
    Write-Host "    [i] AI: patterns.json parse error: $($_.Exception.Message)" -ForegroundColor DarkGray
    return
}

$benchmarks = $patternsData.benchmarks
$patterns = $patternsData.patterns

# =========================================================================
# LAAD DIAGNOSTISCHE DATA
# =========================================================================

$diagFiles = @{}
$allFiles = Get-ChildItem -Path $DiagnosticsPath -Filter "*.txt" -ErrorAction SilentlyContinue
foreach ($f in $allFiles) {
    $diagFiles[$f.Name] = Read-DiagFile -FileName $f.Name
}

# JSON speedtest
$speedJson = $null
$speedJsonPath = Join-Path $DiagnosticsPath "11_speedtest_cli.json"
if (Test-Path $speedJsonPath) {
    try {
        $raw = Get-Content -Path $speedJsonPath -Raw -Encoding UTF8
        $lines = $raw -split "`r?`n"
        $jsonLine = $lines | Where-Object { $_ -match '^\s*\{"type":"result"' } | Select-Object -Last 1
        if (-not $jsonLine) { $jsonLine = $lines | Where-Object { $_ -match '^\s*\{.*"download".*\}\s*$' } | Select-Object -Last 1 }
        if ($jsonLine) { $speedJson = $jsonLine | ConvertFrom-Json }
    }
    catch { }
}

# =========================================================================
# ANALYSE ENGINE
# =========================================================================

$findings = @()

foreach ($pattern in $patterns) {
    $score = $pattern.scoring.base
    $evidences = @()
    $modifiers = @()

    # AND-logic: regex = bewijs vinden, overige = conditie moet kloppen
    $evidenceFound = $false
    $conditionExists = $false
    $conditionPassed = $false

    # Check triggers uit detectie config
    foreach ($trigger in $pattern.detection.triggers) {
        switch ($trigger.type) {
            "regex" {
                $fname = $trigger.file
                if ($diagFiles.ContainsKey($fname) -and $diagFiles[$fname]) {
                    $content = $diagFiles[$fname]
                    if ($content -match $trigger.pattern) {
                        $evidenceFound = $true
                        $ev = Find-Evidence -FileName $fname -Pattern $trigger.pattern
                        $evidences += $ev
                    }
                }
            }
            "count_private_hops" {
                $conditionExists = $true
                $tracert = $diagFiles["08_tracert_8.8.8.8.txt"]
                if ($tracert) {
                    $privateHops = 0
                    foreach ($line in ($tracert -split "`r?`n")) {
                        if ($line -match '(\d+\.\d+\.\d+\.\d+)') {
                            $ip = $Matches[1]
                            if ($ip -match '^10\.' -or $ip -match '^192\.168\.' -or $ip -match '^172\.(1[6-9]|2[0-9]|3[01])\.') {
                                $privateHops++
                                if ($privateHops -le 3) {
                                    $evidences += @{ File = "08_tracert_8.8.8.8.txt"; Line = 0; Text = $line.Trim() }
                                }
                            }
                        }
                    }
                    if ($privateHops -ge $trigger.min) { $conditionPassed = $true }
                }
            }
            "count_unique_dhcp" {
                $conditionExists = $true
                $ipconfig = $diagFiles["01_ipconfig_all.txt"]
                if ($ipconfig) {
                    $dhcpMatches = [regex]::Matches($ipconfig, "DHCP Server[\s.:]+(\d+\.\d+\.\d+\.\d+)")
                    $uniqueServers = @($dhcpMatches | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
                    if ($uniqueServers.Count -ge $trigger.min) {
                        $conditionPassed = $true
                        foreach ($m in $dhcpMatches) {
                            $evidences += @{ File = "01_ipconfig_all.txt"; Line = 0; Text = $m.Value.Trim() }
                        }
                    }
                }
            }
            "threshold_below" {
                $conditionExists = $true
                switch ($trigger.field) {
                    "signal_percent" {
                        $wifi = $diagFiles["09_wifi_netsh_interfaces.txt"]
                        if ($wifi -and $wifi -match "Signal\s*:\s*(\d+)%") {
                            if ([int]$Matches[1] -lt $trigger.value) { $conditionPassed = $true }
                        }
                    }
                    "download_mbps" {
                        if ($speedJson -and $speedJson.download) {
                            $dl = [math]::Round(($speedJson.download.bandwidth * 8) / 1000000, 2)
                            if ($dl -lt $trigger.value) { $conditionPassed = $true }
                        }
                    }
                    "optimal_mtu" {
                        $mtu = $diagFiles["14_mtu_test.txt"]
                        if ($mtu -and $mtu -match "Optimale MTU:\s*(\d+)") {
                            if ([int]$Matches[1] -lt $trigger.value) { $conditionPassed = $true }
                        }
                    }
                }
            }
            "threshold_above" {
                $conditionExists = $true
                switch ($trigger.field) {
                    "loss_percent" {
                        foreach ($fname in @("06_ping_gateway.txt", "07_ping_8.8.8.8.txt")) {
                            $ping = $diagFiles[$fname]
                            if ($ping -and $ping -match "\((\d+)%\s*(?:loss|verlies)\)") {
                                if ([int]$Matches[1] -gt $trigger.value) {
                                    $conditionPassed = $true
                                    $ev = Find-Evidence -FileName $fname -Pattern "\((\d+)%\s*(?:loss|verlies)\)"
                                    $evidences += $ev
                                }
                            }
                        }
                    }
                    "average_latency" {
                        $ping = $diagFiles["07_ping_8.8.8.8.txt"]
                        if ($ping -and $ping -match "(?:Average|gemiddeld)\s*=\s*(\d+)ms") {
                            if ([int]$Matches[1] -gt $trigger.value) {
                                $conditionPassed = $true
                                $ev = Find-Evidence -FileName "07_ping_8.8.8.8.txt" -Pattern "(?:Average|gemiddeld)\s*=\s*(\d+)ms"
                                $evidences += $ev
                            }
                        }
                    }
                    "configured_dns_avg_ms" {
                        $dns = $diagFiles["13_dns_performance.txt"]
                        if ($dns -and $dns -match "\[GECONFIGUREERD\]") {
                            foreach ($line in ($dns -split "`r?`n")) {
                                if ($line -match "\[GECONFIGUREERD\]" -and $line -match "(\d+)ms") {
                                    if ([int]$Matches[1] -gt $trigger.value) {
                                        $conditionPassed = $true
                                        $evidences += @{ File = "13_dns_performance.txt"; Line = 0; Text = $line.Trim() }
                                    }
                                }
                            }
                        }
                    }
                    "jitter_ms" {
                        $jitter = $diagFiles["18_jitter_analysis.txt"]
                        if ($jitter -and $jitter -match "Gemiddeld:\s*([\d.]+)ms") {
                            if ([double]$Matches[1] -gt $trigger.value) {
                                $conditionPassed = $true
                                $ev = Find-Evidence -FileName "18_jitter_analysis.txt" -Pattern "Gemiddeld:\s*[\d.]+ms"
                                $evidences += $ev
                            }
                        }
                    }
                }
            }
            "channel_range" {
                $conditionExists = $true
                $wifi = $diagFiles["09_wifi_netsh_interfaces.txt"]
                if ($wifi -and $wifi -match "Channel\s*:\s*(\d+)") {
                    $ch = [int]$Matches[1]
                    if ($ch -ge $trigger.min -and $ch -le $trigger.max) {
                        $conditionPassed = $true
                        $ev = Find-Evidence -FileName "09_wifi_netsh_interfaces.txt" -Pattern "Channel\s*:\s*\d+"
                        $evidences += $ev
                    }
                }
            }
            "count_same_channel" {
                $conditionExists = $true
                $env = $diagFiles["15_wifi_environment.txt"]
                if ($env) {
                    # Tel netwerken op hetzelfde kanaal als het eigen kanaal
                    $wifi = $diagFiles["09_wifi_netsh_interfaces.txt"]
                    $ownCh = 0
                    if ($wifi -and $wifi -match "Channel\s*:\s*(\d+)") { $ownCh = [int]$Matches[1] }
                    if ($ownCh -gt 0) {
                        $sameChCount = ([regex]::Matches($env, "Kanaal:\s*$ownCh\s")).Count
                        if ($sameChCount -ge $trigger.min) {
                            $conditionPassed = $true
                            $evidences += @{ File = "15_wifi_environment.txt"; Line = 0; Text = "$sameChCount netwerken op kanaal $ownCh" }
                        }
                    }
                }
            }
            "count_failed_services" {
                $conditionExists = $true
                $svc = $diagFiles["16_service_reachability.txt"]
                if ($svc) {
                    $failCount = ([regex]::Matches($svc, [regex]::Escape([char]0x274C))).Count
                    if ($failCount -lt 1) { $failCount = ([regex]::Matches($svc, "FAILED|Onbereikbaar|False")).Count }
                    if ($failCount -ge $trigger.min) {
                        $conditionPassed = $true
                        $ev = Find-Evidence -FileName "16_service_reachability.txt" -Pattern "($([regex]::Escape([char]0x274C))|FAILED|False)"
                        $evidences += $ev
                    }
                }
            }
        }
    }

    # AND-logic: bewijs moet gevonden zijn EN conditie moet kloppen
    $triggered = $false
    if ($conditionExists) {
        $triggered = $evidenceFound -and $conditionPassed
    }
    else {
        $triggered = $evidenceFound
    }

    if ($triggered) {
        # Score modifiers
        foreach ($mod in $pattern.scoring.modifiers) {
            $applied = $false
            switch ($mod.condition) {
                "different_subnets" { $applied = $true }
                "multiple_gateways" { $applied = $false }
                "dhcp_different_subnet" { $applied = $false }
                "signal_below_30" {
                    $wifi = $diagFiles["09_wifi_netsh_interfaces.txt"]
                    if ($wifi -and $wifi -match "Signal\s*:\s*(\d+)%" -and [int]$Matches[1] -lt 30) { $applied = $true }
                }
                "high_packet_loss" {
                    foreach ($f in @("06_ping_gateway.txt", "07_ping_8.8.8.8.txt")) {
                        if ($diagFiles[$f] -and $diagFiles[$f] -match "\((\d+)%\s*(?:loss|verlies)\)" -and [int]$Matches[1] -gt 5) { $applied = $true }
                    }
                }
                "speed_below_50mbps" {
                    if ($speedJson -and $speedJson.download) {
                        $dl = [math]::Round(($speedJson.download.bandwidth * 8) / 1000000, 2)
                        if ($dl -lt 50) { $applied = $true }
                    }
                }
                "gateway_loss_above_5" {
                    $gw = $diagFiles["06_ping_gateway.txt"]
                    if ($gw -and $gw -match "\((\d+)%\s*(?:loss|verlies)\)" -and [int]$Matches[1] -gt 5) { $applied = $true }
                }
                "internet_loss_above_10" {
                    $inet = $diagFiles["07_ping_8.8.8.8.txt"]
                    if ($inet -and $inet -match "\((\d+)%\s*(?:loss|verlies)\)" -and [int]$Matches[1] -gt 10) { $applied = $true }
                }
                "wifi_connected" {
                    $wifi = $diagFiles["09_wifi_netsh_interfaces.txt"]
                    if ($wifi -and $wifi -match "State\s*:\s*connected|Status\s*:\s*Verbonden") { $applied = $true }
                }
                "latency_above_200" {
                    $p = $diagFiles["07_ping_8.8.8.8.txt"]
                    if ($p -and $p -match "(?:Average|gemiddeld)\s*=\s*(\d+)ms" -and [int]$Matches[1] -gt 200) { $applied = $true }
                }
                "download_below_10" {
                    if ($speedJson -and $speedJson.download) {
                        $dl = [math]::Round(($speedJson.download.bandwidth * 8) / 1000000, 2)
                        if ($dl -lt 10) { $applied = $true }
                    }
                }
                "jitter_above_50" {
                    $j = $diagFiles["18_jitter_analysis.txt"]
                    if ($j -and $j -match "Gemiddeld:\s*([\d.]+)ms" -and [double]$Matches[1] -gt 50) { $applied = $true }
                }
                "gateway_jitter_high" {
                    $j = $diagFiles["18_jitter_analysis.txt"]
                    if ($j -and $j -match "Gateway Jitter:[\s\S]*?Gemiddeld:\s*([\d.]+)ms" -and [double]$Matches[1] -gt 30) { $applied = $true }
                }
                "dns_above_200" {
                    $d = $diagFiles["13_dns_performance.txt"]
                    if ($d -and $d -match "\[GECONFIGUREERD\]") {
                        foreach ($line in ($d -split "`r?`n")) {
                            if ($line -match "\[GECONFIGUREERD\]" -and $line -match "(\d+)ms" -and [int]$Matches[1] -gt 200) { $applied = $true }
                        }
                    }
                }
                "mtu_below_1300" {
                    $m = $diagFiles["14_mtu_test.txt"]
                    if ($m -and $m -match "Optimale MTU:\s*(\d+)" -and [int]$Matches[1] -lt 1300) { $applied = $true }
                }
                "all_services_blocked" {
                    $s = $diagFiles["16_service_reachability.txt"]
                    if ($s) {
                        $okCount = ([regex]::Matches($s, [regex]::Escape([char]0x2705))).Count
                        if ($okCount -eq 0) { $applied = $true }
                    }
                }
                default { }
            }
            if ($applied) {
                $score += $mod.add
                $modifiers += $mod.condition
            }
        }

        $findings += @{
            Pattern   = $pattern
            Score     = [math]::Min($score, 100)
            Evidence  = $evidences
            Modifiers = $modifiers
        }
    }
}

# Sorteer op score (hoog naar laag)
$findings = $findings | Sort-Object { $_.Score } -Descending

# =========================================================================
# GENEREER RAPPORT: 98_ai_analyse.txt
# =========================================================================

$report = @()
$report += "================================================================="
$report += "SluisICT - AI ANALYSE RAPPORT"
$report += "================================================================="
$report += "Datum:     $(Get-Date -Format 'dd-MM-yyyy HH:mm')"
$report += "Engine:    Rule-based v3.5 ($(($patterns).Count) patronen)"
$report += "Bronmap:   $DiagnosticsPath"
if ($ClientName) { $report += "Klant:     $ClientName" }
$report += ""

if ($findings.Count -eq 0) {
    $report += "$iOK Geen bekende problemen gedetecteerd."
    $report += ""
    $report += "Alle gecontroleerde patronen vallen binnen normale waardes."
}
else {
    $report += "Gevonden: $($findings.Count) patroon(en)"
    $report += ""

    $nr = 0
    foreach ($finding in $findings) {
        $nr++
        $p = $finding.Pattern
        $icon = if ($finding.Score -ge 70) { $iFail } elseif ($finding.Score -ge 40) { $iWarn } else { $iOK }

        $report += "-----------------------------------------------------------------"
        $report += "$icon BEVINDING ${nr}: $($p.title)"
        $report += "-----------------------------------------------------------------"
        $report += "Score:       $($finding.Score)/100"
        $report += "Ernst:       $(if ($finding.Score -ge 70) { 'HOOG' } elseif ($finding.Score -ge 40) { 'MIDDEL' } else { 'LAAG' })"
        $report += "Omschrijving: $($p.description)"
        $report += ""

        # EVIDENCE LINES
        if ($finding.Evidence.Count -gt 0) {
            $report += "BEWIJS:"
            $shown = @{}
            foreach ($ev in $finding.Evidence) {
                $key = "$($ev.File):$($ev.Text)"
                if (-not $shown.ContainsKey($key)) {
                    $shown[$key] = $true
                    $lineRef = if ($ev.Line -gt 0) { " (regel $($ev.Line))" } else { "" }
                    $report += "  Bron: $($ev.File)$lineRef"
                    $report += "  Regel: `"$($ev.Text)`""
                    $report += ""
                }
            }
        }

        $report += "AANBEVOLEN ACTIES:"
        $stepNr = 0
        foreach ($action in $p.actions) {
            $stepNr++
            $report += "  $stepNr. $action"
        }
        $report += "Moeilijkheid: $($p.difficulty)"
        $report += ""
    }
}

# Benchmark vergelijking
$report += "-----------------------------------------------------------------"
$report += "NL MARKT REFERENTIE"
$report += "-----------------------------------------------------------------"
$report += "Download: uitstekend >$($benchmarks.download_excellent) Mbps | goed >$($benchmarks.download_good) Mbps | minimum $($benchmarks.download_minimum) Mbps"
$report += "Upload:   uitstekend >$($benchmarks.upload_excellent) Mbps | goed >$($benchmarks.upload_good) Mbps | minimum $($benchmarks.upload_minimum) Mbps"
$report += "Latency:  uitstekend <$($benchmarks.latency_excellent)ms | goed <$($benchmarks.latency_good)ms | slecht >$($benchmarks.latency_poor)ms"
$report += "Jitter:   uitstekend <$($benchmarks.jitter_excellent)ms | goed <$($benchmarks.jitter_good)ms | slecht >$($benchmarks.jitter_poor)ms"
$report += "WiFi:     goed >$($benchmarks.wifi_signal_good)% | redelijk >$($benchmarks.wifi_signal_fair)% | slecht <$($benchmarks.wifi_signal_poor)%"
$report += ""

$reportPath = Join-Path $DiagnosticsPath "98_ai_analyse.txt"
$report | Out-File -FilePath $reportPath -Encoding UTF8

# =========================================================================
# APPEND TOP 3 TO ADVIES (99_advies.txt)
# =========================================================================

$adviesPath = Join-Path $DiagnosticsPath "99_advies.txt"
if ((Test-Path $adviesPath) -and $findings.Count -gt 0) {
    $append = @()
    $append += ""
    $append += "================================================================="
    $append += "AI ANALYSE: TOP 3 BEVINDINGEN"
    $append += "================================================================="
    $append += ""

    $topN = [math]::Min(3, $findings.Count)
    for ($i = 0; $i -lt $topN; $i++) {
        $f = $findings[$i]
        $p = $f.Pattern
        $icon = if ($f.Score -ge 70) { $iFail } elseif ($f.Score -ge 40) { $iWarn } else { $iOK }

        $append += "$icon $($p.title) (score: $($f.Score)/100)"

        # Evidence summary
        if ($f.Evidence.Count -gt 0) {
            $firstEv = $f.Evidence | Select-Object -First 1
            $append += "   Bewijs: $($firstEv.File) -> `"$($firstEv.Text)`""
        }

        $stepNr = 0
        foreach ($action in $p.actions) {
            $stepNr++
            $append += "   $stepNr. $action"
        }
        $append += "   Moeilijkheid: $($p.difficulty)"
        $append += ""
    }

    $append | Out-File -FilePath $adviesPath -Encoding UTF8 -Append
}

# =========================================================================
# KLANT HISTORIE
# =========================================================================

if ($ClientName) {
    try {
        $safeName = $ClientName -replace '[^\w\-]', '_'
        $clientDir = Join-Path $dataPath "klanten\$safeName"
        if (!(Test-Path $clientDir)) { New-Item -ItemType Directory -Path $clientDir -Force | Out-Null }

        $histFile = Join-Path $clientDir "history.csv"

        # Maak header als bestand nog niet bestaat
        if (!(Test-Path $histFile)) {
            "Datum,Modus,Findings,TopIssue,Score,DownloadMbps,UploadMbps,Gateway,PacketLoss" |
            Out-File -FilePath $histFile -Encoding UTF8
        }

        # Haal data op
        $topIssue = if ($findings.Count -gt 0) { $findings[0].Pattern.id } else { "geen" }
        $topScore = if ($findings.Count -gt 0) { $findings[0].Score } else { 0 }
        $dlMbps = 0; $ulMbps = 0
        if ($speedJson -and $speedJson.download) {
            $dlMbps = [math]::Round(($speedJson.download.bandwidth * 8) / 1000000, 2)
            $ulMbps = [math]::Round(($speedJson.upload.bandwidth * 8) / 1000000, 2)
        }
        $gwPingFile = Read-DiagFile -FileName "06_ping_gateway.txt"
        $gwIP = "onbekend"
        $gwLoss = "N/A"
        if ($gwPingFile -and $gwPingFile -match "Pinging\s+([\d.]+)") { $gwIP = $Matches[1] }
        if ($gwPingFile -and $gwPingFile -match "\((\d+)%\s*(?:loss|verlies)\)") { $gwLoss = "$($Matches[1])%" }

        $mode = if ($DiagnosticsPath -match "Full|FULL") { "Full" } else { "Quick" }
        $histLine = "$(Get-Date -Format 'yyyy-MM-dd HH:mm'),$mode,$($findings.Count),$topIssue,$topScore,$dlMbps,$ulMbps,$gwIP,$gwLoss"
        $histLine | Out-File -FilePath $histFile -Encoding UTF8 -Append

        # Trend analyse (als minstens 2 metingen)
        $histLines = @(Get-Content -Path $histFile -Encoding UTF8 | Select-Object -Skip 1 | Where-Object { $_ })
        if ($histLines.Count -ge 2) {
            $trendPath = Join-Path $clientDir "trend.txt"
            $trend = @(
                "================================================================="
                "KLANT TREND: $ClientName"
                "================================================================="
                "Totaal metingen: $($histLines.Count)"
                ""
            )
            foreach ($hl in $histLines | Select-Object -Last 5) {
                $parts = $hl -split ","
                if ($parts.Count -ge 5) {
                    $trend += "$($parts[0]) | $($parts[1]) | Issues: $($parts[2]) | Top: $($parts[3]) (score $($parts[4]))"
                }
            }
            $trend | Out-File -FilePath $trendPath -Encoding UTF8
        }
    }
    catch {
        Write-Host "    [i] AI: Klanthistorie fout: $($_.Exception.Message)" -ForegroundColor DarkGray
    }
}

Write-Host "    -> AI analyse: $($findings.Count) bevinding(en)" -ForegroundColor $(if ($findings.Count -eq 0) { "Green" } else { "Yellow" })
