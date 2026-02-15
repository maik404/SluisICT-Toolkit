# =========================================================================
# SluisICT - Netwerk Diagnose Toolkit v3.5 - Advanced Suite
# =========================================================================
# Professionele Windows netwerk-diagnose tool voor veldwerk
# Quick mode (default): 60-90 sec - basis diagnose
# Full mode (-Full):    3-8 min   - diepgaande analyse
#
# READ-ONLY: dit script wijzigt NOOIT netwerkinstellingen, adapters,
# DNS, registry of andere systeemconfiguratie.
#
# GEBRUIK:
#   .\netwerk-diagnose-v3_5.ps1                  (Quick)
#   .\netwerk-diagnose-v3_5.ps1 -Full            (Full)
#   .\netwerk-diagnose-v3_5.ps1 -NoSpeedtest     (Quick zonder speed)
#   .\netwerk-diagnose-v3_5.ps1 -Full -ClientName "Jansen"
# =========================================================================

param(
    [switch]$Full,
    [switch]$NoSpeedtest,
    [string]$ClientName = ""
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

# =========================================================================
# CONFIGURATIE
# =========================================================================

$scriptRoot = Split-Path -Parent $PSScriptRoot
if (-not $scriptRoot -or $scriptRoot -eq "") { $scriptRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }
if (-not $scriptRoot -or $scriptRoot -eq "") { $scriptRoot = "E:\SluisICT" }

$base = Join-Path $scriptRoot "output"
$tools = Join-Path $scriptRoot "Tools\Portable"
$speedtestExe = Join-Path $tools "SpeedtestCLI\speedtest.exe"
$dataPath = Join-Path $scriptRoot "Data"

if (!(Test-Path $base)) { New-Item -ItemType Directory -Path $base | Out-Null }

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$outDir = Join-Path $base $timestamp
New-Item -ItemType Directory -Path $outDir | Out-Null

# Mode en stappen
$modeName = if ($Full) { "FULL" } else { "QUICK" }
$totalSteps = if ($Full) { 12 } else { 7 }
$script:step = 0

# Ping counts
$gwPingCount = if ($Full) { 20 } else { 10 }
$inetPingCount = if ($Full) { 30 } else { 20 }
$tracertHops = if ($Full) { 15 } else { 5 }

# Status iconen (veilig voor elke PS1 encoding, output wordt UTF-8)
$iOK = [char]0x2705   # groene check
$iWarn = [char]0x26A0   # waarschuwing driehoek
$iFail = [char]0x274C   # rood kruis

# =========================================================================
# GLOBALE VARIABELEN
# =========================================================================

$Global:AnalysisResults = @{
    Issues       = [System.Collections.Generic.List[string]]::new()
    Warnings     = [System.Collections.Generic.List[string]]::new()
    Infos        = [System.Collections.Generic.List[string]]::new()
    Observations = [System.Collections.Generic.List[string]]::new()
    NextSteps    = [System.Collections.Generic.List[string]]::new()
    AdviceItems  = [System.Collections.ArrayList]::new()
}

# =========================================================================
# HELPER FUNCTIES
# =========================================================================

function Show-Step($desc) {
    $script:step++
    Write-Host "[$($script:step)/$totalSteps] $desc..." -ForegroundColor Yellow
}

function OutFile($name, $content) {
    $path = Join-Path $outDir $name
    $content | Out-File -FilePath $path -Encoding UTF8
}

function AddLine($path, $line) {
    $line | Out-File -FilePath $path -Encoding UTF8 -Append
}

function Add-Warning($msg) { $Global:AnalysisResults.Warnings.Add($msg) }
function Add-Issue($msg) { $Global:AnalysisResults.Issues.Add($msg) }
function Add-Info($msg) { $Global:AnalysisResults.Infos.Add($msg) }
function Add-Observation($msg) { $Global:AnalysisResults.Observations.Add($msg) }
function Add-NextStep($msg) { $Global:AnalysisResults.NextSteps.Add($msg) }

function Add-AdviceItem {
    param([string]$Problem, [string]$Cause, [string[]]$Steps, [string]$Effort)
    $Global:AnalysisResults.AdviceItems.Add(@{
            Problem = $Problem; Cause = $Cause; Steps = $Steps; Effort = $Effort
        }) | Out-Null
}

function Get-NetshValue($text, $key) {
    $line = ($text -split "`r?`n" | Where-Object { $_ -match "^\s*$key\s*:" } | Select-Object -First 1)
    if ($line) { return (($line -replace ".*:\s*", "").Trim()) }
    return ""
}

function Is-PrivateIP($ip) {
    return ($ip -match '^10\.' -or $ip -match '^192\.168\.' -or
        $ip -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.')
}

function Is-CGNAT($ip) {
    return ($ip -match '^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.')
}

# =========================================================================
# MODULE: ADAPTER CLASSIFICATIE
# =========================================================================

function Classify-NetworkAdapters {
    $result = @{ Physical = @(); Virtual = @(); VPN = @() }

    $virtualPatterns = @(
        "Hyper-V", "vEthernet", "WSL", "VMware", "VirtualBox",
        "Npcap", "Loopback", "Docker", "Virtual Adapter"
    )
    $vpnPatterns = @(
        "WireGuard", "OpenVPN", "AnyConnect", "NordVPN", "NordLynx",
        "Surfshark", "Proton", "Cisco", "Fortinet", "SonicWall",
        "GlobalProtect", "FortiClient", "TAP-Windows", "Windscribe"
    )

    $allAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    $netIPConfigs = Get-NetIPConfiguration

    foreach ($adapter in $allAdapters) {
        $name = $adapter.Name
        $desc = $adapter.InterfaceDescription
        $pnp = $adapter.PnpDeviceId
        $hw = $adapter.HardwareInterface

        $type = "Fysiek"
        $reason = ""

        # Methode 1: HardwareInterface property (meest betrouwbaar)
        if ($null -ne $hw -and $hw -eq $false) {
            $type = "Virtueel"; $reason = "HardwareInterface=false"
        }

        # Methode 2: PnpDeviceId (ROOT\ = virtual, PCI\ = physical)
        if ($type -eq "Fysiek" -and $pnp -and $pnp -match "^ROOT\\") {
            $type = "Virtueel"; $reason = "PnP: ROOT device"
        }

        # Methode 3: Naam/beschrijving patroonherkenning
        if ($type -eq "Fysiek") {
            foreach ($pattern in $virtualPatterns) {
                if ($name -match [regex]::Escape($pattern) -or $desc -match [regex]::Escape($pattern)) {
                    $type = "Virtueel"; $reason = "Patroon: $pattern"; break
                }
            }
        }

        # VPN check (overschrijft virtueel)
        foreach ($pattern in $vpnPatterns) {
            if ($name -match [regex]::Escape($pattern) -or $desc -match [regex]::Escape($pattern)) {
                $type = "VPN"; $reason = "VPN: $pattern"; break
            }
        }

        # Docker subnet heuristiek
        if ($type -eq "Fysiek") {
            $ipCfg = $netIPConfigs | Where-Object { $_.InterfaceIndex -eq $adapter.InterfaceIndex }
            if ($ipCfg -and $ipCfg.IPv4Address) {
                foreach ($ip in $ipCfg.IPv4Address) {
                    if ($ip.IPAddress -match '^172\.(1[7-9]|2[0-9]|3[0-1])\.') {
                        $type = "Virtueel"; $reason = "Docker subnet ($($ip.IPAddress))"; break
                    }
                }
            }
        }

        # Verzamel IP en gateway info
        $ipCfg = $netIPConfigs | Where-Object { $_.InterfaceIndex -eq $adapter.InterfaceIndex }
        $ips = @()
        $gw = ""
        $dhcp = ""
        if ($ipCfg) {
            $ips = @($ipCfg.IPv4Address | Select-Object -ExpandProperty IPAddress -ErrorAction SilentlyContinue)
            $gw = ($ipCfg.IPv4DefaultGateway | Select-Object -ExpandProperty NextHop -ErrorAction SilentlyContinue)
            $dhcp = if ($ipCfg.NetIPv4Interface.Dhcp -eq "Enabled") { "Ja" } else { "Nee" }
        }

        $info = @{
            Name = $name; Description = $desc; IPs = $ips; Gateway = $gw
            PnpDevice = $pnp; Reason = $reason; Type = $type; DHCP = $dhcp
        }

        switch ($type) {
            "VPN" { $result.VPN += $info }
            "Virtueel" { $result.Virtual += $info }
            default { $result.Physical += $info }
        }
    }

    return $result
}

# =========================================================================
# MODULE: PING PARSING
# =========================================================================

function Parse-PingResults {
    param([string]$PingOutput, [string]$Target)

    $r = @{
        Target = $Target; Sent = 0; Received = 0; Lost = 0; LostPercent = 0
        MinLatency = 0; MaxLatency = 0; AvgLatency = 0; Success = $false
    }

    if ($PingOutput -match "Packets: Sent = (\d+), Received = (\d+), Lost = (\d+)") {
        $r.Sent = [int]$Matches[1]; $r.Received = [int]$Matches[2]; $r.Lost = [int]$Matches[3]
        if ($r.Sent -gt 0) { $r.LostPercent = [math]::Round(($r.Lost / $r.Sent) * 100, 1) }
    }
    # NL locale
    if ($PingOutput -match "Pakketten: verzonden = (\d+), ontvangen = (\d+), verloren = (\d+)") {
        $r.Sent = [int]$Matches[1]; $r.Received = [int]$Matches[2]; $r.Lost = [int]$Matches[3]
        if ($r.Sent -gt 0) { $r.LostPercent = [math]::Round(($r.Lost / $r.Sent) * 100, 1) }
    }

    if ($PingOutput -match "Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms") {
        $r.MinLatency = [int]$Matches[1]; $r.MaxLatency = [int]$Matches[2]
        $r.AvgLatency = [int]$Matches[3]; $r.Success = $true
    }
    elseif ($PingOutput -match "minimum = (\d+)ms, maximum = (\d+)ms, gemiddeld = (\d+)ms") {
        $r.MinLatency = [int]$Matches[1]; $r.MaxLatency = [int]$Matches[2]
        $r.AvgLatency = [int]$Matches[3]; $r.Success = $true
    }

    return $r
}

# =========================================================================
# MODULE: JITTER ANALYSE
# =========================================================================

function Analyze-PingJitter {
    param([string]$PingOutput, [string]$Target)

    $r = @{ Target = $Target; Jitter = -1; MaxJitter = 0; StdDev = 0; Samples = 0; Quality = "ONBEKEND" }

    $latencies = @()
    foreach ($m in [regex]::Matches($PingOutput, "(?:time[=<])(\d+)ms")) {
        $latencies += [int]$m.Groups[1].Value
    }
    # NL locale
    if ($latencies.Count -lt 3) {
        foreach ($m in [regex]::Matches($PingOutput, "(?:tijd[=<])(\d+)ms")) {
            $latencies += [int]$m.Groups[1].Value
        }
    }

    if ($latencies.Count -lt 3) { return $r }
    $r.Samples = $latencies.Count

    # Jitter = gemiddelde absolute delta tussen opeenvolgende pings
    $diffs = @()
    for ($i = 1; $i -lt $latencies.Count; $i++) {
        $diffs += [math]::Abs($latencies[$i] - $latencies[$i - 1])
    }
    $r.Jitter = [math]::Round(($diffs | Measure-Object -Average).Average, 1)
    $r.MaxJitter = ($diffs | Measure-Object -Maximum).Maximum

    # Standaarddeviatie
    $avg = ($latencies | Measure-Object -Average).Average
    $sumSqDiff = 0
    foreach ($lat in $latencies) { $sumSqDiff += [math]::Pow($lat - $avg, 2) }
    $r.StdDev = [math]::Round([math]::Sqrt($sumSqDiff / ($latencies.Count - 1)), 1)

    # Kwaliteit
    if ($r.Jitter -le 5) { $r.Quality = "UITSTEKEND" }
    elseif ($r.Jitter -le 15) { $r.Quality = "GOED" }
    elseif ($r.Jitter -le 30) { $r.Quality = "MATIG" }
    else { $r.Quality = "SLECHT" }

    return $r
}

# =========================================================================
# MODULE: NAT DETECTIE (EVIDENCE-BASED)
# =========================================================================

function Detect-NATEvidence {
    param(
        [array]$PhysicalGateways,
        [string]$TracertOutput,
        [array]$VirtualSubnets
    )

    $evidence = @{
        DoubleNAT = $false; CGNAT = $false; Confidence = 0
        PrivateHops = @(); CGNATHops = @(); Details = ""
    }

    # Parse traceroute hops
    $hops = @()
    foreach ($line in ($TracertOutput -split "`r?`n")) {
        if ($line -match '^\s*(\d+)\s' -and $line -match '(\d+\.\d+\.\d+\.\d+)') {
            $hopNum = [int]([regex]::Match($line, '^\s*(\d+)')).Groups[1].Value
            $hopIP = ([regex]::Matches($line, '(\d+\.\d+\.\d+\.\d+)') | Select-Object -Last 1).Value
            $hops += @{ Hop = $hopNum; IP = $hopIP }
        }
    }

    # Filter: verwijder hops in virtuele adapter subnets
    $filteredHops = @()
    foreach ($hop in $hops) {
        $isVirtual = $false
        if ($hop.IP -match '^(\d+\.\d+\.\d+)\.') {
            $hopSubnet = $Matches[1]
            if ($VirtualSubnets -contains $hopSubnet) { $isVirtual = $true }
        }
        if (-not $isVirtual) { $filteredHops += $hop }
    }

    # Tel private en CGNAT hops
    foreach ($hop in $filteredHops) {
        if (Is-PrivateIP $hop.IP) { $evidence.PrivateHops += $hop }
        if (Is-CGNAT $hop.IP) { $evidence.CGNATHops += $hop }
    }

    # Beoordeling
    if ($evidence.PrivateHops.Count -ge 2) {
        $evidence.DoubleNAT = $true
        $evidence.Confidence = 60

        $subnets = @()
        foreach ($hop in $evidence.PrivateHops) {
            if ($hop.IP -match '^(\d+\.\d+\.\d+)\.') { $subnets += $Matches[1] }
        }
        if (($subnets | Sort-Object -Unique).Count -ge 2) { $evidence.Confidence += 25 }
        if ($PhysicalGateways.Count -ge 2) { $evidence.Confidence += 15 }

        $hopIPs = ($evidence.PrivateHops | ForEach-Object { $_.IP }) -join " -> "
        $evidence.Details = "Dubbele NAT: $hopIPs (confidence $($evidence.Confidence)%)"

        Add-Issue("Dubbele NAT gedetecteerd via traceroute: $hopIPs")
        Add-AdviceItem -Problem "Dubbele NAT (router-op-router)" `
            -Cause "ISP modem staat in router mode + eigen router erachter" `
            -Steps @(
            "Check of er 2 apparaten met NAT draaien (ISP modem + eigen router)",
            "Zet ISP modem in bridge mode, OF eigen router in access point mode",
            "Test of gaming/port forwarding daarna werkt"
        ) -Effort "middel"
        Add-NextStep("Dubbele NAT oplossen: ISP modem in bridge of router in AP mode")
    }
    elseif ($evidence.PrivateHops.Count -eq 1 -and $PhysicalGateways.Count -ge 2) {
        Add-Warning("Mogelijk dubbele NAT: meerdere gateways maar traceroute toont 1 private hop")
    }

    if ($evidence.CGNATHops.Count -gt 0) {
        $evidence.CGNAT = $true
        $cgnatIP = $evidence.CGNATHops[0].IP
        Add-Info("CGNAT actief ($cgnatIP) - alleen relevant bij port forwarding/gaming")
        Add-Observation("CGNAT betekent dat uw provider een extra NAT-laag toevoegt. Port forwarding werkt mogelijk niet.")
    }

    return $evidence
}

# =========================================================================
# MODULE: GATEWAY / SUBNET / DHCP ANALYSE
# =========================================================================

function Analyze-GatewayAndSubnets {
    param(
        [array]$PhysicalGateways,
        [array]$DnsServers,
        [array]$DhcpServers,
        [object]$AdapterClassification
    )

    # Gateway
    if ($PhysicalGateways.Count -gt 1) {
        Add-Warning("Meerdere fysieke gateways: $($PhysicalGateways -join ', ')")
        $subnets = @()
        foreach ($gw in $PhysicalGateways) {
            if ($gw -match '^(\d+\.\d+\.\d+)\.') { $subnets += $Matches[1] }
        }
        if (($subnets | Sort-Object -Unique).Count -gt 1) {
            Add-Issue("Meerdere gateways in VERSCHILLENDE subnets: $($PhysicalGateways -join ', ')")
            Add-AdviceItem -Problem "Meerdere gateways in verschillende subnets" `
                -Cause "Mogelijk meerdere routers of netwerkkoppeling" `
                -Steps @("Controleer welke router als primair moet dienen", "Schakel routing uit op extra apparaten") `
                -Effort "middel"
        }
    }
    elseif ($PhysicalGateways.Count -eq 0) {
        Add-Issue("Geen default gateway gevonden op fysieke adapters")
        Add-NextStep("Check netwerkkabel of WiFi verbinding")
    }

    # Dubbele DHCP server detectie
    $uniqueDhcp = @($DhcpServers | Sort-Object -Unique)
    if ($uniqueDhcp.Count -gt 1) {
        Add-Issue("Meerdere DHCP servers gedetecteerd: $($uniqueDhcp -join ', ')")
        Add-AdviceItem -Problem "Dubbele DHCP ($($uniqueDhcp -join ' + '))" `
            -Cause "Er draaien 2 apparaten die IP-adressen uitdelen op hetzelfde netwerk" `
            -Steps @(
            "Controleer of ISP modem EN eigen router beide DHCP aan hebben staan",
            "Schakel DHCP uit op 1 van de 2 (meestal op de eigen router als die in AP-mode gaat)",
            "Herstart alle apparaten na wijziging"
        ) -Effort "laag"
        Add-NextStep("Dubbele DHCP uitschakelen op 1 van de 2 apparaten")
    }

    # DNS
    if ($DnsServers.Count -gt 4) {
        Add-Observation("Veel DNS servers: $($DnsServers -join ', ')")
    }

    # Adapter notificaties
    if ($AdapterClassification.Virtual.Count -gt 0) {
        $names = ($AdapterClassification.Virtual | ForEach-Object { $_.Name }) -join ", "
        Add-Observation("Virtuele adapters (genegeerd): $names")
    }
    if ($AdapterClassification.VPN.Count -gt 0) {
        $names = ($AdapterClassification.VPN | ForEach-Object { $_.Name }) -join ", "
        Add-Observation("VPN adapter(s): $names")
    }
}

# =========================================================================
# MODULE: LATENCY / PACKET LOSS
# =========================================================================

function Analyze-LatencyAndPacketLoss {
    param([hashtable]$GatewayPing, [hashtable]$InternetPing)

    if ($GatewayPing.Success) {
        if ($GatewayPing.LostPercent -gt 5) {
            Add-Issue("Gateway packet loss: $($GatewayPing.LostPercent)%")
            Add-AdviceItem -Problem "Hoog pakketverlies naar router ($($GatewayPing.LostPercent)%)" `
                -Cause "WiFi instabiliteit, slechte kabel, of overbelaste router" `
                -Steps @("Test met netwerkkabel ipv WiFi", "Vervang netwerkkabel", "Herstart router") `
                -Effort "laag"
            Add-NextStep("Test bekabeld om WiFi als oorzaak uit te sluiten")
        }
        if ($GatewayPing.AvgLatency -gt 10) {
            Add-Warning("Gateway latency hoog: $($GatewayPing.AvgLatency)ms (normaal <5ms)")
        }
        if ($GatewayPing.MaxLatency -gt 50) {
            Add-Warning("Gateway latency spikes: max $($GatewayPing.MaxLatency)ms")
        }
    }
    else {
        Add-Issue("Gateway niet bereikbaar")
        Add-NextStep("Controleer netwerkkabel en router")
    }

    if ($InternetPing.Success) {
        if ($InternetPing.LostPercent -gt 5) {
            Add-Issue("Internet packet loss: $($InternetPing.LostPercent)%")
            if ($GatewayPing.Success -and $GatewayPing.LostPercent -lt 2) {
                Add-AdviceItem -Problem "Pakketverlies richting internet ($($InternetPing.LostPercent)%)" `
                    -Cause "Probleem bij provider of modem (lokaal netwerk is OK)" `
                    -Steps @("Herstart modem", "Neem contact op met provider", "Test op ander tijdstip") `
                    -Effort "laag"
            }
        }
        if ($InternetPing.AvgLatency -gt 100) {
            Add-Warning("Internet latency hoog: $($InternetPing.AvgLatency)ms")
            Add-AdviceItem -Problem "Hoge internet latency ($($InternetPing.AvgLatency)ms)" `
                -Cause "Overbelaste route, congestie bij provider, of grote afstand tot server" `
                -Steps @("Herstart modem en router", "Test op ander tijdstip (buiten avondpiek)", "Neem contact op met provider als het aanhoudt") `
                -Effort "laag"
        }
    }

    # Vergelijking gateway vs internet
    if ($GatewayPing.Success -and $InternetPing.Success) {
        $delta = $InternetPing.AvgLatency - $GatewayPing.AvgLatency
        if ($delta -gt 200) {
            Add-Warning("Groot verschil gateway ($($GatewayPing.AvgLatency)ms) vs internet ($($InternetPing.AvgLatency)ms)")
        }
    }
}

# =========================================================================
# MODULE: WIFI ANALYSE
# =========================================================================

function Analyze-WiFi {
    param(
        [string]$State, [string]$SSID, [string]$Signal,
        [string]$Channel, [string]$RadioType,
        [string]$ReceiveRate, [string]$TransmitRate
    )

    $connected = ($State -match "connected") -or ($State -match "Verbonden")
    if (-not $connected) {
        Add-Observation("Geen WiFi (bekabeld of WiFi uit)")
        return
    }

    # Signaal
    if ($Signal -match "(\d+)") {
        $pct = [int]$Matches[1]
        if ($pct -lt 50) {
            Add-Issue("WiFi signaal zeer zwak: $pct%")
            Add-AdviceItem -Problem "WiFi signaal te zwak ($pct%)" `
                -Cause "Router te ver weg of achter dikke muren/vloeren" `
                -Steps @("Ga dichter bij de router staan", "Test met netwerkkabel om WiFi uit te sluiten", "Overweeg mesh systeem of extra access point") `
                -Effort "middel"
            Add-NextStep("WiFi signaal verbeteren: router verplaatsen of mesh")
        }
        elseif ($pct -lt 60) { Add-Warning("WiFi signaal laag: $pct%") }
        elseif ($pct -lt 75) { Add-Observation("WiFi signaal redelijk: $pct%") }
        else { Add-Observation("WiFi signaal goed: $pct%") }
    }

    # Frequentie band
    $is24 = $false
    if ($Channel -match "(\d+)") {
        $ch = [int]$Matches[1]
        if ($ch -le 14) {
            $is24 = $true
            Add-Observation("WiFi: 2.4 GHz kanaal $ch")
            if ($ch -ne 1 -and $ch -ne 6 -and $ch -ne 11) {
                Add-Warning("WiFi kanaal ${ch}: aanbevolen is 1, 6 of 11")
            }
        }
        else {
            Add-Observation("WiFi: 5 GHz kanaal $ch")
        }
    }
    elseif ($RadioType -match "802\.11n") { $is24 = $true }

    if ($is24) {
        Add-AdviceItem -Problem "WiFi op 2.4 GHz band" `
            -Cause "Device kiest automatisch 2.4GHz of 5GHz niet beschikbaar" `
            -Steps @("Controleer of router 5GHz ondersteunt", "Maak apart 5GHz netwerk aan of activeer band steering") `
            -Effort "laag"
    }

    # Link speed
    $rx = 0; $tx = 0
    if ($ReceiveRate -match "(\d+)") { $rx = [int]$Matches[1] }
    if ($TransmitRate -match "(\d+)") { $tx = [int]$Matches[1] }
    if ($rx -gt 0 -or $tx -gt 0) {
        $avg = [math]::Round(($rx + $tx) / 2, 0)
        if ($avg -lt 50) { Add-Warning("WiFi link speed laag: RX $rx / TX $tx Mbps") }
        else { Add-Observation("WiFi link speed: RX $rx / TX $tx Mbps") }
    }
}

# =========================================================================
# MODULE: DNS PRESTATIE [Full only]
# =========================================================================

function Test-DNSPerformance {
    param([array]$DnsServers)

    $testDomains = @("google.com", "microsoft.com", "sluisict.nl")
    $allDNS = @($DnsServers) + @("1.1.1.1", "8.8.8.8", "9.9.9.9") | Sort-Object -Unique | Where-Object { $_ }
    $results = @()

    foreach ($dns in $allDNS | Select-Object -First 6) {
        $totalMs = 0; $ok = 0; $fail = 0; $times = @()

        foreach ($domain in $testDomains) {
            try {
                $elapsed = Measure-Command {
                    Resolve-DnsName -Name $domain -Server $dns -DnsOnly -Type A -ErrorAction Stop | Out-Null
                }
                $ms = [math]::Round($elapsed.TotalMilliseconds, 0)
                $totalMs += $ms; $times += $ms; $ok++
            }
            catch { $fail++ }
        }

        $avgMs = if ($ok -gt 0) { [math]::Round($totalMs / $ok, 0) } else { -1 }
        $isCfg = ($DnsServers -contains $dns)
        $label = switch ($dns) {
            "8.8.8.8" { "Google DNS" }
            "1.1.1.1" { "Cloudflare" }
            "9.9.9.9" { "Quad9" }
            default { if ($isCfg) { "Geconfigureerd" } else { "Publiek" } }
        }

        $results += @{
            Server = $dns; AvgMs = $avgMs; Times = $times
            Successes = $ok; Failures = $fail; IsConfigured = $isCfg; Label = $label
        }
    }

    return $results
}

function Analyze-DNSResults {
    param([array]$Results)
    if ($Results.Count -eq 0) { return }

    $configured = $Results | Where-Object { $_.IsConfigured }
    $public = $Results | Where-Object { -not $_.IsConfigured }

    foreach ($dns in $configured) {
        if ($dns.Successes -eq 0) {
            Add-Issue("DNS server $($dns.Server) reageert niet")
            Add-NextStep("Wissel DNS naar 1.1.1.1 (Cloudflare)")
        }
        elseif ($dns.AvgMs -gt 100) {
            Add-Warning("DNS $($dns.Server) traag: $($dns.AvgMs)ms")
            Add-AdviceItem -Problem "Trage DNS server ($($dns.Server): $($dns.AvgMs)ms)" `
                -Cause "ISP DNS server overbelast of ver weg" `
                -Steps @("Wijzig DNS naar 1.1.1.1 (Cloudflare) of 8.8.8.8 (Google)", "In Windows: netwerk adapter -> IPv4 -> DNS handmatig instellen") `
                -Effort "laag"
        }
    }

    $bestCfg = $configured | Where-Object { $_.AvgMs -gt 0 } | Sort-Object AvgMs | Select-Object -First 1
    $bestPub = $public | Where-Object { $_.AvgMs -gt 0 } | Sort-Object AvgMs | Select-Object -First 1

    if ($bestCfg -and $bestPub -and $bestPub.AvgMs -gt 0 -and $bestCfg.AvgMs -gt ($bestPub.AvgMs * 2)) {
        Add-NextStep("DNS versnellen: wissel naar $($bestPub.Label) ($($bestPub.Server): $($bestPub.AvgMs)ms)")
    }
}

# =========================================================================
# MODULE: MTU DISCOVERY [Full only]
# =========================================================================

function Find-OptimalMTU {
    param([string]$Target = "1.1.1.1", [int]$MaxSeconds = 90)

    $result = @{ OptimalMTU = 1500; StandardMTU = $true; Issue = "" }
    $startTime = Get-Date

    # Snelle check: standaard MTU 1500 (payload 1472)?
    $test = ping $Target -n 1 -f -l 1472 -w 3000 2>&1 | Out-String
    if ($test -match "Reply from|Antwoord van") { return $result }

    # Binary search
    $low = 1200; $high = 1500; $best = 1200

    while ($low -le $high) {
        if (((Get-Date) - $startTime).TotalSeconds -gt $MaxSeconds) { break }

        $mid = [math]::Floor(($low + $high) / 2)
        $payload = $mid - 28
        if ($payload -lt 0) { break }

        $test = ping $Target -n 1 -f -l $payload -w 2000 2>&1 | Out-String

        if ($test -match "Reply from|Antwoord van") {
            $best = $mid; $low = $mid + 1
        }
        else { $high = $mid - 1 }
    }

    $result.OptimalMTU = $best
    $result.StandardMTU = ($best -ge 1490)

    if ($best -lt 1400) {
        $result.Issue = "LAAG"
        Add-Issue("MTU zeer laag: $best (standaard 1500)")
        Add-AdviceItem -Problem "MTU verlaagd naar $best (standaard 1500)" `
            -Cause "Dubbele encapsulatie: VPN tunnel, PPPoE, of router-op-router" `
            -Steps @("Check of er een VPN actief is", "Check of glasvezel/PPPoE correct is geconfigureerd", "Check op dubbele router situatie") `
            -Effort "middel"
    }
    elseif ($best -lt 1490) {
        $result.Issue = "VERLAAGD"
        Add-Warning("MTU iets onder standaard: $best (normaal bij PPPoE/glasvezel)")
    }
    else { Add-Observation("MTU standaard: $best") }

    return $result
}

# =========================================================================
# MODULE: WIFI OMGEVINGSSCAN [Full only]
# =========================================================================

function Scan-WiFiEnvironment {
    $raw = (netsh wlan show networks mode=bssid) 2>$null | Out-String
    if (-not $raw -or $raw.Length -lt 20) { return @() }

    $networks = @()
    $cur = $null

    foreach ($line in $raw -split "`r?`n") {
        if ($line -match "^SSID \d+\s*:\s*(.*)") {
            if ($cur) { $networks += $cur }
            $cur = @{ SSID = $Matches[1].Trim(); Signal = 0; Channel = 0; Auth = ""; Band = "" }
        }
        if ($cur) {
            if ($line -match "Signal\s*:\s*(\d+)%") { $cur.Signal = [int]$Matches[1] }
            if ($line -match "Channel\s*:\s*(\d+)") {
                $ch = [int]$Matches[1]; $cur.Channel = $ch
                $cur.Band = if ($ch -le 14) { "2.4GHz" } else { "5GHz" }
            }
            if ($line -match "Authentication\s*:\s*(.+)") { $cur.Auth = $Matches[1].Trim() }
        }
    }
    if ($cur) { $networks += $cur }
    return $networks
}

function Analyze-WiFiEnvironment {
    param([array]$Networks, [int]$OwnChannel, [string]$OwnSSID)

    if ($Networks.Count -eq 0) { return }
    Add-Observation("WiFi omgeving: $($Networks.Count) netwerken")

    $ch24 = $Networks | Where-Object { $_.Channel -gt 0 -and $_.Channel -le 14 }

    if ($OwnChannel -gt 0 -and $OwnChannel -le 14) {
        $same = ($ch24 | Where-Object { $_.Channel -eq $OwnChannel -and $_.SSID -ne $OwnSSID }).Count
        if ($same -ge 3) {
            Add-Issue("WiFi kanaal $OwnChannel is DRUK: $same netwerken op hetzelfde kanaal")
            Add-NextStep("Wissel WiFi kanaal naar rustiger alternatief (1, 6 of 11)")
        }
        elseif ($same -ge 1) {
            Add-Warning("WiFi kanaal $OwnChannel gedeeld met $same netwerk(en)")
        }

        $best = @(1, 6, 11) | ForEach-Object {
            @{ Ch = $_; Count = ($ch24 | Where-Object { $_.Channel -eq $_ }).Count }
        } | Sort-Object Count | Select-Object -First 1

        $ownCount = ($ch24 | Where-Object { $_.Channel -eq $OwnChannel }).Count
        if ($best.Ch -ne $OwnChannel -and $ownCount -gt ($best.Count + 1)) {
            Add-AdviceItem -Problem "WiFi kanaal $OwnChannel is drukker dan kanaal $($best.Ch)" `
                -Cause "Buurnetwerken gebruiken hetzelfde kanaal" `
                -Steps @("Log in op router (vaak 192.168.1.1)", "Ga naar WiFi instellingen", "Kies kanaal $($best.Ch) (nu $($best.Count) netwerken, uw kanaal $ownCount)") `
                -Effort "laag"
        }
    }

    $open = $Networks | Where-Object { $_.Auth -match "Open" }
    $wep = $Networks | Where-Object { $_.Auth -match "WEP" }
    if ($open.Count -gt 0) { Add-Observation("Open netwerken in buurt: $($open.Count)") }
    if ($wep.Count -gt 0) { Add-Warning("WEP-netwerken in buurt (onveilig)") }

    if ($Networks.Count -ge 10) {
        Add-Observation("Drukke omgeving: overweeg 5GHz band voor minder interferentie")
    }
}

# =========================================================================
# MODULE: SERVICE BEREIKBAARHEID [Full only]
# =========================================================================

function Test-TCPPortFast {
    param([string]$ComputerName, [int]$Port, [int]$TimeoutMs = 3000)
    $tcp = $null
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $connect = $tcp.BeginConnect($ComputerName, $Port, $null, $null)
        $done = $connect.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($done) {
            try { $tcp.EndConnect($connect); return $true }
            catch { return $false }
        }
        return $false
    }
    catch { return $false }
    finally { if ($tcp) { $tcp.Close() } }
}

function Test-ServiceReachability {
    $services = @(
        @{ Name = "Google DNS"; Host = "dns.google"; Port = 443 },
        @{ Name = "Cloudflare"; Host = "cloudflare-dns.com"; Port = 443 },
        @{ Name = "Microsoft 365"; Host = "outlook.office365.com"; Port = 443 },
        @{ Name = "YouTube"; Host = "www.youtube.com"; Port = 443 },
        @{ Name = "Netflix"; Host = "www.netflix.com"; Port = 443 },
        @{ Name = "Steam"; Host = "store.steampowered.com"; Port = 443 },
        @{ Name = "Xbox Live"; Host = "www.xbox.com"; Port = 443 },
        @{ Name = "PlayStation"; Host = "www.playstation.com"; Port = 443 }
    )

    $results = @()
    foreach ($svc in $services) {
        $ms = -1; $ok = $false
        try {
            $elapsed = Measure-Command {
                $ok = Test-TCPPortFast -ComputerName $svc.Host -Port $svc.Port -TimeoutMs 5000
            }
            $ms = [math]::Round($elapsed.TotalMilliseconds, 0)
        }
        catch { }

        $results += @{
            Name = $svc.Name; Host = $svc.Host; Reachable = $ok; LatencyMs = $ms
        }
    }
    return $results
}

function Analyze-ServiceResults {
    param([array]$Results)
    if ($Results.Count -eq 0) { return }

    $ok = ($Results | Where-Object { $_.Reachable }).Count
    $fail = ($Results | Where-Object { -not $_.Reachable }).Count

    if ($fail -eq $Results.Count) {
        Add-Issue("ALLE services onbereikbaar - geen functioneel internet")
    }
    elseif ($fail -ge 3) {
        $names = ($Results | Where-Object { -not $_.Reachable } | Select-Object -ExpandProperty Name) -join ", "
        Add-Warning("$fail services onbereikbaar: $names")
        Add-AdviceItem -Problem "$fail van $($Results.Count) services niet bereikbaar" `
            -Cause "Firewall, proxy of DNS filtering blokkeert services" `
            -Steps @("Check of firewall/proxy deze sites blokkeert", "Test met andere DNS (1.1.1.1)", "Probeer in incognito browser") `
            -Effort "laag"
    }

    $slow = $Results | Where-Object { $_.Reachable -and $_.LatencyMs -gt 3000 }
    if ($slow.Count -gt 0) {
        $names = ($slow | Select-Object -ExpandProperty Name) -join ", "
        Add-Warning("Trage verbinding naar: $names (>3 sec)")
    }
}

# =========================================================================
# MODULE: SECURITY + IPv6
# =========================================================================

function Test-SecurityAndIPv6 {
    param([array]$WifiNetworks, [string]$OwnSSID, [switch]$FullMode)

    # WiFi security (altijd als we op WiFi zitten)
    if ($WifiNetworks -and $WifiNetworks.Count -gt 0) {
        $own = $WifiNetworks | Where-Object { $_.SSID -eq $OwnSSID } | Select-Object -First 1
        if ($own) {
            if ($own.Auth -match "Open") {
                Add-Issue("WiFi '$OwnSSID' is OPEN (geen wachtwoord!)")
                Add-NextStep("WiFi beveiligen: stel WPA2/WPA3 in op router")
            }
            elseif ($own.Auth -match "WEP") {
                Add-Issue("WiFi '$OwnSSID' gebruikt WEP (makkelijk te kraken)")
                Add-NextStep("WiFi beveiligen: upgrade naar WPA2/WPA3")
            }
            elseif ($own.Auth -match "WPA3") { Add-Observation("WiFi beveiliging: WPA3 (uitstekend)") }
            elseif ($own.Auth -match "WPA2") { Add-Observation("WiFi beveiliging: WPA2 (goed)") }
        }
    }

    # Windows Firewall
    try {
        $fwProfiles = Get-NetFirewallProfile -ErrorAction Stop
        $off = $fwProfiles | Where-Object { $_.Enabled -eq $false }
        if ($off.Count -gt 0) {
            $names = ($off | Select-Object -ExpandProperty Name) -join ", "
            Add-Warning("Windows Firewall UIT voor: $names")
            Add-NextStep("Windows Firewall inschakelen voor alle profielen")
        }
        else { Add-Observation("Windows Firewall: actief") }
    }
    catch { Add-Observation("Firewall status niet controleerbaar") }

    # IPv6
    $ipv6Result = @{ HasIPv6 = $false; Connectivity = $false; DualStack = $false; Addresses = @() }

    try {
        $v6addrs = Get-NetIPAddress -AddressFamily IPv6 -ErrorAction Stop |
        Where-Object { $_.IPAddress -notmatch '^fe80::' -and $_.IPAddress -ne '::1' }
        if ($v6addrs.Count -gt 0) {
            $ipv6Result.HasIPv6 = $true
            $ipv6Result.Addresses = @($v6addrs | Select-Object -ExpandProperty IPAddress)

            if ($FullMode) {
                $v6ping = ping -6 ipv6.google.com -n 2 -w 3000 2>&1 | Out-String
                if ($v6ping -match "Reply from|Antwoord van") {
                    $ipv6Result.Connectivity = $true
                    $ipv6Result.DualStack = $true
                }
            }
        }
    }
    catch { }

    if ($ipv6Result.DualStack) { Add-Observation("IPv6: dual-stack actief") }
    elseif ($ipv6Result.HasIPv6) { Add-Observation("IPv6: aanwezig maar connectiviteit niet getest") }
    else { Add-Observation("IPv6: niet beschikbaar (alleen IPv4)") }

    return $ipv6Result
}

# =========================================================================
# MODULE: SPEEDTEST CLASSIFICATIE
# =========================================================================

function Analyze-Speedtest {
    param(
        [double]$DownloadMbps, [double]$UploadMbps, [double]$LatencyMs,
        [hashtable]$GatewayPing, [string]$ISP
    )

    if ($DownloadMbps -lt 25) {
        Add-Issue("Download zeer laag: $DownloadMbps Mbps")
        Add-AdviceItem -Problem "Lage downloadsnelheid ($DownloadMbps Mbps)" `
            -Cause "Goedkoop abonnement, WiFi bottleneck, of provider congestie" `
            -Steps @("Check abonnement: welke snelheid hoort erbij?", "Test bekabeld (WiFi uit)", "Test op ander tijdstip (buiten avondpiek)") `
            -Effort "laag"
        Add-NextStep("Snelheid onderzoeken: test bekabeld + check abonnement")
    }
    elseif ($DownloadMbps -lt 50) {
        Add-Warning("Download traag: $DownloadMbps Mbps")
    }
    else { Add-Observation("Download: $DownloadMbps Mbps") }

    if ($UploadMbps -lt 10) {
        Add-Warning("Upload laag: $UploadMbps Mbps (videobellen kan haperen)")
    }

    # Gateway vs speedtest latency
    if ($GatewayPing.Success) {
        if ($GatewayPing.AvgLatency -gt 10 -and $LatencyMs -gt 50) {
            Add-Issue("INTERN PROBLEEM: hoge latency lokaal ($($GatewayPing.AvgLatency)ms) + internet ($LatencyMs ms)")
            Add-NextStep("Lokaal netwerk troubleshooten: test bekabeld")
        }
        elseif ($LatencyMs -gt 100 -and $GatewayPing.AvgLatency -lt 10) {
            Add-Warning("EXTERN PROBLEEM: lokaal OK maar internet latency $LatencyMs ms")
        }
    }

    # Symmetrisch/asymmetrisch
    if ($UploadMbps -gt 0) {
        $ratio = $DownloadMbps / $UploadMbps
        if ($ratio -lt 2) { Add-Observation("Symmetrische verbinding (waarschijnlijk glasvezel)") }
        elseif ($ratio -gt 10) { Add-Observation("Sterk asymmetrisch (DL/UL $([math]::Round($ratio,1)):1) - kabel/DSL") }
    }
}

# =========================================================================
# MODULE: RAPPORT - SUMMARY GENERATIE
# =========================================================================

function Generate-Summary {
    param(
        [hashtable]$GatewayPing, [hashtable]$InternetPing,
        [hashtable]$GatewayJitter, [hashtable]$InternetJitter,
        [array]$PhysicalGateways, [array]$DnsServers, [array]$DhcpServers,
        [object]$AdapterClass,
        [string]$WifiState, [string]$WifiSSID, [string]$WifiSignal,
        [string]$WifiChannel, [string]$WifiRadio,
        [string]$WifiRateR, [string]$WifiRateT,
        [bool]$SpeedOK, [double]$DLMbps, [double]$ULMbps,
        [double]$SpeedLatency, [string]$ISP,
        [array]$DnsResults, [hashtable]$MtuResult, [array]$ServiceResults,
        [hashtable]$IPv6Status, [array]$WifiEnvironment
    )

    # Status labels met emoji
    $gwStatus = "$iFail Fout"
    if ($PhysicalGateways.Count -eq 1) {
        if ($GatewayPing.Success -and $GatewayPing.LostPercent -eq 0 -and $GatewayPing.AvgLatency -lt 10) { $gwStatus = "$iOK OK" }
        elseif ($GatewayPing.Success) { $gwStatus = "$iWarn Let op" }
    }
    elseif ($PhysicalGateways.Count -gt 1) { $gwStatus = "$iWarn Meerdere" }

    $wifiConnected = ($WifiState -match "connected|Verbonden")
    $wifiLabel = "$iOK Geen WiFi (bekabeld)"
    if ($wifiConnected -and $WifiSignal -match "(\d+)") {
        $sig = [int]$Matches[1]
        if ($sig -ge 75) { $wifiLabel = "$iOK Goed ($sig%)" }
        elseif ($sig -ge 60) { $wifiLabel = "$iWarn Redelijk ($sig%)" }
        else { $wifiLabel = "$iFail Zwak ($sig%)" }
    }

    $gwPingLabel = "$iFail Fout"
    if ($GatewayPing.Success) {
        if ($GatewayPing.LostPercent -eq 0 -and $GatewayPing.AvgLatency -lt 5) { $gwPingLabel = "$iOK Perfect" }
        elseif ($GatewayPing.LostPercent -lt 2 -and $GatewayPing.AvgLatency -lt 10) { $gwPingLabel = "$iOK Goed" }
        elseif ($GatewayPing.LostPercent -lt 5) { $gwPingLabel = "$iWarn Matig" }
        else { $gwPingLabel = "$iFail Slecht" }
    }

    $inetPingLabel = "$iFail Fout"
    if ($InternetPing.Success) {
        if ($InternetPing.LostPercent -eq 0 -and $InternetPing.AvgLatency -lt 30) { $inetPingLabel = "$iOK Goed" }
        elseif ($InternetPing.LostPercent -lt 2 -and $InternetPing.AvgLatency -lt 100) { $inetPingLabel = "$iWarn Redelijk" }
        else { $inetPingLabel = "$iFail Slecht" }
    }

    $speedLabel = "$iWarn Niet getest"
    if ($SpeedOK) {
        if ($DLMbps -ge 200) { $speedLabel = "$iOK Snel" }
        elseif ($DLMbps -ge 50) { $speedLabel = "$iOK Normaal" }
        else { $speedLabel = "$iWarn Traag" }
    }

    $jitterLabel = "N/A"
    if ($InternetJitter.Jitter -ge 0) {
        $jitterLabel = switch ($InternetJitter.Quality) {
            "UITSTEKEND" { "$iOK Uitstekend ($($InternetJitter.Jitter)ms)" }
            "GOED" { "$iOK Goed ($($InternetJitter.Jitter)ms)" }
            "MATIG" { "$iWarn Matig ($($InternetJitter.Jitter)ms)" }
            "SLECHT" { "$iFail Slecht ($($InternetJitter.Jitter)ms)" }
            default { "$($InternetJitter.Jitter)ms" }
        }
    }

    # =====================================================================
    # RISICO SCORE (0-100)
    # =====================================================================
    # 0-10  = Gezond         (groen)
    # 11-30 = Aandachtspunt  (geel)
    # 31-60 = Probleem       (oranje)
    # 61+   = Actie nodig    (rood)
    $riskScore = 0

    # Gateway bereikbaarheid (zwaarste factor)
    if (-not $GatewayPing.Success) {
        $riskScore += 50   # router down = ernstig
    }
    else {
        # Gateway packet loss
        if ($GatewayPing.LostPercent -gt 10) { $riskScore += 30 }
        elseif ($GatewayPing.LostPercent -gt 2) { $riskScore += 15 }
        elseif ($GatewayPing.LostPercent -gt 0) { $riskScore += 5 }

        # Gateway latency
        if ($GatewayPing.AvgLatency -gt 50) { $riskScore += 15 }
        elseif ($GatewayPing.AvgLatency -gt 10) { $riskScore += 5 }
    }

    # Internet bereikbaarheid
    if (-not $InternetPing.Success) {
        $riskScore += 25
    }
    else {
        if ($InternetPing.LostPercent -gt 5) { $riskScore += 15 }
        elseif ($InternetPing.LostPercent -gt 1) { $riskScore += 8 }

        if ($InternetPing.AvgLatency -gt 100) { $riskScore += 10 }
        elseif ($InternetPing.AvgLatency -gt 50) { $riskScore += 5 }
    }

    # Jitter
    if ($InternetJitter -and $InternetJitter.Jitter -ge 0) {
        switch ($InternetJitter.Quality) {
            "SLECHT" { $riskScore += 15 }
            "MATIG" { $riskScore += 8 }
            "GOED" { $riskScore += 2 }
        }
    }

    # Snelheid
    if ($SpeedOK) {
        if ($DLMbps -lt 10) { $riskScore += 15 }
        elseif ($DLMbps -lt 25) { $riskScore += 10 }
        elseif ($DLMbps -lt 50) { $riskScore += 5 }
    }

    # Issues en warnings
    $riskScore += [Math]::Min(($Global:AnalysisResults.Issues.Count * 10), 30)
    $riskScore += [Math]::Min(($Global:AnalysisResults.Warnings.Count * 3), 15)

    # WiFi signaal (als op WiFi)
    if ($wifiConnected -and $WifiSignal -match "(\d+)") {
        $wSig = [int]$Matches[1]
        if ($wSig -lt 30) { $riskScore += 15 }
        elseif ($wSig -lt 50) { $riskScore += 8 }
        elseif ($wSig -lt 60) { $riskScore += 3 }
    }

    # Clamp
    $riskScore = [Math]::Min($riskScore, 100)
    $riskScore = [Math]::Max($riskScore, 0)

    # Label
    $riskLabel = switch ($true) {
        ($riskScore -le 10) { "$iOK GEZOND"; break }
        ($riskScore -le 30) { "$iWarn AANDACHTSPUNT"; break }
        ($riskScore -le 60) { "$iFail PROBLEEM"; break }
        default { "$iFail ACTIE NODIG" }
    }

    # Conclusie
    $conclusie = @()
    $gezond = $true

    if ($Global:AnalysisResults.Issues.Count -gt 0 -or $riskScore -gt 60) {
        $gezond = $false
        $conclusie += "$iWarn Er zijn problemen gevonden."
        if (-not $GatewayPing.Success) {
            $conclusie += "Router is niet bereikbaar. Check kabel/WiFi."
        }
        elseif ($GatewayPing.LostPercent -gt 5) {
            $conclusie += "Verbinding naar router is instabiel ($($GatewayPing.LostPercent)% loss)."
        }
        else {
            $conclusie += "Zie DIAGNOSE sectie voor details."
        }
    }
    elseif ($riskScore -gt 10) {
        # Score 11-60: werkt maar niet ideaal
        $gezond = $false
        $conclusie += "$iWarn Netwerk werkt, maar er zijn aandachtspunten."
    }
    else {
        # Score 0-10: alles top
        $conclusie += "$iOK Netwerk is gezond en stabiel."
        if ($SpeedOK) { $conclusie += "Snelheid: $DLMbps Mbps download." }
    }

    # Klant-interpretatie (1 regel)
    $klantLine = ""
    $isWired = -not $wifiConnected
    $connType = if ($isWired) { "bekabeld" } else { "WiFi" }
    $hasCGNAT = $Global:AnalysisResults.Infos | Where-Object { $_ -match 'CGNAT' }
    if ($SpeedOK -and $DLMbps -gt 200) {
        $parts = @()
        if ($InternetJitter -and $InternetJitter.Quality -in @('UITSTEKEND', 'GOED')) {
            $parts += "videobellen/gaming uitstekend"
        }
        elseif ($InternetJitter) {
            $parts += "videobellen OK, gaming kan haperen"
        }
        if ($hasCGNAT) { $parts += "port forwarding mogelijk lastig door CGNAT" }
        if ($parts.Count -gt 0) { $klantLine = "Voor deze verbinding ($connType): $($parts -join '. ')." }
    }
    elseif ($SpeedOK) {
        $klantLine = "Verbinding ($connType) is functioneel maar niet snel ($DLMbps Mbps)."
    }

    # Build summary
    $uniqueDhcp = @($DhcpServers | Sort-Object -Unique)
    $dhcpLabel = if ($uniqueDhcp.Count -eq 1) { "$iOK OK" } elseif ($uniqueDhcp.Count -eq 0) { "$iOK OK (handmatig IP)" } else { "$iFail $($uniqueDhcp.Count) servers!" }

    $s = Join-Path $outDir "00_summary.txt"
    @(
        "================================================================="
        "SluisICT Netwerk Diagnose v3.5 - $modeName MODE"
        "================================================================="
        "Tijdstip: $(Get-Date -Format 'dd-MM-yyyy HH:mm')"
        $(if ($ClientName) { "Klant:    $ClientName" } else { "" })
        "Score:    $riskScore/100 $riskLabel"
        ""
        "-----------------------------------------------------------------"
        "NETWERK BASIS"
        "-----------------------------------------------------------------"
        "Status:   $gwStatus"
        "Router:   $(if ($PhysicalGateways.Count) { $PhysicalGateways -join ', ' } else { 'Niet gevonden' })"
        "DHCP:     $dhcpLabel"
        "DNS:      $iOK OK ($($DnsServers.Count) servers)"
        "Adapters: $($AdapterClass.Physical.Count) fysiek$(if ($AdapterClass.Virtual.Count -gt 0) { ", $($AdapterClass.Virtual.Count) virtueel (genegeerd)" })$(if ($AdapterClass.VPN.Count -gt 0) { ", $($AdapterClass.VPN.Count) VPN" })"
        ""
        "-----------------------------------------------------------------"
        "WIFI"
        "-----------------------------------------------------------------"
        "Status:   $wifiLabel"
    ) | Out-File -FilePath $s -Encoding UTF8

    if ($wifiConnected) {
        AddLine $s "Netwerk:  $WifiSSID"
        if ($WifiChannel -match "(\d+)") {
            $ch = [int]$Matches[1]
            $band = if ($ch -le 14) { "2.4 GHz (kanaal $ch)" } else { "5 GHz (kanaal $ch)" }
            AddLine $s "Band:     $band"
        }
        if ($WifiRateR -match "\d+" -or $WifiRateT -match "\d+") {
            AddLine $s "Snelheid: RX $WifiRateR / TX $WifiRateT Mbps"
        }
    }
    else {
        AddLine $s "          Niet op WiFi (bekabeld of WiFi uit)"
    }

    AddLine $s ""
    AddLine $s "-----------------------------------------------------------------"
    AddLine $s "STABILITEIT"
    AddLine $s "-----------------------------------------------------------------"
    AddLine $s "Router:   $gwPingLabel"
    if ($GatewayPing.Success) {
        AddLine $s "  -> Loss: $($GatewayPing.LostPercent)% | Latency: $($GatewayPing.AvgLatency)ms (max $($GatewayPing.MaxLatency)ms)"
    }
    else { AddLine $s "  -> Niet bereikbaar" }
    AddLine $s "Internet: $inetPingLabel"
    if ($InternetPing.Success) {
        AddLine $s "  -> Loss: $($InternetPing.LostPercent)% | Latency: $($InternetPing.AvgLatency)ms (max $($InternetPing.MaxLatency)ms)"
    }
    else { AddLine $s "  -> Geen verbinding" }
    AddLine $s "Jitter:   $jitterLabel"
    AddLine $s ""

    # Full-only secties
    if ($Full) {
        # DNS
        AddLine $s "-----------------------------------------------------------------"
        AddLine $s "DNS"
        AddLine $s "-----------------------------------------------------------------"
        if ($DnsResults -and $DnsResults.Count -gt 0) {
            foreach ($d in $DnsResults | Sort-Object AvgMs) {
                $dIcon = if ($d.AvgMs -le 0) { $iFail } elseif ($d.AvgMs -lt 30) { $iOK } elseif ($d.AvgMs -lt 100) { $iWarn } else { $iFail }
                $cfg = if ($d.IsConfigured) { " [IN GEBRUIK]" } else { "" }
                $val = if ($d.AvgMs -gt 0) { "$($d.AvgMs)ms" } else { "FAILED" }
                AddLine $s "  $dIcon $($d.Server) ($($d.Label)): $val$cfg"
            }
            $fastest = $DnsResults | Where-Object { $_.AvgMs -gt 0 } | Sort-Object AvgMs | Select-Object -First 1
            if ($fastest) { AddLine $s "  Snelste: $($fastest.Label) ($($fastest.Server): $($fastest.AvgMs)ms)" }
        }
        else { AddLine $s "  DNS test niet uitgevoerd" }
        AddLine $s ""

        # MTU
        AddLine $s "-----------------------------------------------------------------"
        AddLine $s "MTU"
        AddLine $s "-----------------------------------------------------------------"
        if ($MtuResult -and $MtuResult.OptimalMTU -gt 0) {
            $mLabel = if ($MtuResult.StandardMTU) { "$iOK Standaard" } elseif ($MtuResult.Issue -eq "LAAG") { "$iFail Verlaagd" } else { "$iWarn Iets verlaagd" }
            AddLine $s "  $mLabel ($($MtuResult.OptimalMTU) / 1500)"
            if (-not $MtuResult.StandardMTU) { AddLine $s "  PPPoE glasvezel of VPN/tunnel overhead" }
        }
        AddLine $s ""

        # Services
        AddLine $s "-----------------------------------------------------------------"
        AddLine $s "SERVICES"
        AddLine $s "-----------------------------------------------------------------"
        if ($ServiceResults -and $ServiceResults.Count -gt 0) {
            $okCount = ($ServiceResults | Where-Object { $_.Reachable }).Count
            AddLine $s "  $okCount/$($ServiceResults.Count) bereikbaar"
            foreach ($sv in $ServiceResults) {
                $sIcon = if ($sv.Reachable) { $iOK } else { $iFail }
                $sTime = if ($sv.LatencyMs -gt 0) { "$($sv.LatencyMs)ms" } else { "N/A" }
                AddLine $s "  $sIcon $($sv.Name): $sTime"
            }
        }
        AddLine $s ""
    }

    # Speedtest (beide modes)
    AddLine $s "-----------------------------------------------------------------"
    AddLine $s "SPEEDTEST"
    AddLine $s "-----------------------------------------------------------------"
    if ($SpeedOK) {
        AddLine $s "Status:   $speedLabel"
        AddLine $s "Download: $DLMbps Mbps"
        AddLine $s "Upload:   $ULMbps Mbps"
        AddLine $s "Latency:  $SpeedLatency ms"
        AddLine $s "Provider: $ISP"
    }
    elseif ($NoSpeedtest) {
        AddLine $s "Status:   Overgeslagen (-NoSpeedtest)"
    }
    else {
        AddLine $s "Status:   Niet uitgevoerd"
    }
    AddLine $s ""

    # Diagnose
    AddLine $s "-----------------------------------------------------------------"
    AddLine $s "DIAGNOSE"
    AddLine $s "-----------------------------------------------------------------"
    if ($gezond -and $Global:AnalysisResults.Warnings.Count -eq 0) {
        AddLine $s "$iOK Geen problemen gevonden"
    }
    else {
        if ($Global:AnalysisResults.Issues.Count -gt 0) {
            AddLine $s ""
            AddLine $s "$iFail PROBLEMEN:"
            foreach ($iss in $Global:AnalysisResults.Issues) { AddLine $s "  - $iss" }
        }
        if ($Global:AnalysisResults.Warnings.Count -gt 0) {
            AddLine $s ""
            AddLine $s "$iWarn AANDACHTSPUNTEN:"
            foreach ($w in $Global:AnalysisResults.Warnings) { AddLine $s "  - $w" }
        }
    }
    AddLine $s ""

    # Conclusie
    AddLine $s "-----------------------------------------------------------------"
    AddLine $s "CONCLUSIE"
    AddLine $s "-----------------------------------------------------------------"
    foreach ($c in $conclusie) { AddLine $s $c }
    if ($klantLine) { AddLine $s $klantLine }
    AddLine $s ""

    # Info (niet-kritieke bevindingen)
    if ($Global:AnalysisResults.Infos.Count -gt 0) {
        AddLine $s "-----------------------------------------------------------------"
        AddLine $s "INFO"
        AddLine $s "-----------------------------------------------------------------"
        $iInfo = "$([char]0x2139)"
        foreach ($inf in $Global:AnalysisResults.Infos) { AddLine $s "  $iInfo $inf" }
        AddLine $s ""
    }

    # Volgende stap (max 3)
    AddLine $s "-----------------------------------------------------------------"
    AddLine $s "VOLGENDE STAP"
    AddLine $s "-----------------------------------------------------------------"
    if ($Global:AnalysisResults.NextSteps.Count -gt 0) {
        $shown = 0
        foreach ($ns in $Global:AnalysisResults.NextSteps) {
            if ($shown -ge 3) { break }
            AddLine $s "  -> $ns"
            $shown++
        }
    }
    else {
        AddLine $s "  Geen actie nodig."
        if (-not $gezond) {
            AddLine $s "  Als klacht blijft: draai Full-mode diagnose."
        }
    }
    AddLine $s ""
    AddLine $s "================================================================="
    $fileRef = if ($Full) { "01-18 + 98-99" } else { "01-12 + 17-18 + 98-99" }
    AddLine $s "Bestanden: $fileRef"
    AddLine $s "================================================================="
}

# =========================================================================
# MODULE: RAPPORT - ADVIES GENERATIE
# =========================================================================

function Generate-AdviceReport {
    $c = @()
    $c += "================================================================="
    $c += "SluisICT - ADVIES RAPPORT"
    $c += "================================================================="
    $c += "Datum: $(Get-Date -Format 'dd-MM-yyyy HH:mm')"
    $c += "Mode:  $modeName"
    if ($ClientName) { $c += "Klant: $ClientName" }
    $c += ""

    if ($Global:AnalysisResults.AdviceItems.Count -gt 0) {
        $nr = 0
        foreach ($item in $Global:AnalysisResults.AdviceItems) {
            $nr++
            $c += "-----------------------------------------------------------------"
            $c += "PROBLEEM ${nr}: $($item.Problem)"
            $c += "-----------------------------------------------------------------"
            $c += "OORZAAK: $($item.Cause)"
            $c += ""
            $c += "WAT TE DOEN:"
            $stepNr = 0
            foreach ($step in $item.Steps) {
                $stepNr++
                $c += "  $stepNr. $step"
            }
            $c += ""
            $c += "MOEITE: $($item.Effort)"
            $c += ""
        }
    }
    else {
        $c += "$iOK Geen problemen gevonden die actie vereisen."
        $c += ""
    }

    if ($Global:AnalysisResults.Observations.Count -gt 0) {
        $c += "-----------------------------------------------------------------"
        $c += "OBSERVATIES"
        $c += "-----------------------------------------------------------------"
        foreach ($obs in $Global:AnalysisResults.Observations) { $c += "  - $obs" }
        $c += ""
    }

    $c += "================================================================="
    $c += "STANDAARD TROUBLESHOOTING"
    $c += "================================================================="
    $c += ""
    $c += "1. WiFi problemen:"
    $c += "   -> Test ALTIJD eerst bekabeld"
    $c += "   -> Gebruik 5GHz waar mogelijk"
    $c += "   -> Router centraal + op hoogte"
    $c += ""
    $c += "2. Dubbele NAT:"
    $c += "   -> ISP modem in bridge mode"
    $c += "   -> OF eigen router in access point mode"
    $c += ""
    $c += "3. Lage snelheid:"
    $c += "   -> Check abonnement"
    $c += "   -> Test bekabeld vs WiFi"
    $c += "   -> Test op meerdere tijdstippen"
    $c += ""
    $c += "================================================================="
    $c += "SluisICT"
    $c += "================================================================="

    OutFile "99_advies.txt" $c
}

# =========================================================================
# =========================================================================
# MAIN EXECUTION
# =========================================================================
# =========================================================================

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "SluisICT Netwerk Diagnose v3.5" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Mode: $modeName | Stappen: $totalSteps" -ForegroundColor White
if ($ClientName) { Write-Host "Klant: $ClientName" -ForegroundColor White }
Write-Host ""

# =========================================================================
# STAP 1: NETWERKDATA + ADAPTER CLASSIFICATIE
# =========================================================================

Show-Step "Netwerkdata + adapter classificatie"

$netIP = Get-NetIPConfiguration
$adaptersUp = $netIP | Where-Object { $_.NetAdapter.Status -eq "Up" }

$adapterClassification = Classify-NetworkAdapters

# Verzamel gateway/DNS/DHCP van ALLEEN fysieke adapters
$physicalGateways = @( @($adapterClassification.Physical | Where-Object { $_.Gateway } |
        Select-Object -ExpandProperty Gateway) | Sort-Object -Unique )

# Fallback: als geen gateway via adapter classificatie, probeer route tabel
if ($physicalGateways.Count -eq 0) {
    try {
        $defaultRoutes = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue
        if ($defaultRoutes) {
            $physicalGateways = @( @($defaultRoutes | Select-Object -ExpandProperty NextHop -ErrorAction SilentlyContinue |
                    Where-Object { $_ -and $_ -ne '0.0.0.0' }) | Sort-Object -Unique )
        }
    }
    catch { }

    # Fallback 2: ipconfig parsing
    if ($physicalGateways.Count -eq 0) {
        $ipcOut = ipconfig | Out-String
        $gwMatches = [regex]::Matches($ipcOut, 'Default Gateway[\s.:]+([\d]+\.[\d]+\.[\d]+\.[\d]+)')
        if ($gwMatches.Count -gt 0) {
            $physicalGateways = @( @($gwMatches | ForEach-Object { $_.Groups[1].Value }) | Sort-Object -Unique )
        }
    }
}

$dnsServers = @()
$dhcpServers = @()

foreach ($a in $adaptersUp) {
    if ($a.DnsServer.ServerAddresses) { $dnsServers += $a.DnsServer.ServerAddresses }
    if ($a.DhcpServer) { $dhcpServers += $a.DhcpServer }
}
$dnsServers = $dnsServers  | Where-Object { $_ } | Sort-Object -Unique
$dhcpServers = $dhcpServers | Where-Object { $_ } | Sort-Object -Unique

Write-Host "    Fysiek: $($adapterClassification.Physical.Count) | Virtueel: $($adapterClassification.Virtual.Count) | VPN: $($adapterClassification.VPN.Count)" -ForegroundColor Gray

# =========================================================================
# STAP 2: WIFI SNAPSHOT
# =========================================================================

Show-Step "WiFi snapshot"

$wifiInfo = (netsh wlan show interfaces) 2>$null | Out-String
$wifiState = Get-NetshValue $wifiInfo "State"
if (-not $wifiState) { $wifiState = Get-NetshValue $wifiInfo "Status" }
$wifiSSID = Get-NetshValue $wifiInfo "SSID"
$wifiSignal = Get-NetshValue $wifiInfo "Signal"
$wifiChan = Get-NetshValue $wifiInfo "Channel"
$wifiRadio = Get-NetshValue $wifiInfo "Radio type"
$wifiRateR = Get-NetshValue $wifiInfo "Receive rate (Mbps)"
$wifiRateT = Get-NetshValue $wifiInfo "Transmit rate (Mbps)"

# =========================================================================
# STAP 3: PING + TRACEROUTE
# =========================================================================

Show-Step "Ping + traceroute"

$gatewayPingRaw = ""
$internetPingRaw = ""

if ($physicalGateways.Count -ge 1) {
    Write-Host "    -> Ping gateway ($($physicalGateways[0])) x$gwPingCount..." -ForegroundColor Gray
    $gatewayPingRaw = ping $physicalGateways[0] -n $gwPingCount | Out-String
    OutFile "06_ping_gateway.txt" $gatewayPingRaw
}
else {
    OutFile "06_ping_gateway.txt" "Geen fysieke gateway gevonden."
}

Write-Host "    -> Ping 8.8.8.8 x$inetPingCount..." -ForegroundColor Gray
$internetPingRaw = ping 8.8.8.8 -n $inetPingCount | Out-String
OutFile "07_ping_8.8.8.8.txt" $internetPingRaw

Write-Host "    -> Traceroute ($tracertHops hops)..." -ForegroundColor Gray
$tracertRaw = tracert -d -h $tracertHops -w 1000 8.8.8.8 | Out-String
OutFile "08_tracert_8.8.8.8.txt" $tracertRaw

# Parse resultaten
$gatewayPing = Parse-PingResults -PingOutput $gatewayPingRaw -Target "Gateway"
$internetPing = Parse-PingResults -PingOutput $internetPingRaw -Target "8.8.8.8"
$gatewayJitter = Analyze-PingJitter -PingOutput $gatewayPingRaw -Target "Gateway"
$internetJitter = Analyze-PingJitter -PingOutput $internetPingRaw -Target "Internet"

# =========================================================================
# STAP 4: NETWERK ANALYSE
# =========================================================================

Show-Step "Netwerk analyse"

# Gateway, DHCP, DNS sanity
Analyze-GatewayAndSubnets -PhysicalGateways $physicalGateways `
    -DnsServers $dnsServers -DhcpServers $dhcpServers `
    -AdapterClassification $adapterClassification

# NAT evidence-based detectie
$virtualSubnets = @()
foreach ($va in $adapterClassification.Virtual) {
    foreach ($ip in $va.IPs) {
        if ($ip -match '^(\d+\.\d+\.\d+)\.') { $virtualSubnets += $Matches[1] }
    }
}
$natEvidence = Detect-NATEvidence -PhysicalGateways $physicalGateways `
    -TracertOutput $tracertRaw -VirtualSubnets $virtualSubnets

# Latency + packet loss
Analyze-LatencyAndPacketLoss -GatewayPing $gatewayPing -InternetPing $internetPing

# Jitter
if ($gatewayJitter.Quality -eq "SLECHT") {
    Add-Issue("Gateway jitter: $($gatewayJitter.Jitter)ms - VoIP/gaming onbruikbaar")
    Add-NextStep("Test bekabeld: hoge jitter duidt op WiFi probleem")
}
elseif ($gatewayJitter.Quality -eq "MATIG") {
    Add-Warning("Gateway jitter: $($gatewayJitter.Jitter)ms - videobellen kan haperen")
}
if ($internetJitter.Quality -eq "SLECHT") {
    Add-Warning("Internet jitter: $($internetJitter.Jitter)ms")
}

# WiFi
Analyze-WiFi -State $wifiState -SSID $wifiSSID -Signal $wifiSignal `
    -Channel $wifiChan -RadioType $wifiRadio `
    -ReceiveRate $wifiRateR -TransmitRate $wifiRateT

# =========================================================================
# FULL MODE: GEAVANCEERDE TESTS (stappen 5-9)
# =========================================================================

$dnsPerformance = @()
$mtuResult = @{ OptimalMTU = 0; StandardMTU = $true; Issue = "" }
$serviceResults = @()
$ipv6Status = @{ HasIPv6 = $false; Connectivity = $false; DualStack = $false }
$wifiEnvironment = @()

if ($Full) {

    # ----- STAP 5: DNS PRESTATIE -----
    Show-Step "DNS prestatie analyse"
    $dnsPerformance = Test-DNSPerformance -DnsServers $dnsServers
    Analyze-DNSResults -Results $dnsPerformance

    # ----- STAP 6: WIFI OMGEVINGSSCAN -----
    Show-Step "WiFi omgevingsscan"
    $wifiEnvironment = Scan-WiFiEnvironment
    $ownCh = 0
    if ($wifiChan -match "(\d+)") { $ownCh = [int]$Matches[1] }
    Analyze-WiFiEnvironment -Networks $wifiEnvironment -OwnChannel $ownCh -OwnSSID $wifiSSID

    # ----- STAP 7: MTU DISCOVERY -----
    Show-Step "MTU discovery (max 90 sec)"
    $mtuResult = Find-OptimalMTU -Target "1.1.1.1" -MaxSeconds 90

    # ----- STAP 8: SERVICE BEREIKBAARHEID -----
    Show-Step "Service bereikbaarheid (8 services)"
    $serviceResults = Test-ServiceReachability
    Analyze-ServiceResults -Results $serviceResults

    # ----- STAP 9: SECURITY + IPv6 (uitgebreid) -----
    Show-Step "Security + IPv6"
    $ipv6Status = Test-SecurityAndIPv6 -WifiNetworks $wifiEnvironment -OwnSSID $wifiSSID -FullMode
}
else {
    # Quick mode: basis security check (firewall + IPv6 aanwezigheid)
    $ipv6Status = Test-SecurityAndIPv6 -WifiNetworks @() -OwnSSID ""
}

# =========================================================================
# SPEEDTEST
# =========================================================================

$speedtestSuccess = $false
$downloadMbps = 0; $uploadMbps = 0; $latencyMs = 0; $ispName = ""

if ($NoSpeedtest) {
    $script:step++
    Write-Host "[$($script:step)/$totalSteps] Speedtest overgeslagen (-NoSpeedtest)" -ForegroundColor DarkGray
    OutFile "11_speedtest_cli.json" "Overgeslagen met -NoSpeedtest parameter."
    OutFile "12_speedtest_readable.txt" "Speedtest overgeslagen op verzoek."
}
else {
    Show-Step "Speedtest (30-60 sec)"

    if (Test-Path $speedtestExe) {
        try {
            Write-Host "    -> Speedtest uitvoeren..." -ForegroundColor Gray
            $speedtestOutput = & $speedtestExe --accept-license --accept-gdpr -f json 2>&1
            OutFile "11_speedtest_cli.json" $speedtestOutput

            $jsonString = ""
            $lines = $speedtestOutput | Where-Object { $_ }
            foreach ($line in $lines) {
                if ($line -match '^\s*\{"type":"result"') { $jsonString = $line; break }
            }
            if (-not $jsonString) {
                $jsonString = ($lines | Where-Object { $_ -match '^\s*\{.*\}\s*$' } | Select-Object -Last 1)
            }

            if ($jsonString) {
                $obj = $jsonString | ConvertFrom-Json
                if ($obj.download -and $obj.upload -and $obj.ping) {
                    $downloadMbps = [math]::Round(($obj.download.bandwidth * 8) / 1000000, 2)
                    $uploadMbps = [math]::Round(($obj.upload.bandwidth * 8) / 1000000, 2)
                    $latencyMs = $obj.ping.latency
                    $ispName = $obj.isp
                    $srv = $obj.server.name

                    OutFile "12_speedtest_readable.txt" @(
                        "================================================================="
                        "SPEEDTEST RESULTAAT"
                        "================================================================="
                        ""
                        "Download:  $downloadMbps Mbps"
                        "Upload:    $uploadMbps Mbps"
                        "Latency:   $latencyMs ms"
                        "ISP:       $ispName"
                        "Server:    $srv"
                        "Tijd:      $(Get-Date -Format 'HH:mm:ss')"
                    )

                    $speedtestSuccess = $true
                    Write-Host "    -> OK: $downloadMbps Mbps download" -ForegroundColor Green

                    Analyze-Speedtest -DownloadMbps $downloadMbps -UploadMbps $uploadMbps `
                        -LatencyMs $latencyMs -GatewayPing $gatewayPing -ISP $ispName
                }
                else { throw "JSON bevat niet download/upload/ping" }
            }
            else {
                OutFile "12_speedtest_readable.txt" "Speedtest fout: geen JSON output. Zie 11_speedtest_cli.json"
                Add-Warning("Speedtest failed - geen JSON output")
            }
        }
        catch {
            OutFile "12_speedtest_readable.txt" "Speedtest fout: $($_.Exception.Message)"
            Add-Warning("Speedtest error: $($_.Exception.Message)")
        }
    }
    else {
        OutFile "11_speedtest_cli.json" "speedtest.exe niet gevonden: $speedtestExe"
        OutFile "12_speedtest_readable.txt" @(
            "Speedtest CLI niet gevonden."
            ""
            "Download: https://www.speedtest.net/apps/cli"
            "Plaats in: $tools\SpeedtestCLI\"
        )
        Write-Host "    -> Speedtest CLI niet gevonden" -ForegroundColor DarkYellow
        Add-Observation("Speedtest CLI niet geinstalleerd")
    }
}

# =========================================================================
# RAW DATA DUMPS + RAPPORTAGE
# =========================================================================

Show-Step "Raw data + rapportage"

# Raw network dumps
OutFile "01_ipconfig_all.txt" (ipconfig /all)
OutFile "02_routes.txt" (route print)
OutFile "03_arp.txt" (arp -a)
OutFile "04_netstat_ano.txt" (netstat -ano)
OutFile "05_dns_nslookup.txt" @(
    "nslookup google.com"
    (nslookup google.com 2>$null)
    "" ; "nslookup sluisict.nl"
    (nslookup sluisict.nl 2>$null)
)
OutFile "09_wifi_netsh_interfaces.txt" $wifiInfo
OutFile "10_wifi_profiles.txt" (netsh wlan show profiles)

# Jitter (altijd)
$jitterContent = @("=================================================================", "JITTER ANALYSE", "=================================================================", "")
if ($gatewayJitter.Jitter -ge 0) {
    $jitterContent += "Gateway Jitter:"
    $jitterContent += "  Gemiddeld: $($gatewayJitter.Jitter)ms | Maximum: $($gatewayJitter.MaxJitter)ms | StdDev: $($gatewayJitter.StdDev)ms"
    $jitterContent += "  Kwaliteit: $($gatewayJitter.Quality) | Samples: $($gatewayJitter.Samples)"
    $jitterContent += ""
}
if ($internetJitter.Jitter -ge 0) {
    $jitterContent += "Internet Jitter:"
    $jitterContent += "  Gemiddeld: $($internetJitter.Jitter)ms | Maximum: $($internetJitter.MaxJitter)ms | StdDev: $($internetJitter.StdDev)ms"
    $jitterContent += "  Kwaliteit: $($internetJitter.Quality) | Samples: $($internetJitter.Samples)"
}
OutFile "18_jitter_analysis.txt" $jitterContent

# Security + adapters (ALTIJD, niet alleen Full)
$secContent = @("=================================================================", "SECURITY & ADAPTERS", "=================================================================", "")
$secContent += "IPv6: $(if ($ipv6Status.DualStack) { 'Dual-stack actief' } elseif ($ipv6Status.HasIPv6) { 'Aanwezig' } else { 'Niet beschikbaar' })"
$secContent += ""
$secContent += "Adapter Classificatie:"
foreach ($a in $adapterClassification.Physical) {
    $secContent += "  [FYSIEK]   $($a.Name) - $($a.Description) - IP: $($a.IPs -join ', ')"
}
foreach ($a in $adapterClassification.Virtual) {
    $secContent += "  [VIRTUEEL] $($a.Name) - $($a.Reason)"
}
foreach ($a in $adapterClassification.VPN) {
    $secContent += "  [VPN]      $($a.Name) - $($a.Description)"
}
OutFile "17_security_adapters.txt" $secContent

# Full-only output files
if ($Full) {
    # DNS
    $dnsContent = @("=================================================================", "DNS PRESTATIE ANALYSE", "=================================================================", "")
    foreach ($d in $dnsPerformance) {
        $status = if ($d.AvgMs -gt 0) { "$($d.AvgMs)ms" } else { "FAILED" }
        $cfg = if ($d.IsConfigured) { " [GECONFIGUREERD]" } else { "" }
        $dnsContent += "$($d.Server) ($($d.Label)): $status (succes: $($d.Successes)/3)$cfg"
    }
    OutFile "13_dns_performance.txt" $dnsContent

    # MTU
    OutFile "14_mtu_test.txt" @(
        "=================================================================", "MTU DISCOVERY", "================================================================="
        "", "Optimale MTU: $($mtuResult.OptimalMTU)", "Standaard (1500): $(if ($mtuResult.StandardMTU) { 'JA' } else { 'NEE' })"
        "Status: $(if ($mtuResult.Issue) { $mtuResult.Issue } else { 'OK' })"
    )

    # WiFi omgeving
    if ($wifiEnvironment.Count -gt 0) {
        $wfContent = @("=================================================================", "WIFI OMGEVINGSSCAN", "================================================================="
            "", "Totaal netwerken gevonden: $($wifiEnvironment.Count)", "")
        foreach ($net in $wifiEnvironment | Sort-Object Signal -Descending) {
            $ssidDisplay = if ($net.SSID) { $net.SSID } else { "[Verborgen]" }
            $wfContent += "$ssidDisplay | Signaal: $($net.Signal)% | Kanaal: $($net.Channel) ($($net.Band)) | Auth: $($net.Auth)"
        }
        OutFile "15_wifi_environment.txt" $wfContent
    }

    # Services
    $svcContent = @("=================================================================", "SERVICE BEREIKBAARHEID", "=================================================================", "")
    foreach ($sv in $serviceResults) {
        $icon = if ($sv.Reachable) { "$iOK" } else { "$iFail" }
        $svcContent += "$icon $($sv.Name) ($($sv.Host)) - $($sv.LatencyMs)ms"
    }
    OutFile "16_service_reachability.txt" $svcContent
}

# Generate summary + advice
Generate-Summary -GatewayPing $gatewayPing -InternetPing $internetPing `
    -GatewayJitter $gatewayJitter -InternetJitter $internetJitter `
    -PhysicalGateways $physicalGateways -DnsServers $dnsServers -DhcpServers $dhcpServers `
    -AdapterClass $adapterClassification `
    -WifiState $wifiState -WifiSSID $wifiSSID -WifiSignal $wifiSignal `
    -WifiChannel $wifiChan -WifiRadio $wifiRadio `
    -WifiRateR $wifiRateR -WifiRateT $wifiRateT `
    -SpeedOK $speedtestSuccess -DLMbps $downloadMbps -ULMbps $uploadMbps `
    -SpeedLatency $latencyMs -ISP $ispName `
    -DnsResults $dnsPerformance -MtuResult $mtuResult `
    -ServiceResults $serviceResults -IPv6Status $ipv6Status `
    -WifiEnvironment $wifiEnvironment

Generate-AdviceReport

# =========================================================================
# AI ANALYSE
# =========================================================================

Show-Step "AI analyse"

$aiAnalyzerPath = Join-Path $PSScriptRoot "Invoke-SluisICT-AIAnalysis.ps1"

if (Test-Path $aiAnalyzerPath) {
    try {
        $aiParams = @{ DiagnosticsPath = $outDir }
        if ($ClientName) { $aiParams.ClientName = $ClientName }
        & $aiAnalyzerPath @aiParams
    }
    catch {
        Write-Host "    [i] AI analyse error: $($_.Exception.Message)" -ForegroundColor DarkGray
    }
}
else {
    Write-Host "    [i] AI module niet gevonden ($aiAnalyzerPath)" -ForegroundColor DarkGray
}

# =========================================================================
# DONE
# =========================================================================

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Green
Write-Host "$iOK Diagnose compleet!" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Output: $outDir" -ForegroundColor Cyan
Write-Host ""
Write-Host "Bekijk:" -ForegroundColor Yellow
Write-Host "  -> 00_summary.txt    (overzicht)" -ForegroundColor White
Write-Host "  -> 99_advies.txt     (aanbevelingen)" -ForegroundColor White
Write-Host "  -> 98_ai_analyse.txt (AI analyse)" -ForegroundColor White
Write-Host ""

Start-Process explorer.exe $outDir
