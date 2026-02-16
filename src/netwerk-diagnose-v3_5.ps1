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
    [switch]$SpeedtestOnly,
    [string]$ClientName = "",
    [ValidateSet("", "VoIP", "Gaming", "WorkFromHome")]
    [string]$CaseMode = ""
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
if ($SpeedtestOnly) { $modeName = "SPEEDTEST" }
elseif ($Full) { $modeName = "FULL" }
else { $modeName = "QUICK" }
if ($CaseMode) { $modeName = "$modeName+$CaseMode" }
$totalSteps = if ($Full) { 15 } else { 11 }
$script:step = 0

# Ping counts
$gwPingCount = if ($Full) { 20 } else { 10 }
$inetPingCount = if ($Full) { 30 } else { 20 }
$tracertHops = if ($Full) { 15 } else { 5 }

# Stability monitor timing (both modes)
$monitorDuration = if ($Full) { 300 } else { 60 }
$monitorInterval = 1000

# DNS Battle queries per target
$dnsBattleQueries = if ($Full) { 20 } else { 10 }

# Case mode overrides
if ($CaseMode -eq "VoIP") {
    $inetPingCount = if ($Full) { 50 } else { 30 }
    if ($Full) { $monitorDuration = 300 }
    else { $monitorDuration = 90 }
}
elseif ($CaseMode -eq "Gaming") {
    $inetPingCount = if ($Full) { 50 } else { 30 }
    if ($Full) { $monitorDuration = 300 }
    else { $monitorDuration = 90 }
}
elseif ($CaseMode -eq "WorkFromHome") {
    if ($Full) { $monitorDuration = 300 }
    else { $monitorDuration = 90 }
}

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
    Evidence     = [System.Collections.ArrayList]::new()
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
    param(
        [string]$Problem, [string]$Cause, [string[]]$Steps, [string]$Effort,
        [string]$Impact = "Middel", [string]$Certainty = "Middel",
        [string[]]$SourceFiles = @()
    )
    $Global:AnalysisResults.AdviceItems.Add(@{
            Problem = $Problem; Cause = $Cause; Steps = $Steps; Effort = $Effort
            Impact = $Impact; Certainty = $Certainty; SourceFiles = $SourceFiles
        }) | Out-Null
}

function Add-Evidence {
    param([string]$Finding, [string]$File, [string]$Impact, [string]$Certainty)
    $Global:AnalysisResults.Evidence.Add(@{
            Finding = $Finding; File = $File; Impact = $Impact; Certainty = $Certainty
        }) | Out-Null
}

function Get-Percentile {
    param([double[]]$Data, [int]$Percentile)
    if ($Data.Count -eq 0) { return 0 }
    $sorted = @($Data | Sort-Object)
    $index = [math]::Ceiling($Percentile / 100.0 * $sorted.Count) - 1
    $index = [math]::Max(0, [math]::Min($index, $sorted.Count - 1))
    return $sorted[$index]
}

function Measure-Percentiles {
    param([double[]]$Data)
    if ($Data.Count -eq 0) { return @{ P50 = 0; P95 = 0; P99 = 0 } }
    return @{
        P50 = Get-Percentile -Data $Data -Percentile 50
        P95 = Get-Percentile -Data $Data -Percentile 95
        P99 = Get-Percentile -Data $Data -Percentile 99
    }
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
    param(
        [array]$DnsServers,
        [switch]$Deep
    )

    $testDomains = if ($Deep) {
        @("google.com", "microsoft.com", "cloudflare.com", "example.com", "msftconnecttest.com")
    }
    else {
        @("google.com", "microsoft.com", "sluisict.nl")
    }

    $allDNS = @($DnsServers) + @("1.1.1.1", "8.8.8.8", "9.9.9.9") | Sort-Object -Unique | Where-Object { $_ }
    $results = @()

    foreach ($dns in $allDNS | Select-Object -First 6) {
        $totalMs = 0; $ok = 0; $fail = 0; $times = @(); $nxdomain = 0

        foreach ($domain in $testDomains) {
            try {
                $elapsed = Measure-Command {
                    Resolve-DnsName -Name $domain -Server $dns -DnsOnly -Type A -ErrorAction Stop | Out-Null
                }
                $ms = [math]::Round($elapsed.TotalMilliseconds, 0)
                $totalMs += $ms; $times += $ms; $ok++
            }
            catch {
                if ($_.Exception.Message -match 'NXDOMAIN|does not exist') { $nxdomain++ }
                $fail++
            }
        }

        # AAAA records (Deep mode)
        $aaaaTimes = @(); $aaaaFail = 0
        if ($Deep) {
            foreach ($domain in @("google.com", "cloudflare.com")) {
                try {
                    $elapsed = Measure-Command {
                        Resolve-DnsName -Name $domain -Server $dns -DnsOnly -Type AAAA -ErrorAction Stop | Out-Null
                    }
                    $aaaaTimes += [math]::Round($elapsed.TotalMilliseconds, 0)
                }
                catch { $aaaaFail++ }
            }
        }

        $avgMs = if ($ok -gt 0) { [math]::Round($totalMs / $ok, 0) } else { -1 }
        $medianMs = if ($times.Count -gt 0) { Get-Percentile -Data $times -Percentile 50 } else { -1 }
        $p95Ms = if ($times.Count -gt 0) { Get-Percentile -Data $times -Percentile 95 } else { -1 }
        $isCfg = ($DnsServers -contains $dns)
        $label = switch ($dns) {
            "8.8.8.8" { "Google DNS" }
            "1.1.1.1" { "Cloudflare" }
            "9.9.9.9" { "Quad9" }
            default { if ($isCfg) { "Geconfigureerd" } else { "Publiek" } }
        }

        $results += @{
            Server = $dns; AvgMs = $avgMs; MedianMs = $medianMs; P95Ms = $p95Ms
            Times = $times; Successes = $ok; Failures = $fail; NXDOMAIN = $nxdomain
            IsConfigured = $isCfg; Label = $label
            AAAATimes = $aaaaTimes; AAAAFailures = $aaaaFail
        }
    }

    # DoH probe (Deep mode) - meten, geen config wijzigen
    $dohResults = @()
    if ($Deep) {
        $dohEndpoints = @(
            @{ Name = "Cloudflare DoH"; URL = "https://cloudflare-dns.com/dns-query?name=google.com&type=A" },
            @{ Name = "Google DoH"; URL = "https://dns.google/resolve?name=google.com&type=A" }
        )
        foreach ($doh in $dohEndpoints) {
            try {
                $elapsed = Measure-Command {
                    $null = Invoke-WebRequest -Uri $doh.URL -Headers @{"Accept" = "application/dns-json" } -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
                }
                $dohResults += @{ Name = $doh.Name; Ms = [math]::Round($elapsed.TotalMilliseconds, 0); Success = $true }
            }
            catch {
                $dohResults += @{ Name = $doh.Name; Ms = -1; Success = $false }
            }
        }
    }

    return @{ DNS = $results; DoH = $dohResults }
}

function Analyze-DNSResults {
    param([hashtable]$DnsData)
    if (-not $DnsData -or -not $DnsData.DNS) { return }
    $Results = $DnsData.DNS

    $configured = $Results | Where-Object { $_.IsConfigured }
    $public = $Results | Where-Object { -not $_.IsConfigured }

    foreach ($dns in $configured) {
        if ($dns.Successes -eq 0) {
            Add-Issue("DNS server $($dns.Server) reageert niet")
            Add-Evidence -Finding "DNS $($dns.Server) fail" -File "13_dns_performance.txt" -Impact "Hoog" -Certainty "Hoog"
            Add-NextStep("Wissel DNS naar 1.1.1.1 (Cloudflare)")
        }
        elseif ($dns.P95Ms -gt 300) {
            Add-Warning("DNS $($dns.Server) p95: $($dns.P95Ms)ms - merkbare vertraging")
            Add-AdviceItem -Problem "DNS server $($dns.Server) traag (p95=$($dns.P95Ms)ms)" `
                -Cause "ISP DNS overbelast of trage DNS proxy op router" `
                -Steps @("Zet DNS vast op 1.1.1.1 (Cloudflare)", "Of 8.8.8.8 (Google)", "Fritz: Internet > DNS-Server handmatig instellen") `
                -Effort "laag" -Impact "Hoog" -Certainty "Hoog" `
                -SourceFiles @("13_dns_performance.txt", "05_dns_nslookup.txt")
        }
        elseif ($dns.AvgMs -gt 100) {
            Add-Warning("DNS $($dns.Server) traag: $($dns.AvgMs)ms")
            Add-AdviceItem -Problem "Trage DNS server ($($dns.Server): $($dns.AvgMs)ms)" `
                -Cause "ISP DNS server overbelast of ver weg" `
                -Steps @("Wijzig DNS naar 1.1.1.1 (Cloudflare) of 8.8.8.8 (Google)", "In Windows: netwerk adapter -> IPv4 -> DNS handmatig instellen") `
                -Effort "laag" -Impact "Middel" -Certainty "Middel" `
                -SourceFiles @("13_dns_performance.txt")
        }
        if ($dns.NXDOMAIN -gt 0) {
            Add-Observation("DNS $($dns.Server): $($dns.NXDOMAIN) NXDOMAIN responses")
        }
        if ($dns.AAAAFailures -gt 0 -and $dns.AAAATimes.Count -eq 0) {
            Add-Observation("DNS $($dns.Server): IPv6 AAAA lookups falen")
        }
    }

    $bestCfg = $configured | Where-Object { $_.AvgMs -gt 0 } | Sort-Object AvgMs | Select-Object -First 1
    $bestPub = $public | Where-Object { $_.AvgMs -gt 0 } | Sort-Object AvgMs | Select-Object -First 1

    if ($bestCfg -and $bestPub -and $bestPub.AvgMs -gt 0 -and $bestCfg.AvgMs -gt ($bestPub.AvgMs * 2)) {
        Add-NextStep("DNS versnellen: wissel naar $($bestPub.Label) ($($bestPub.Server): $($bestPub.AvgMs)ms)")
    }

    # DoH results analysis
    if ($DnsData.DoH -and $DnsData.DoH.Count -gt 0) {
        $dohOK = $DnsData.DoH | Where-Object { $_.Success }
        if ($dohOK.Count -gt 0 -and $bestCfg -and $bestCfg.AvgMs -gt 0) {
            $bestDoH = $dohOK | Sort-Object Ms | Select-Object -First 1
            if ($bestDoH.Ms -lt ($bestCfg.AvgMs * 0.5)) {
                Add-Observation("DoH $($bestDoH.Name): $($bestDoH.Ms)ms vs huidige DNS: $($bestCfg.AvgMs)ms - DoH is sneller")
                Add-NextStep("Overweeg DoH/DoT activeren op router voor snellere + veiligere DNS")
            }
        }
    }
}

# =========================================================================
# MODULE: DNS BATTLE
# =========================================================================
# Vergelijkt systeem DNS resolver vs publieke DNS vs DoH
# Meerdere queries per target voor betrouwbare percentielberekening
# Output: 20_dns_battle.txt

function Invoke-DnsBattle {
    param(
        [array]$SystemDnsServers,
        [int]$QueriesPerTarget = 10,
        [switch]$Deep
    )

    $testDomains = @("google.com", "microsoft.com", "cloudflare.com", "example.com", "sluisict.nl")
    $publicDNS = @(
        @{ IP = "1.1.1.1"; Label = "Cloudflare" },
        @{ IP = "8.8.8.8"; Label = "Google DNS" },
        @{ IP = "9.9.9.9"; Label = "Quad9" }
    )
    $dohEndpoints = @(
        @{ Name = "Cloudflare DoH"; URL = "https://cloudflare-dns.com/dns-query?name={DOMAIN}&type=A"; Domains = @("google.com", "microsoft.com", "cloudflare.com") },
        @{ Name = "Google DoH"; URL = "https://dns.google/resolve?name={DOMAIN}&type=A"; Domains = @("google.com", "microsoft.com", "cloudflare.com") }
    )

    $battleResults = @{
        SystemDNS = @()
        PublicDNS = @()
        DoH       = @()
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        QueriesPerTarget = $QueriesPerTarget
    }

    Write-Host "    -> DNS Battle: $QueriesPerTarget queries per target..." -ForegroundColor Gray

    # --- SYSTEM DNS RESOLVERS ---
    foreach ($sysDns in $SystemDnsServers | Select-Object -First 3) {
        $allTimes = @(); $failures = 0; $timeouts = 0

        for ($q = 0; $q -lt $QueriesPerTarget; $q++) {
            $domain = $testDomains[$q % $testDomains.Count]
            try {
                $elapsed = Measure-Command {
                    Resolve-DnsName -Name $domain -Server $sysDns -DnsOnly -Type A -ErrorAction Stop | Out-Null
                }
                $ms = [math]::Round($elapsed.TotalMilliseconds, 0)
                if ($ms -gt 3000) { $timeouts++ } else { $allTimes += $ms }
            }
            catch {
                $failures++
                if ($_.Exception.Message -match 'timed out|timeout') { $timeouts++ }
            }
        }

        $pct = Measure-Percentiles -Data $allTimes
        $battleResults.SystemDNS += @{
            Server   = $sysDns; Label = "Systeem DNS"
            Times    = $allTimes; Failures = $failures; Timeouts = $timeouts
            Median   = $pct.P50; P95 = $pct.P95; P99 = $pct.P99
            Avg      = if ($allTimes.Count -gt 0) { [math]::Round(($allTimes | Measure-Object -Average).Average, 0) } else { -1 }
            Queries  = $QueriesPerTarget
        }
    }

    # --- PUBLIC DNS (direct queries) ---
    foreach ($pub in $publicDNS) {
        $allTimes = @(); $failures = 0; $timeouts = 0

        for ($q = 0; $q -lt $QueriesPerTarget; $q++) {
            $domain = $testDomains[$q % $testDomains.Count]
            try {
                $elapsed = Measure-Command {
                    Resolve-DnsName -Name $domain -Server $pub.IP -DnsOnly -Type A -ErrorAction Stop | Out-Null
                }
                $ms = [math]::Round($elapsed.TotalMilliseconds, 0)
                if ($ms -gt 3000) { $timeouts++ } else { $allTimes += $ms }
            }
            catch {
                $failures++
                if ($_.Exception.Message -match 'timed out|timeout') { $timeouts++ }
            }
        }

        $pct = Measure-Percentiles -Data $allTimes
        $battleResults.PublicDNS += @{
            Server   = $pub.IP; Label = $pub.Label
            Times    = $allTimes; Failures = $failures; Timeouts = $timeouts
            Median   = $pct.P50; P95 = $pct.P95; P99 = $pct.P99
            Avg      = if ($allTimes.Count -gt 0) { [math]::Round(($allTimes | Measure-Object -Average).Average, 0) } else { -1 }
            Queries  = $QueriesPerTarget
        }
    }

    # --- DoH (HTTPS queries) ---
    foreach ($doh in $dohEndpoints) {
        $allTimes = @(); $failures = 0

        $queriesForDoH = [math]::Min($QueriesPerTarget, $doh.Domains.Count * 3)
        for ($q = 0; $q -lt $queriesForDoH; $q++) {
            $domain = $doh.Domains[$q % $doh.Domains.Count]
            $url = $doh.URL -replace '\{DOMAIN\}', $domain
            try {
                $elapsed = Measure-Command {
                    $null = Invoke-WebRequest -Uri $url -Headers @{"Accept" = "application/dns-json" } `
                        -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
                }
                $allTimes += [math]::Round($elapsed.TotalMilliseconds, 0)
            }
            catch { $failures++ }
        }

        $pct = Measure-Percentiles -Data $allTimes
        $battleResults.DoH += @{
            Name     = $doh.Name
            Times    = $allTimes; Failures = $failures
            Median   = $pct.P50; P95 = $pct.P95; P99 = $pct.P99
            Avg      = if ($allTimes.Count -gt 0) { [math]::Round(($allTimes | Measure-Object -Average).Average, 0) } else { -1 }
            Queries  = $queriesForDoH
        }
    }

    # --- Analysis ---
    Analyze-DnsBattle -BattleData $battleResults
    return $battleResults
}

function Analyze-DnsBattle {
    param([hashtable]$BattleData)
    if (-not $BattleData) { return }

    # Find best system DNS and best public DNS
    $bestSys = $BattleData.SystemDNS | Where-Object { $_.Avg -gt 0 } | Sort-Object Avg | Select-Object -First 1
    $bestPub = $BattleData.PublicDNS | Where-Object { $_.Avg -gt 0 } | Sort-Object Avg | Select-Object -First 1

    # System DNS issues
    if ($bestSys) {
        if ($bestSys.Timeouts -gt 0) {
            Add-Issue("Systeem DNS ($($bestSys.Server)): $($bestSys.Timeouts) timeouts van $($bestSys.Queries) queries")
            Add-Evidence -Finding "DNS timeouts $($bestSys.Timeouts)x (systeem resolver $($bestSys.Server))" `
                -File "20_dns_battle.txt" -Impact "Hoog" -Certainty "Hoog"
        }
        if ($bestSys.P95 -gt 200) {
            Add-Warning("Systeem DNS p95: $($bestSys.P95)ms - trage name resolution")
            Add-Evidence -Finding "DNS p95=$($bestSys.P95)ms (systeem)" `
                -File "20_dns_battle.txt" -Impact "Hoog" -Certainty "Hoog"
        }
    }

    # Compare system vs public
    if ($bestSys -and $bestPub -and $bestSys.Avg -gt 0 -and $bestPub.Avg -gt 0) {
        if ($bestPub.Avg -lt ($bestSys.Avg * 0.5)) {
            Add-Observation("Publieke DNS ($($bestPub.Label)) is $([math]::Round($bestSys.Avg / $bestPub.Avg, 1))x sneller dan systeem DNS")
            Add-AdviceItem -Problem "Systeem DNS traag (median $($bestSys.Median)ms vs publiek $($bestPub.Median)ms)" `
                -Cause "ISP DNS/router DNS-proxy is traag" `
                -Steps @("Zet router DNS op $($bestPub.Server) ($($bestPub.Label))", "Of configureer DoH/DoT op router", "Test na wijziging met DNS Battle") `
                -Effort "laag" -Impact "Hoog" -Certainty "Hoog" `
                -SourceFiles @("20_dns_battle.txt")
        }
    }

    # DoH comparison
    $bestDoH = $BattleData.DoH | Where-Object { $_.Avg -gt 0 } | Sort-Object Avg | Select-Object -First 1
    if ($bestDoH -and $bestSys -and $bestSys.Avg -gt 0) {
        if ($bestDoH.Avg -lt ($bestSys.Avg * 0.5)) {
            Add-Observation("DoH ($($bestDoH.Name)): median $($bestDoH.Median)ms vs systeem DNS: $($bestSys.Median)ms")
            Add-NextStep("Overweeg DoH activeren op router voor snellere + veiligere DNS")
        }
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
    param([string]$CaseMode = "")

    $services = @(
        # DNS providers
        @{ Name = "Cloudflare DNS"; Host = "cloudflare-dns.com"; Port = 443; Category = "DNS" },
        @{ Name = "Google DNS"; Host = "dns.google"; Port = 443; Category = "DNS" },
        @{ Name = "Quad9"; Host = "dns.quad9.net"; Port = 443; Category = "DNS" },
        # Microsoft / Productivity
        @{ Name = "Microsoft 365"; Host = "outlook.office365.com"; Port = 443; Category = "Microsoft" },
        @{ Name = "MS Connectivity"; Host = "www.msftconnecttest.com"; Port = 80; Category = "Microsoft" },
        # Cloud / CDN
        @{ Name = "Google"; Host = "www.google.com"; Port = 443; Category = "Cloud" },
        @{ Name = "Cloudflare CDN"; Host = "www.cloudflare.com"; Port = 443; Category = "Cloud" }
    )

    # Case mode additions
    if ($CaseMode -eq "VoIP") {
        $services += @(
            @{ Name = "Teams"; Host = "teams.microsoft.com"; Port = 443; Category = "VoIP" },
            @{ Name = "Zoom"; Host = "zoom.us"; Port = 443; Category = "VoIP" }
        )
    }
    elseif ($CaseMode -eq "Gaming") {
        $services += @(
            @{ Name = "Steam"; Host = "store.steampowered.com"; Port = 443; Category = "Gaming" },
            @{ Name = "Xbox Live"; Host = "www.xbox.com"; Port = 443; Category = "Gaming" },
            @{ Name = "PlayStation"; Host = "www.playstation.com"; Port = 443; Category = "Gaming" }
        )
    }
    elseif ($CaseMode -eq "WorkFromHome") {
        $services += @(
            @{ Name = "Teams"; Host = "teams.microsoft.com"; Port = 443; Category = "WFH" },
            @{ Name = "SharePoint"; Host = "sharepoint.com"; Port = 443; Category = "WFH" },
            @{ Name = "VPN Check"; Host = "vpn.google.com"; Port = 443; Category = "WFH" }
        )
    }
    else {
        # Default: gaming + NL endpoint
        $services += @(
            @{ Name = "Steam"; Host = "store.steampowered.com"; Port = 443; Category = "Gaming" },
            @{ Name = "Rijksoverheid NL"; Host = "www.rijksoverheid.nl"; Port = 443; Category = "NL" }
        )
    }

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
            Name = $svc.Name; Host = $svc.Host; Reachable = $ok
            LatencyMs = $ms; Category = $svc.Category
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
        Add-Evidence -Finding "All services unreachable" -File "16_service_reachability.txt" -Impact "Hoog" -Certainty "Hoog"
    }
    elseif ($fail -ge 3) {
        $names = ($Results | Where-Object { -not $_.Reachable } | Select-Object -ExpandProperty Name) -join ", "
        Add-Warning("$fail services onbereikbaar: $names")

        # Analyze per category
        $categories = $Results | Group-Object { $_.Category }
        foreach ($cat in $categories) {
            $catFail = ($cat.Group | Where-Object { -not $_.Reachable }).Count
            if ($catFail -eq $cat.Count -and $cat.Count -gt 1) {
                Add-Warning("Categorie '$($cat.Name)': ALLE onbereikbaar")
            }
        }

        Add-AdviceItem -Problem "$fail van $($Results.Count) services niet bereikbaar" `
            -Cause "Firewall, proxy of DNS filtering blokkeert services" `
            -Steps @("Check of firewall/proxy deze sites blokkeert", "Test met andere DNS (1.1.1.1)", "Probeer in incognito browser") `
            -Effort "laag" -Impact "Middel" -Certainty "Middel" `
            -SourceFiles @("16_service_reachability.txt")
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
# MODULE: STABILITEITSMONITOR [Full only]
# =========================================================================
# Continue monitoring: elke 2s meten gedurende 2-5 min
# ping gateway + extern, DNS resolve, HTTP HEAD
# Rapporteert: loss %, max spike, p95 latency, jitter p95, outage count

function Test-StabilityMonitor {
    param(
        [string]$Gateway,
        [string[]]$ExternalIPs = @("1.1.1.1", "8.8.8.8"),
        [int]$DurationSec = 60,
        [int]$IntervalMs = 1000,
        [int]$SpikeThresholdMs = 100
    )

    $result = @{
        DurationSec = $DurationSec; Samples = 0
        Gateway  = @{ Latencies = [System.Collections.Generic.List[int]]::new(); Timeouts = 0; Outages = 0; OutageDurationSec = 0; Spikes = 0; Stats = @{} }
        External = @{ Latencies = [System.Collections.Generic.List[int]]::new(); Timeouts = 0; Outages = 0; OutageDurationSec = 0; Spikes = 0; Stats = @{} }
        DNS      = @{ Times = [System.Collections.Generic.List[int]]::new(); Failures = 0; Stats = @{} }
        HTTP     = @{ Times = [System.Collections.Generic.List[int]]::new(); Failures = 0; Stats = @{} }
    }

    $startTime = Get-Date
    $gwConsecTimeout = 0; $extConsecTimeout = 0
    $gwOutageStart = $null; $extOutageStart = $null
    $domains = @("google.com", "microsoft.com", "cloudflare.com", "example.com", "sluisict.nl")
    $httpEndpoints = @("http://www.msftconnecttest.com/connecttest.txt", "http://clients3.google.com/generate_204")
    $domIdx = 0; $httpIdx = 0; $extIdx = 0; $lastProgress = -1

    Write-Host "    -> Stabiliteitsmonitor: $DurationSec sec (interval ${IntervalMs}ms)..." -ForegroundColor Gray

    while (((Get-Date) - $startTime).TotalSeconds -lt $DurationSec) {
        $result.Samples++
        $tick = $result.Samples

        # Ping gateway (every tick)
        if ($Gateway) {
            $gwOut = ping $Gateway -n 1 -w 1000 2>&1 | Out-String
            if ($gwOut -match 'time[=<](\d+)ms' -or $gwOut -match 'tijd[=<](\d+)ms') {
                $gwMs = [int]$Matches[1]
                $result.Gateway.Latencies.Add($gwMs)
                if ($gwMs -gt $SpikeThresholdMs) { $result.Gateway.Spikes++ }
                if ($gwConsecTimeout -ge 3 -and $gwOutageStart) {
                    $result.Gateway.OutageDurationSec += [int]((Get-Date) - $gwOutageStart).TotalSeconds
                }
                $gwConsecTimeout = 0; $gwOutageStart = $null
            }
            else {
                $result.Gateway.Timeouts++
                $gwConsecTimeout++
                if ($gwConsecTimeout -eq 3) {
                    $result.Gateway.Outages++
                    $gwOutageStart = (Get-Date).AddSeconds(-3)
                }
            }
        }

        # Ping external (every tick, rotate targets)
        $extTarget = $ExternalIPs[$extIdx % $ExternalIPs.Count]; $extIdx++
        $extOut = ping $extTarget -n 1 -w 1000 2>&1 | Out-String
        if ($extOut -match 'time[=<](\d+)ms' -or $extOut -match 'tijd[=<](\d+)ms') {
            $extMs = [int]$Matches[1]
            $result.External.Latencies.Add($extMs)
            if ($extMs -gt $SpikeThresholdMs) { $result.External.Spikes++ }
            if ($extConsecTimeout -ge 3 -and $extOutageStart) {
                $result.External.OutageDurationSec += [int]((Get-Date) - $extOutageStart).TotalSeconds
            }
            $extConsecTimeout = 0; $extOutageStart = $null
        }
        else {
            $result.External.Timeouts++
            $extConsecTimeout++
            if ($extConsecTimeout -eq 3) {
                $result.External.Outages++
                $extOutageStart = (Get-Date).AddSeconds(-3)
            }
        }

        # DNS resolve (every 3 ticks)
        if ($tick % 3 -eq 0) {
            $domain = $domains[$domIdx % $domains.Count]; $domIdx++
            try {
                $dnsT = Measure-Command { Resolve-DnsName -Name $domain -Type A -DnsOnly -ErrorAction Stop | Out-Null }
                $result.DNS.Times.Add([math]::Round($dnsT.TotalMilliseconds, 0))
            }
            catch { $result.DNS.Failures++ }
        }

        # HTTP HEAD (every 10 ticks)
        if ($tick % 10 -eq 0) {
            $ep = $httpEndpoints[$httpIdx % $httpEndpoints.Count]; $httpIdx++
            try {
                $httpT = Measure-Command { $null = Invoke-WebRequest -Uri $ep -Method Head -TimeoutSec 3 -UseBasicParsing -ErrorAction Stop }
                $result.HTTP.Times.Add([math]::Round($httpT.TotalMilliseconds, 0))
            }
            catch { $result.HTTP.Failures++ }
        }

        # Progress every 30s
        $elapsed = [int]((Get-Date) - $startTime).TotalSeconds
        $progKey = [math]::Floor($elapsed / 30)
        if ($progKey -gt $lastProgress -and $elapsed -gt 0) {
            $lastProgress = $progKey
            $pct = [math]::Round(($elapsed / $DurationSec) * 100)
            Write-Host "    -> Monitor: ${pct}% (${elapsed}/${DurationSec}s, samples: $($result.Samples))..." -ForegroundColor Gray
        }

        Start-Sleep -Milliseconds $IntervalMs
    }

    # Close open outages
    if ($gwConsecTimeout -ge 3 -and $gwOutageStart) {
        $result.Gateway.OutageDurationSec += [int]((Get-Date) - $gwOutageStart).TotalSeconds
    }
    if ($extConsecTimeout -ge 3 -and $extOutageStart) {
        $result.External.OutageDurationSec += [int]((Get-Date) - $extOutageStart).TotalSeconds
    }

    # Calculate gateway stats (p50/p95/p99)
    if ($result.Gateway.Latencies.Count -gt 0) {
        $gwLats = @($result.Gateway.Latencies)
        $gwTotal = $gwLats.Count + $result.Gateway.Timeouts
        $gwPct = Measure-Percentiles -Data $gwLats
        $result.Gateway.Stats = @{
            Avg         = [math]::Round(($gwLats | Measure-Object -Average).Average, 1)
            Min         = ($gwLats | Measure-Object -Minimum).Minimum
            Max         = ($gwLats | Measure-Object -Maximum).Maximum
            P50         = $gwPct.P50
            P95         = $gwPct.P95
            P99         = $gwPct.P99
            LossPercent = if ($gwTotal -gt 0) { [math]::Round(($result.Gateway.Timeouts / $gwTotal) * 100, 2) } else { 0 }
            Spikes      = $result.Gateway.Spikes
        }
        if ($gwLats.Count -gt 1) {
            $diffs = @(); for ($i = 1; $i -lt $gwLats.Count; $i++) { $diffs += [math]::Abs($gwLats[$i] - $gwLats[$i - 1]) }
            $jPct = Measure-Percentiles -Data $diffs
            $result.Gateway.Stats.Jitter = [math]::Round(($diffs | Measure-Object -Average).Average, 1)
            $result.Gateway.Stats.JitterP95 = $jPct.P95
            $result.Gateway.Stats.JitterP99 = $jPct.P99
        }
    }

    # Calculate external stats (p50/p95/p99)
    if ($result.External.Latencies.Count -gt 0) {
        $extLats = @($result.External.Latencies)
        $extTotal = $extLats.Count + $result.External.Timeouts
        $extPct = Measure-Percentiles -Data $extLats
        $result.External.Stats = @{
            Avg         = [math]::Round(($extLats | Measure-Object -Average).Average, 1)
            Min         = ($extLats | Measure-Object -Minimum).Minimum
            Max         = ($extLats | Measure-Object -Maximum).Maximum
            P50         = $extPct.P50
            P95         = $extPct.P95
            P99         = $extPct.P99
            LossPercent = if ($extTotal -gt 0) { [math]::Round(($result.External.Timeouts / $extTotal) * 100, 2) } else { 0 }
            Spikes      = $result.External.Spikes
        }
        if ($extLats.Count -gt 1) {
            $diffs = @(); for ($i = 1; $i -lt $extLats.Count; $i++) { $diffs += [math]::Abs($extLats[$i] - $extLats[$i - 1]) }
            $jPct = Measure-Percentiles -Data $diffs
            $result.External.Stats.Jitter = [math]::Round(($diffs | Measure-Object -Average).Average, 1)
            $result.External.Stats.JitterP95 = $jPct.P95
            $result.External.Stats.JitterP99 = $jPct.P99
        }
    }

    # Calculate DNS stats (p50/p95/p99)
    if ($result.DNS.Times.Count -gt 0) {
        $dnsTimes = @($result.DNS.Times)
        $dnsPct = Measure-Percentiles -Data $dnsTimes
        $result.DNS.Stats = @{
            Median   = $dnsPct.P50
            P50      = $dnsPct.P50
            P95      = $dnsPct.P95
            P99      = $dnsPct.P99
            Avg      = [math]::Round(($dnsTimes | Measure-Object -Average).Average, 0)
            Max      = ($dnsTimes | Measure-Object -Maximum).Maximum
            Failures = $result.DNS.Failures
        }
    }

    # Calculate HTTP stats (p50/p95/p99)
    if ($result.HTTP.Times.Count -gt 0) {
        $httpTimes = @($result.HTTP.Times)
        $httpPct = Measure-Percentiles -Data $httpTimes
        $result.HTTP.Stats = @{
            Median   = $httpPct.P50
            P50      = $httpPct.P50
            P95      = $httpPct.P95
            P99      = $httpPct.P99
            Failures = $result.HTTP.Failures
        }
    }

    return $result
}

function Analyze-StabilityMonitor {
    param([hashtable]$MonitorResult)
    if (-not $MonitorResult -or $MonitorResult.Samples -eq 0) { return }

    $dur = $MonitorResult.DurationSec
    $gwS = $MonitorResult.Gateway.Stats
    $extS = $MonitorResult.External.Stats
    $dnsS = $MonitorResult.DNS.Stats

    # Gateway stability
    if ($gwS.Count -gt 0) {
        if ($gwS.LossPercent -gt 2) {
            Add-Issue("Stabiliteitsmonitor: gateway loss $($gwS.LossPercent)% over ${dur}s")
            Add-Evidence -Finding "Gateway packet loss $($gwS.LossPercent)% (${dur}s monitor)" `
                -File "19_stability_monitor.txt" -Impact "Hoog" -Certainty "Hoog"
        }
        if ($MonitorResult.Gateway.Outages -gt 0) {
            $outDur = $MonitorResult.Gateway.OutageDurationSec
            Add-Issue("Gateway outages: $($MonitorResult.Gateway.Outages)x (totaal ${outDur}s onbereikbaar)")
            Add-Evidence -Finding "Gateway outage $($MonitorResult.Gateway.Outages)x, ${outDur}s" `
                -File "19_stability_monitor.txt" -Impact "Hoog" -Certainty "Hoog"
        }
        if ($gwS.P99 -and $gwS.P99 -gt 50) {
            Add-Warning("Gateway p99 latency: $($gwS.P99)ms (spikes merkbaar bij VoIP/gaming)")
        }
        elseif ($gwS.P95 -gt 30) {
            Add-Warning("Gateway p95 latency: $($gwS.P95)ms (spikes merkbaar bij VoIP)")
        }
        if ($gwS.Spikes -gt 0) {
            Add-Observation("Gateway spikes (>100ms): $($gwS.Spikes)x in ${dur}s")
        }
    }

    # External stability
    if ($extS.Count -gt 0) {
        if ($extS.LossPercent -gt 1) {
            $detail = "$($extS.LossPercent)% loss, p99 $($extS.P99)ms, spikes $($extS.Spikes)x"
            Add-Warning("Internet instabiliteit: $detail")
            Add-Evidence -Finding "Internet $detail (${dur}s monitor)" `
                -File "19_stability_monitor.txt" -Impact "Hoog" -Certainty "Hoog"
        }
        if ($MonitorResult.External.Outages -gt 0) {
            $outDur = $MonitorResult.External.OutageDurationSec
            Add-Issue("Internet outages: $($MonitorResult.External.Outages)x (totaal ${outDur}s)")
            Add-Evidence -Finding "Internet outage $($MonitorResult.External.Outages)x, ${outDur}s" `
                -File "19_stability_monitor.txt" -Impact "Hoog" -Certainty "Hoog"
        }
        if ($extS.P99 -and $extS.P99 -gt 200) {
            Add-Warning("Internet p99: $($extS.P99)ms (VoIP/gaming onbruikbaar bij spikes)")
        }
        if ($extS.JitterP95 -and $extS.JitterP95 -gt 30) {
            Add-Warning("Internet jitter p95: $($extS.JitterP95)ms (VoIP/gaming instabiel)")
        }
        if ($extS.LossPercent -gt 0.5 -or ($extS.P99 -and $extS.P99 -gt 200)) {
            Add-Observation("Impact: merkbaar bij videobellen/gaming/Teams")
        }
    }

    # DNS stability
    if ($dnsS.Count -gt 0) {
        if ($dnsS.Failures -gt 0) {
            Add-Warning("DNS failures: $($dnsS.Failures)x tijdens ${dur}s monitor")
            Add-Evidence -Finding "DNS failures $($dnsS.Failures)x (${dur}s)" `
                -File "19_stability_monitor.txt" -Impact "Hoog" -Certainty "Hoog"
        }
        if ($dnsS.P95 -gt 200) {
            Add-Warning("DNS p95: $($dnsS.P95)ms - trage pagina loads")
            Add-AdviceItem -Problem "DNS instabiel (p95=$($dnsS.P95)ms, $($dnsS.Failures) failures)" `
                -Cause "ISP DNS overbelast of router DNS-proxy traag" `
                -Steps @("Zet Fritz/router DNS vast op 1.1.1.1 + 1.0.0.1", "Of gebruik DoT/DoH op router", "Test 24h na wijziging") `
                -Effort "laag" -Impact "Hoog" -Certainty "Hoog" `
                -SourceFiles @("19_stability_monitor.txt", "20_dns_battle.txt")
        }
    }
}

# =========================================================================
# MODULE: SPLIT-TEST LOKALISATIE
# =========================================================================
# Bepaalt: probleem in LAN, Router, of ISP/upstream
# ARP stability, hop-1 check, multi-target external ping

function Test-SplitLocalization {
    param(
        [string]$Gateway,
        [int]$PingCount = 10
    )

    $result = @{
        Gateway       = @{ ARP = ""; ARP2 = ""; MACStable = $true; PingResult = $null }
        Hop1          = @{ IP = ""; AvgLatency = 0; MaxLatency = 0; Spikes = $false }
        Targets       = @()
        Verdict       = "UNKNOWN"
        VerdictDetail = ""
    }

    # 1. Gateway ARP stability check
    if ($Gateway) {
        $arp1 = arp -a 2>&1 | Out-String
        $mac1 = ""
        $gwEscaped = [regex]::Escape($Gateway)
        if ($arp1 -match "$gwEscaped\s+([\da-f][\da-f]-[\da-f][\da-f]-[\da-f][\da-f]-[\da-f][\da-f]-[\da-f][\da-f]-[\da-f][\da-f])") { $mac1 = $Matches[1] }

        # Ping gateway
        $gwPingRaw = ping $Gateway -n $PingCount -w 1000 2>&1 | Out-String
        $result.Gateway.PingResult = Parse-PingResults -PingOutput $gwPingRaw -Target "Gateway"

        # Re-check ARP after some traffic
        Start-Sleep -Milliseconds 500
        $arp2 = arp -a 2>&1 | Out-String
        $mac2 = ""
        if ($arp2 -match "$gwEscaped\s+([\da-f][\da-f]-[\da-f][\da-f]-[\da-f][\da-f]-[\da-f][\da-f]-[\da-f][\da-f]-[\da-f][\da-f])") { $mac2 = $Matches[1] }

        $result.Gateway.ARP = $mac1
        $result.Gateway.ARP2 = $mac2
        if ($mac1 -and $mac2 -and $mac1 -ne $mac2) {
            $result.Gateway.MACStable = $false
        }
    }

    # 2. Hop-1 traceroute check (1 hop only, fast)
    $hop1Raw = tracert -d -h 2 -w 2000 8.8.8.8 2>&1 | Out-String
    foreach ($hline in ($hop1Raw -split "`r?`n")) {
        if ($hline -match '^\s*1\s') {
            $latencies = @([regex]::Matches($hline, '(\d+)\s*ms') | ForEach-Object { [int]$_.Groups[1].Value })
            if ($hline -match '(\d+\.\d+\.\d+\.\d+)') { $result.Hop1.IP = $Matches[1] }
            if ($latencies.Count -gt 0) {
                $result.Hop1.AvgLatency = [math]::Round(($latencies | Measure-Object -Average).Average, 0)
                $result.Hop1.MaxLatency = ($latencies | Measure-Object -Maximum).Maximum
                if ($result.Hop1.MaxLatency -gt 50) { $result.Hop1.Spikes = $true }
            }
            break
        }
    }

    # 3. Multi-target external ping
    $externalTargets = @(
        @{ IP = "1.1.1.1"; Name = "Cloudflare" },
        @{ IP = "8.8.8.8"; Name = "Google" },
        @{ IP = "9.9.9.9"; Name = "Quad9" }
    )
    $allFail = $true; $failCount = 0

    foreach ($target in $externalTargets) {
        Write-Host "    -> Split-test: $($target.Name) ($($target.IP))..." -ForegroundColor Gray
        $tRaw = ping $target.IP -n 5 -w 1000 2>&1 | Out-String
        $tResult = Parse-PingResults -PingOutput $tRaw -Target $target.Name
        $result.Targets += @{
            IP = $target.IP; Name = $target.Name
            Success = $tResult.Success; LossPercent = $tResult.LostPercent
            AvgLatency = $tResult.AvgLatency; MaxLatency = $tResult.MaxLatency
        }
        if ($tResult.Success -and $tResult.LostPercent -lt 100) { $allFail = $false }
        else { $failCount++ }
    }

    # 4. Verdict
    $gwOK = $result.Gateway.PingResult -and $result.Gateway.PingResult.Success -and $result.Gateway.PingResult.LostPercent -lt 5

    if (-not $gwOK) {
        $result.Verdict = "LOCAL"
        $result.VerdictDetail = "Gateway instabiel: probleem in lokaal netwerk (kabel/WiFi/switch)"
        Add-Issue("Split-test: LOKAAL probleem - gateway instabiel")
        Add-Evidence -Finding "Gateway unreachable/unstable" -File "20_split_test.txt" -Impact "Hoog" -Certainty "Hoog"
    }
    elseif (-not $result.Gateway.MACStable) {
        $result.Verdict = "LOCAL_LOOP"
        $result.VerdictDetail = "Gateway MAC wisselt: verdachte switching loop of ARP spoofing"
        Add-Issue("Split-test: ARP instabiliteit - MAC adres wisselt ($($result.Gateway.ARP) -> $($result.Gateway.ARP2))")
        Add-Evidence -Finding "MAC address flip" -File "20_split_test.txt" -Impact "Hoog" -Certainty "Hoog"
    }
    elseif ($result.Hop1.Spikes) {
        $result.Verdict = "LOCAL_EDGE"
        $result.VerdictDetail = "Hop-1 latency spikes ($($result.Hop1.MaxLatency)ms): probleem bij modem/router"
        Add-Warning("Split-test: hop-1 spike $($result.Hop1.MaxLatency)ms - router/modem verdacht")
        Add-Evidence -Finding "Hop-1 spike $($result.Hop1.MaxLatency)ms" -File "20_split_test.txt" -Impact "Middel" -Certainty "Middel"
    }
    elseif ($allFail) {
        $result.Verdict = "ISP"
        $result.VerdictDetail = "Alle externe targets falen: ISP/upstream probleem"
        Add-Issue("Split-test: ISP/upstream storing - alle 3 targets onbereikbaar")
        Add-Evidence -Finding "All 3 external targets fail" -File "20_split_test.txt" -Impact "Hoog" -Certainty "Hoog"
    }
    elseif ($failCount -ge 2) {
        $result.Verdict = "ISP_PARTIAL"
        $result.VerdictDetail = "Meerdere externe targets falen: waarschijnlijk upstream probleem"
        Add-Warning("Split-test: $failCount/3 externe targets falen")
    }
    elseif ($failCount -eq 1) {
        $failedName = ($result.Targets | Where-Object { -not $_.Success -or $_.LossPercent -ge 100 } | Select-Object -First 1).Name
        $result.Verdict = "TARGET_BIAS"
        $result.VerdictDetail = "Alleen $failedName faalt: target-specifiek, geen netwerk probleem"
        Add-Observation("Split-test: alleen $failedName onbereikbaar (target bias)")
    }
    else {
        $result.Verdict = "STABLE"
        $result.VerdictDetail = "Geen lokale of upstream problemen gedetecteerd"
    }

    return $result
}

# =========================================================================
# MODULE: IPv6 DIEPTETEST
# =========================================================================
# Niet alleen "aanwezig" maar: werkt het daadwerkelijk?
# ping -6, DNS AAAA, HTTP over IPv6, detect broken RA/DHCPv6

function Test-IPv6Deep {
    param([switch]$FullMode)

    $result = @{
        HasGlobalIPv6 = $false; Addresses = @()
        PingIPv6 = $false; PingLatency = 0
        DNSAAAA = $false; DNSAAAATime = 0
        HTTPIPv6 = $false; HTTPTime = 0
        Status = "NIET_BESCHIKBAAR"; Detail = ""
    }

    # Check for global IPv6 (niet link-local, niet loopback)
    try {
        $v6addrs = Get-NetIPAddress -AddressFamily IPv6 -ErrorAction Stop |
        Where-Object { $_.IPAddress -notmatch '^fe80::' -and $_.IPAddress -ne '::1' -and $_.PrefixOrigin -ne 'WellKnown' }
        if ($v6addrs.Count -gt 0) {
            $result.HasGlobalIPv6 = $true
            $result.Addresses = @($v6addrs | Select-Object -ExpandProperty IPAddress)
        }
    }
    catch { }

    if (-not $result.HasGlobalIPv6) {
        $result.Status = "NIET_BESCHIKBAAR"
        $result.Detail = "Geen globaal IPv6 adres (alleen IPv4)"
        Add-Observation("IPv6: niet beschikbaar (alleen IPv4)")
        return $result
    }

    # Test 1: Ping IPv6 target (Cloudflare)
    $v6target = "2606:4700:4700::1111"
    $v6ping = ping -6 $v6target -n 4 -w 2000 2>&1 | Out-String
    if ($v6ping -match 'Reply from|Antwoord van') {
        $result.PingIPv6 = $true
        if ($v6ping -match 'Average\s*=\s*(\d+)ms') { $result.PingLatency = [int]$Matches[1] }
        elseif ($v6ping -match 'gemiddeld\s*=\s*(\d+)ms') { $result.PingLatency = [int]$Matches[1] }
    }

    # Test 2: DNS AAAA resolve
    try {
        $aaaaElapsed = Measure-Command {
            $aaaaRes = Resolve-DnsName -Name "google.com" -Type AAAA -DnsOnly -ErrorAction Stop
        }
        if ($aaaaRes | Where-Object { $_.Type -eq 'AAAA' }) {
            $result.DNSAAAA = $true
            $result.DNSAAAATime = [math]::Round($aaaaElapsed.TotalMilliseconds, 0)
        }
    }
    catch { }

    # Test 3: HTTP over IPv6 (Full mode only, takes time)
    if ($FullMode) {
        try {
            $httpElapsed = Measure-Command {
                $null = Invoke-WebRequest -Uri "http://ipv6.google.com" -Method Head -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
            }
            $result.HTTPIPv6 = $true
            $result.HTTPTime = [math]::Round($httpElapsed.TotalMilliseconds, 0)
        }
        catch { }
    }

    # Determine status
    if ($result.PingIPv6 -and $result.DNSAAAA) {
        $result.Status = "VOLLEDIG_WERKEND"
        $result.Detail = "IPv6 dual-stack volledig functioneel"
        Add-Observation("IPv6: volledig werkend (ping OK, AAAA OK)")
    }
    elseif ($result.PingIPv6 -and -not $result.DNSAAAA) {
        $result.Status = "GEDEELTELIJK"
        $result.Detail = "IPv6 ping OK maar DNS AAAA faalt (DNS config issue)"
        Add-Warning("IPv6 gedeeltelijk: ping OK maar AAAA lookup faalt")
        Add-Evidence -Finding "IPv6 AAAA resolve failure" -File "21_ipv6_test.txt" -Impact "Middel" -Certainty "Middel"
    }
    elseif (-not $result.PingIPv6 -and $result.DNSAAAA) {
        $result.Status = "GEDEELTELIJK"
        $result.Detail = "DNS AAAA OK maar IPv6 ping faalt (routing/firewall)"
        Add-Warning("IPv6 gedeeltelijk: AAAA OK maar ping faalt (routing probleem)")
        Add-Evidence -Finding "IPv6 ping failure despite AAAA" -File "21_ipv6_test.txt" -Impact "Middel" -Certainty "Middel"
    }
    else {
        $result.Status = "BROKEN"
        $result.Detail = "IPv6 adres aanwezig maar niet functioneel (broken RA/DHCPv6)"
        Add-Issue("IPv6 BROKEN: adres aanwezig maar niets werkt")
        Add-Evidence -Finding "IPv6 broken (address present, no connectivity)" -File "21_ipv6_test.txt" -Impact "Middel" -Certainty "Hoog"
        Add-AdviceItem -Problem "IPv6 aanwezig maar niet werkend" `
            -Cause "Broken RA/DHCPv6 prefix delegation of ISP IPv6 storing" `
            -Steps @("Test: IPv6 tijdelijk uitschakelen op PC of Fritz", "Als problemen verdwijnen: IPv6 issue bij ISP/router", "Fritz: Internet > Zugangsdaten > IPv6 controleren") `
            -Effort "middel" -Impact "Middel" -Certainty "Hoog" `
            -SourceFiles @("21_ipv6_test.txt", "17_security_adapters.txt")
    }

    return $result
}

# =========================================================================
# MODULE: BUFFERBLOAT DETECTIE
# =========================================================================
# Idle latency vs loaded latency: als delta groot → bufferbloat
# SQM/QoS advies als delta > 30ms

function Test-Bufferbloat {
    param(
        [string]$Target = "1.1.1.1",
        [int]$BaselinePings = 10,
        [int]$LoadedDurationSec = 15,
        [int]$IntervalMs = 200
    )

    $result = @{
        IdleLatency = 0; IdleMax = 0
        LoadedLatencies = [System.Collections.Generic.List[int]]::new()
        LoadedAvg = 0; LoadedP95 = 0; LoadedMax = 0
        Delta = 0; Grade = "ONBEKEND"; Detail = ""
    }

    # Measure idle/baseline latency
    $idleRaw = ping $Target -n $BaselinePings -w 1000 2>&1 | Out-String
    $idleResult = Parse-PingResults -PingOutput $idleRaw -Target $Target
    if ($idleResult.Success) {
        $result.IdleLatency = $idleResult.AvgLatency
        $result.IdleMax = $idleResult.MaxLatency
    }
    else {
        $result.Grade = "NIET_MEETBAAR"
        $result.Detail = "Baseline ping faalt - kan bufferbloat niet meten"
        return $result
    }

    # Now measure loaded latency (rapid pings during network activity)
    # We use rapid pings as a proxy; real bufferbloat test would need simultaneous download
    Write-Host "    -> Bufferbloat: laden-test ($LoadedDurationSec sec)..." -ForegroundColor Gray

    # Start a background download to generate load
    $loadJob = $null
    try {
        $loadJob = Start-Job -ScriptBlock {
            # Generate sustained network traffic
            $wc = New-Object System.Net.WebClient
            for ($i = 0; $i -lt 10; $i++) {
                try {
                    $null = $wc.DownloadData("http://speed.cloudflare.com/__down?bytes=5000000")
                }
                catch { Start-Sleep -Milliseconds 500 }
            }
        }
    }
    catch { }

    # Measure latency during load
    $startTime = Get-Date
    while (((Get-Date) - $startTime).TotalSeconds -lt $LoadedDurationSec) {
        $lPing = ping $Target -n 1 -w 1000 2>&1 | Out-String
        if ($lPing -match 'time[=<](\d+)ms' -or $lPing -match 'tijd[=<](\d+)ms') {
            $result.LoadedLatencies.Add([int]$Matches[1])
        }
        Start-Sleep -Milliseconds $IntervalMs
    }

    # Cleanup background job
    if ($loadJob) {
        Stop-Job -Job $loadJob -ErrorAction SilentlyContinue
        Remove-Job -Job $loadJob -Force -ErrorAction SilentlyContinue
    }

    if ($result.LoadedLatencies.Count -gt 0) {
        $loadedArr = @($result.LoadedLatencies)
        $result.LoadedAvg = [math]::Round(($loadedArr | Measure-Object -Average).Average, 1)
        $result.LoadedMax = ($loadedArr | Measure-Object -Maximum).Maximum
        $result.LoadedP95 = Get-Percentile -Data $loadedArr -Percentile 95
        $result.Delta = [math]::Round($result.LoadedAvg - $result.IdleLatency, 1)

        if ($result.Delta -le 5) {
            $result.Grade = "A"
            $result.Detail = "Geen bufferbloat (delta $($result.Delta)ms)"
        }
        elseif ($result.Delta -le 30) {
            $result.Grade = "B"
            $result.Detail = "Minimale bufferbloat (delta $($result.Delta)ms)"
        }
        elseif ($result.Delta -le 100) {
            $result.Grade = "C"
            $result.Detail = "Matige bufferbloat (delta $($result.Delta)ms) - VoIP kan haperen"
            Add-Warning("Bufferbloat: +$($result.Delta)ms onder load - Teams/VoIP kan haperen")
            Add-AdviceItem -Problem "Bufferbloat: +$($result.Delta)ms latency onder load" `
                -Cause "Router buffert te veel pakketten zonder prioriteit" `
                -Steps @("Activeer SQM/QoS op router (Fritz: Internet > Zugangsdaten > Bandbreite)", "Beperk upload tot 80% van max als SQM niet beschikbaar", "Test opnieuw na wijziging") `
                -Effort "middel" -Impact "Hoog" -Certainty "Middel" `
                -SourceFiles @("22_bufferbloat.txt")
        }
        else {
            $result.Grade = "F"
            $result.Detail = "Ernstige bufferbloat (delta $($result.Delta)ms) - Teams/VoIP onbruikbaar onder load"
            Add-Issue("Bufferbloat ERNSTIG: +$($result.Delta)ms onder load")
            Add-Evidence -Finding "Bufferbloat delta $($result.Delta)ms" -File "22_bufferbloat.txt" -Impact "Hoog" -Certainty "Hoog"
            Add-AdviceItem -Problem "Ernstige bufferbloat: +$($result.Delta)ms onder upload/download" `
                -Cause "Router buffert pakketten zonder flow control" `
                -Steps @("Activeer SQM/QoS op router", "Zet upload/download limieten in SQM op 80-90% van maximum", "Overweeg router met fq_codel/CAKE ondersteuning") `
                -Effort "middel" -Impact "Hoog" -Certainty "Hoog" `
                -SourceFiles @("22_bufferbloat.txt")
        }
    }

    return $result
}

# =========================================================================
# MODULE: OMGEVINGSSNAPSHOT
# =========================================================================
# NIC driver, link speed, duplex, MAC OUI lookup voor AP/switch detectie

function Get-EnvironmentSnapshot {

    # Common OUI prefixes for network equipment (router/AP/switch vendors)
    $ouiLookup = @{
        "24-65-11" = "AVM/Fritz"; "C8-0E-14" = "AVM/Fritz"; "3C-A6-2F" = "AVM/Fritz"
        "B0-F2-08" = "AVM/Fritz"; "2C-91-AB" = "AVM/Fritz"; "E0-28-6D" = "AVM/Fritz"
        "3C-84-6A" = "TP-Link"; "50-C7-BF" = "TP-Link"; "EC-08-6B" = "TP-Link"
        "B0-95-75" = "TP-Link"; "98-DA-C4" = "TP-Link"; "30-B5-C2" = "TP-Link"
        "60-E3-27" = "TP-Link"; "AC-84-C6" = "TP-Link"; "DC-FE-18" = "TP-Link"
        "14-EB-B6" = "TP-Link"; "C4-E9-84" = "TP-Link Deco"; "18-D6-C7" = "TP-Link Deco"
        "04-D9-F5" = "ASUS"; "2C-FD-A1" = "ASUS"; "60-45-CB" = "ASUS"
        "F4-6B-EF" = "Netgear"; "28-80-88" = "Netgear"; "C4-04-15" = "Netgear"
        "B0-48-7A" = "Netgear"; "3C-37-86" = "Netgear"; "E4-F4-C6" = "Netgear"
        "B4-B0-24" = "Ubiquiti"; "24-5A-4C" = "Ubiquiti"; "68-D7-9A" = "Ubiquiti"
        "FC-EC-DA" = "Ubiquiti"; "78-8A-20" = "Ubiquiti"; "DC-9F-DB" = "Ubiquiti"
        "74-83-C2" = "Ubiquiti"; "44-D9-E7" = "Ubiquiti"; "80-2A-A8" = "Ubiquiti"
        "C8-3A-35" = "Tenda"; "00-1E-58" = "D-Link"; "00-1B-11" = "D-Link"
        "00-14-BF" = "Linksys"; "E8-9F-80" = "Linksys"
        "20-A6-CD" = "Google/Nest"; "F4-F5-D8" = "Google/Nest"
        "58-EF-68" = "Synology"; "00-11-32" = "Synology"
        "00-50-56" = "VMware"; "00-0C-29" = "VMware"
        "A8-6D-AA" = "Ziggo/VodafoneZiggo"; "8C-A6-DF" = "Ziggo/VodafoneZiggo"
    }

    $result = @{
        Adapters         = @()
        NetworkEquipment = @()
    }

    # Gather NIC details
    try {
        $nics = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        foreach ($nic in $nics) {
            $speed = $nic.LinkSpeed
            $duplex = ""
            try {
                $advProp = Get-NetAdapterAdvancedProperty -Name $nic.Name -ErrorAction SilentlyContinue
                $duplexProp = $advProp | Where-Object { $_.DisplayName -match 'Duplex|Speed.*Duplex' } | Select-Object -First 1
                if ($duplexProp) { $duplex = $duplexProp.DisplayValue }
            }
            catch { }

            $driverVer = ""
            try {
                $driverVer = (Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue |
                    Where-Object { $_.DeviceID -eq $nic.PnpDeviceId } |
                    Select-Object -First 1).DriverVersion
            }
            catch { }

            $result.Adapters += @{
                Name          = $nic.Name
                Description   = $nic.InterfaceDescription
                LinkSpeed     = $speed
                Duplex        = if ($duplex) { $duplex } else { "N/A" }
                DriverVersion = if ($driverVer) { $driverVer } else { "N/A" }
                MacAddress    = $nic.MacAddress
                MediaType     = $nic.MediaType
            }
        }
    }
    catch { }

    # ARP scan for network equipment via OUI prefix
    try {
        $arpRaw = arp -a 2>&1 | Out-String
        foreach ($aLine in ($arpRaw -split "`r?`n")) {
            if ($aLine -match '(\d+\.\d+\.\d+\.\d+)\s+([\da-f]{2}-[\da-f]{2}-[\da-f]{2})-[\da-f]{2}-[\da-f]{2}-[\da-f]{2}') {
                $ip = $Matches[1]
                $ouiPrefix = $Matches[2].ToUpper()
                if ($ouiLookup.ContainsKey($ouiPrefix)) {
                    $fullMac = ($aLine -replace '.*?(\S{17}).*', '$1').Trim()
                    $result.NetworkEquipment += @{
                        IP     = $ip
                        MAC    = $fullMac
                        Vendor = $ouiLookup[$ouiPrefix]
                    }
                }
            }
        }
    }
    catch { }

    # Analyze findings
    foreach ($adapter in $result.Adapters) {
        # Check for negotiation issues
        if ($adapter.LinkSpeed -match '(\d+)\s*(Mbps|Gbps)') {
            $speedVal = [int]$Matches[1]
            $unit = $Matches[2]
            if ($unit -eq "Gbps") { $speedVal = $speedVal * 1000 }
            if ($speedVal -le 100 -and $adapter.Duplex -match 'Half') {
                Add-Warning("NIC '$($adapter.Name)': $($adapter.LinkSpeed) Half-Duplex → kabel/poort probleem")
                Add-Evidence -Finding "Half-duplex negotiation on $($adapter.Name)" -File "23_environment.txt" -Impact "Hoog" -Certainty "Hoog"
            }
            elseif ($speedVal -le 100 -and $adapter.Description -match 'Gigabit|1Gb|2\.5G') {
                Add-Warning("NIC '$($adapter.Name)': onderhandeld op $($adapter.LinkSpeed) maar adapter is Gigabit → slechte kabel?")
            }
        }
    }

    if ($result.NetworkEquipment.Count -gt 0) {
        $vendors = ($result.NetworkEquipment | ForEach-Object { "$($_.Vendor) ($($_.IP))" }) -join ", "
        Add-Observation("Netwerkapparatuur op LAN: $vendors")
    }

    return $result
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
        [hashtable]$IPv6Status, [array]$WifiEnvironment,
        # v3.5 new params
        [hashtable]$StabilityMonitor = $null,
        [hashtable]$SplitTest = $null,
        [hashtable]$IPv6Deep = $null,
        [hashtable]$BufferbloatResult = $null,
        [hashtable]$EnvSnapshot = $null,
        [hashtable]$Segments = $null,
        [hashtable]$DnsBattleData = $null,
        [string]$CaseModeLabel = "",
        [int]$ExternalRiskScore = -1
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
    # RISICO SCORE (0-100) - gebruik extern als beschikbaar
    # =====================================================================
    # 0-10  = Gezond         (groen)
    # 11-30 = Aandachtspunt  (geel)
    # 31-60 = Probleem       (oranje)
    # 61+   = Actie nodig    (rood)

    if ($ExternalRiskScore -ge 0) {
        $riskScore = $ExternalRiskScore
    }
    else {
        $riskScore = 0

        if (-not $GatewayPing.Success) { $riskScore += 50 }
        else {
            if ($GatewayPing.LostPercent -gt 10) { $riskScore += 30 }
            elseif ($GatewayPing.LostPercent -gt 2) { $riskScore += 15 }
            elseif ($GatewayPing.LostPercent -gt 0) { $riskScore += 5 }
            if ($GatewayPing.AvgLatency -gt 50) { $riskScore += 15 }
            elseif ($GatewayPing.AvgLatency -gt 10) { $riskScore += 5 }
        }

        if (-not $InternetPing.Success) { $riskScore += 25 }
        else {
            if ($InternetPing.LostPercent -gt 5) { $riskScore += 15 }
            elseif ($InternetPing.LostPercent -gt 1) { $riskScore += 8 }
            if ($InternetPing.AvgLatency -gt 100) { $riskScore += 10 }
            elseif ($InternetPing.AvgLatency -gt 50) { $riskScore += 5 }
        }

        if ($InternetJitter -and $InternetJitter.Jitter -ge 0) {
            switch ($InternetJitter.Quality) {
                "SLECHT" { $riskScore += 15 }
                "MATIG" { $riskScore += 8 }
                "GOED" { $riskScore += 2 }
            }
        }

        if ($SpeedOK) {
            if ($DLMbps -lt 10) { $riskScore += 15 }
            elseif ($DLMbps -lt 25) { $riskScore += 10 }
            elseif ($DLMbps -lt 50) { $riskScore += 5 }
        }

        $riskScore += [Math]::Min(($Global:AnalysisResults.Issues.Count * 10), 30)
        $riskScore += [Math]::Min(($Global:AnalysisResults.Warnings.Count * 3), 15)

        if ($wifiConnected -and $WifiSignal -match "(\d+)") {
            $wSig = [int]$Matches[1]
            if ($wSig -lt 30) { $riskScore += 15 }
            elseif ($wSig -lt 50) { $riskScore += 8 }
            elseif ($wSig -lt 60) { $riskScore += 3 }
        }

        $riskScore = [Math]::Min($riskScore, 100)
        $riskScore = [Math]::Max($riskScore, 0)
    }

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
    ) | Out-File -FilePath $s -Encoding UTF8

    # Segment status matrix (altijd als beschikbaar)
    if ($Segments -and $Segments.Count -gt 0) {
        AddLine $s "-----------------------------------------------------------------"
        AddLine $s "SEGMENT STATUS"
        AddLine $s "-----------------------------------------------------------------"
        foreach ($segKey in @('LocalLAN', 'Upstream', 'DNS', 'IPv6')) {
            if ($Segments.ContainsKey($segKey)) {
                $seg = $Segments[$segKey]
                $segName = switch ($segKey) {
                    'LocalLAN' { 'LOCAL LAN ' }
                    'Upstream' { 'UPSTREAM  ' }
                    'DNS'      { 'DNS       ' }
                    'IPv6'     { 'IPv6      ' }
                }
                AddLine $s "  $($seg.Icon) $segName $($seg.Label) | $($seg.Detail)"
            }
        }
        AddLine $s ""
    }

    @(
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
    ) | Out-File -FilePath $s -Append -Encoding UTF8

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

    # DNS (beide modes nu)
    AddLine $s "-----------------------------------------------------------------"
    AddLine $s "DNS"
    AddLine $s "-----------------------------------------------------------------"
    if ($DnsResults -and $DnsResults.Count -gt 0) {
        foreach ($d in $DnsResults | Sort-Object AvgMs) {
            $dIcon = if ($d.AvgMs -le 0) { $iFail } elseif ($d.AvgMs -lt 30) { $iOK } elseif ($d.AvgMs -lt 100) { $iWarn } else { $iFail }
            $cfg = if ($d.IsConfigured) { " [IN GEBRUIK]" } else { "" }
            $val = if ($d.AvgMs -gt 0) {
                $extra = ""
                if ($d.MedianMs) { $extra = " | median $($d.MedianMs)ms" }
                if ($d.P95Ms) { $extra += " | p95 $($d.P95Ms)ms" }
                "$($d.AvgMs)ms$extra"
            }
            else { "FAILED" }
            AddLine $s "  $dIcon $($d.Server) ($($d.Label)): $val$cfg"
        }
        $fastest = $DnsResults | Where-Object { $_.AvgMs -gt 0 } | Sort-Object AvgMs | Select-Object -First 1
        if ($fastest) { AddLine $s "  Snelste: $($fastest.Label) ($($fastest.Server): $($fastest.AvgMs)ms)" }
    }
    else { AddLine $s "  DNS test niet uitgevoerd" }
    AddLine $s ""

    # Stabiliteitsmonitor (beide modes)
    if ($StabilityMonitor -and $StabilityMonitor.Samples -gt 0) {
        AddLine $s "-----------------------------------------------------------------"
        AddLine $s "STABILITEITSMONITOR ($($StabilityMonitor.DurationSec)s)"
        AddLine $s "-----------------------------------------------------------------"
        if ($StabilityMonitor.Gateway.Stats.Count -gt 0) {
            $gwS = $StabilityMonitor.Gateway.Stats
            $smIcon = if ($gwS.LossPercent -eq 0 -and $gwS.P95 -lt 30) { $iOK } elseif ($gwS.LossPercent -lt 2) { $iWarn } else { $iFail }
            AddLine $s "  $smIcon Gateway: p50 $($gwS.P50)ms | p95 $($gwS.P95)ms | p99 $($gwS.P99)ms | loss $($gwS.LossPercent)% | spikes $($gwS.Spikes)"
        }
        if ($StabilityMonitor.External.Stats.Count -gt 0) {
            $extS = $StabilityMonitor.External.Stats
            $seIcon = if ($extS.LossPercent -eq 0 -and $extS.P95 -lt 50) { $iOK } elseif ($extS.LossPercent -lt 1) { $iWarn } else { $iFail }
            AddLine $s "  $seIcon Extern:  p50 $($extS.P50)ms | p95 $($extS.P95)ms | p99 $($extS.P99)ms | loss $($extS.LossPercent)% | spikes $($extS.Spikes)"
        }
        if ($StabilityMonitor.DNS.Stats.Count -gt 0) {
            $dnsS = $StabilityMonitor.DNS.Stats
            $sdIcon = if ($dnsS.P95 -lt 100) { $iOK } elseif ($dnsS.P95 -lt 300) { $iWarn } else { $iFail }
            AddLine $s "  $sdIcon DNS:     p50 $($dnsS.P50)ms | p95 $($dnsS.P95)ms | p99 $($dnsS.P99)ms"
        }
        AddLine $s ""
    }

    # DNS Battle (beide modes)
    if ($DnsBattleData) {
        AddLine $s "-----------------------------------------------------------------"
        AddLine $s "DNS BATTLE"
        AddLine $s "-----------------------------------------------------------------"
        # System DNS
        foreach ($sys in $DnsBattleData.SystemDNS) {
            $sysIcon = if ($sys.Avg -le 0) { $iFail } elseif ($sys.P95 -lt 80) { $iOK } elseif ($sys.P95 -lt 200) { $iWarn } else { $iFail }
            $sysVal = if ($sys.Avg -gt 0) { "median $($sys.Median)ms | p95 $($sys.P95)ms" } else { "FAILED" }
            AddLine $s "  $sysIcon $($sys.Server) (systeem): $sysVal"
        }
        # Best public
        $bestPub = $DnsBattleData.PublicDNS | Where-Object { $_.Avg -gt 0 } | Sort-Object Median | Select-Object -First 1
        if ($bestPub) {
            AddLine $s "  $iOK Snelste publiek: $($bestPub.Server) ($($bestPub.Label)) median $($bestPub.Median)ms"
        }
        AddLine $s ""
    }

    # Full-only secties
    if ($Full) {
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
        AddLine $s "SERVICES$(if ($CaseModeLabel) { " ($CaseModeLabel)" })"
        AddLine $s "-----------------------------------------------------------------"
        if ($ServiceResults -and $ServiceResults.Count -gt 0) {
            $okCount = ($ServiceResults | Where-Object { $_.Reachable }).Count
            AddLine $s "  $okCount/$($ServiceResults.Count) bereikbaar"
            # Groepen op categorie als beschikbaar
            $hasCat = ($ServiceResults | Where-Object { $_.Category }) | Select-Object -First 1
            if ($hasCat) {
                $cats = $ServiceResults | Group-Object { $_.Category } | Sort-Object Name
                foreach ($cat in $cats) {
                    $catOk = ($cat.Group | Where-Object { $_.Reachable }).Count
                    AddLine $s "  [$($cat.Name)] $catOk/$($cat.Count)"
                    foreach ($sv in $cat.Group) {
                        $sIcon = if ($sv.Reachable) { $iOK } else { $iFail }
                        $sTime = if ($sv.LatencyMs -gt 0) { "$($sv.LatencyMs)ms" } else { "N/A" }
                        AddLine $s "    $sIcon $($sv.Name): $sTime"
                    }
                }
            }
            else {
                foreach ($sv in $ServiceResults) {
                    $sIcon = if ($sv.Reachable) { $iOK } else { $iFail }
                    $sTime = if ($sv.LatencyMs -gt 0) { "$($sv.LatencyMs)ms" } else { "N/A" }
                    AddLine $s "  $sIcon $($sv.Name): $sTime"
                }
            }
        }
        AddLine $s ""

        # Bufferbloat
        if ($BufferbloatResult) {
            AddLine $s "-----------------------------------------------------------------"
            AddLine $s "BUFFERBLOAT"
            AddLine $s "-----------------------------------------------------------------"
            $bbIcon = switch ($BufferbloatResult.Grade) { "A" { $iOK } "B" { $iOK } "C" { $iWarn } "F" { $iFail } default { $iWarn } }
            AddLine $s "  $bbIcon Grade $($BufferbloatResult.Grade): +$($BufferbloatResult.Delta)ms onder load (idle: $($BufferbloatResult.IdleLatency)ms)"
            AddLine $s ""
        }
    }

    # Split-test (beide modes)
    if ($SplitTest) {
        AddLine $s "-----------------------------------------------------------------"
        AddLine $s "LOKALISATIE (SPLIT-TEST)"
        AddLine $s "-----------------------------------------------------------------"
        $spIcon = switch -Wildcard ($SplitTest.Verdict) {
            "STABLE" { $iOK } "LOCAL*" { $iFail } "ISP*" { $iFail } default { $iWarn }
        }
        AddLine $s "  $spIcon Verdict: $($SplitTest.Verdict)"
        AddLine $s "  $($SplitTest.VerdictDetail)"
        AddLine $s ""
    }

    # IPv6 Deep (beide modes)
    if ($IPv6Deep) {
        AddLine $s "-----------------------------------------------------------------"
        AddLine $s "IPv6"
        AddLine $s "-----------------------------------------------------------------"
        $v6Icon = switch ($IPv6Deep.Status) {
            "VOLLEDIG_WERKEND" { $iOK } "BROKEN" { $iFail } default { $iWarn }
        }
        AddLine $s "  $v6Icon $($IPv6Deep.Status): $($IPv6Deep.Detail)"
        AddLine $s ""
    }

    # Environment snapshot (beide modes)
    if ($EnvSnapshot -and $EnvSnapshot.Adapters.Count -gt 0) {
        AddLine $s "-----------------------------------------------------------------"
        AddLine $s "OMGEVING"
        AddLine $s "-----------------------------------------------------------------"
        foreach ($nic in $EnvSnapshot.Adapters) {
            AddLine $s "  $($nic.Name): $($nic.LinkSpeed) $(if ($nic.Duplex -eq 'Half Duplex') { "$iFail HALF DUPLEX" } else { '' })"
        }
        if ($EnvSnapshot.NetworkEquipment.Count -gt 0) {
            AddLine $s "  Apparatuur:"
            foreach ($eq in $EnvSnapshot.NetworkEquipment | Select-Object -First 5) {
                AddLine $s "    $($eq.Vendor) ($($eq.IP))"
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
    $fileRef = if ($Full) { "01-20 + 98-99" } else { "01-13 + 17-20 + 98-99" }
    AddLine $s "Bestanden: $fileRef"
    if ($CaseModeLabel) { AddLine $s "Case mode: $CaseModeLabel" }
    AddLine $s "================================================================="
}

# =========================================================================
# MODULE: NETWERK SEGMENT CONCLUSIE
# =========================================================================
# Berekent segment status: LOCAL LAN / UPSTREAM / DNS / IPv6
# Elke segment krijgt: icon, label, detail string

function Build-NetworkConclusion {
    param(
        [hashtable]$GatewayPing,
        [hashtable]$StabilityMonitor,
        [hashtable]$DnsBattle,
        [hashtable]$IPv6Deep,
        [hashtable]$SplitTest,
        [hashtable]$BufferbloatResult
    )

    $segments = @{}

    # ---- LOCAL LAN ----
    $lanIcon = $iOK; $lanLabel = "STABIEL"; $lanDetail = ""
    $gwS = if ($StabilityMonitor -and $StabilityMonitor.Gateway.Stats.Count -gt 0) { $StabilityMonitor.Gateway.Stats } else { $null }

    if (-not $GatewayPing -or -not $GatewayPing.Success) {
        $lanIcon = $iFail; $lanLabel = "ONBEREIKBAAR"; $lanDetail = "gateway niet bereikbaar"
    }
    elseif ($gwS) {
        $lanDetail = "loss $($gwS.LossPercent)%, p95 $($gwS.P95)ms"
        if ($gwS.LossPercent -gt 2 -or ($StabilityMonitor.Gateway.Outages -gt 0)) {
            $lanIcon = $iFail; $lanLabel = "INSTABIEL"
        }
        elseif ($gwS.LossPercent -gt 0 -or $gwS.P95 -gt 30) {
            $lanIcon = $iWarn; $lanLabel = "SPIKES"
        }
    }
    else {
        $lanDetail = "loss $($GatewayPing.LostPercent)%, avg $($GatewayPing.AvgLatency)ms"
        if ($GatewayPing.LostPercent -gt 5) { $lanIcon = $iFail; $lanLabel = "INSTABIEL" }
        elseif ($GatewayPing.LostPercent -gt 0 -or $GatewayPing.AvgLatency -gt 10) { $lanIcon = $iWarn; $lanLabel = "SPIKES" }
    }
    $segments.LocalLAN = @{ Icon = $lanIcon; Label = $lanLabel; Detail = $lanDetail }

    # ---- UPSTREAM ----
    $upIcon = $iOK; $upLabel = "STABIEL"; $upDetail = ""
    $extS = if ($StabilityMonitor -and $StabilityMonitor.External.Stats.Count -gt 0) { $StabilityMonitor.External.Stats } else { $null }

    if ($extS) {
        $upDetail = "p99 $($extS.P99)ms, outages $($StabilityMonitor.External.Outages)"
        if ($extS.LossPercent -gt 2 -or $StabilityMonitor.External.Outages -gt 0) {
            $upIcon = $iFail; $upLabel = "INSTABIEL"
        }
        elseif ($extS.LossPercent -gt 0.5 -or $extS.P99 -gt 200) {
            $upIcon = $iWarn; $upLabel = "SPIKES"
        }
        # Bufferbloat adds to upstream assessment
        if ($BufferbloatResult -and $BufferbloatResult.Grade -eq "F") {
            if ($upLabel -eq "STABIEL") { $upIcon = $iWarn; $upLabel = "BUFFERBLOAT" }
            $upDetail += ", bufferbloat grade F"
        }
    }
    else {
        $upDetail = "geen stabiliteitsmonitor data"
        $upIcon = $iWarn; $upLabel = "ONBEKEND"
    }
    $segments.Upstream = @{ Icon = $upIcon; Label = $upLabel; Detail = $upDetail }

    # ---- DNS ----
    $dnsIcon = $iOK; $dnsLabel = "STABIEL"; $dnsDetail = ""

    if ($DnsBattle -and $DnsBattle.SystemDNS.Count -gt 0) {
        $bestSys = $DnsBattle.SystemDNS | Where-Object { $_.Avg -gt 0 } | Sort-Object Avg | Select-Object -First 1
        $bestPub = $DnsBattle.PublicDNS | Where-Object { $_.Avg -gt 0 } | Sort-Object Avg | Select-Object -First 1
        $totalTimeouts = ($DnsBattle.SystemDNS | ForEach-Object { $_.Timeouts } | Measure-Object -Sum).Sum

        if ($bestSys) {
            $dnsDetail = "timeouts $totalTimeouts, p95 $($bestSys.P95)ms"
            if ($bestPub) { $dnsDetail += "; public DNS p95 $($bestPub.P95)ms" }

            if ($totalTimeouts -gt 2 -or $bestSys.P95 -gt 300) {
                $dnsIcon = $iFail; $dnsLabel = "INSTABIEL"
            }
            elseif ($totalTimeouts -gt 0 -or $bestSys.P95 -gt 100) {
                $dnsIcon = $iWarn; $dnsLabel = "TRAAG"
            }
        }
        else {
            $dnsIcon = $iFail; $dnsLabel = "UNREACHABLE"; $dnsDetail = "alle DNS queries gefaald"
        }
    }
    else {
        $dnsDetail = "geen DNS battle data"
        $dnsIcon = $iWarn; $dnsLabel = "ONBEKEND"
    }
    $segments.DNS = @{ Icon = $dnsIcon; Label = $dnsLabel; Detail = $dnsDetail }

    # ---- IPv6 ----
    $v6Icon = $iOK; $v6Label = "VOLLEDIG"; $v6Detail = ""

    if (-not $IPv6Deep -or $IPv6Deep.Status -eq "NIET_BESCHIKBAAR" -or $IPv6Deep.Status -eq "NIET_GETEST") {
        $v6Icon = $iWarn; $v6Label = "NIET BESCHIKBAAR"
        $v6Detail = "alleen IPv4"
    }
    elseif ($IPv6Deep.Status -eq "VOLLEDIG_WERKEND") {
        $v6Detail = "ping ok, AAAA ok"
        if ($IPv6Deep.HTTPIPv6) { $v6Detail += ", HTTP ok" }
    }
    elseif ($IPv6Deep.Status -eq "GEDEELTELIJK") {
        $v6Icon = $iWarn; $v6Label = "PARTIAL"
        $pingOK = if ($IPv6Deep.PingIPv6) { "ok" } else { "fail" }
        $aaaaOK = if ($IPv6Deep.DNSAAAA) { "ok" } else { "fail" }
        $v6Detail = "AAAA $aaaaOK, ping -6 $pingOK"
    }
    elseif ($IPv6Deep.Status -eq "BROKEN") {
        $v6Icon = $iFail; $v6Label = "BROKEN"
        $v6Detail = "adres aanwezig, geen connectiviteit"
    }
    $segments.IPv6 = @{ Icon = $v6Icon; Label = $v6Label; Detail = $v6Detail }

    return $segments
}

# =========================================================================
# MODULE: RAPPORT - ADVIES GENERATIE
# =========================================================================

function Generate-AdviceReport {
    param(
        [int]$RiskScore = 0,
        [string]$TopConclusion = "",
        [hashtable]$Segments = @{}
    )
    $c = @()
    $c += "================================================================="
    $c += "SluisICT - ADVIES RAPPORT"
    $c += "================================================================="
    $c += "Datum: $(Get-Date -Format 'dd-MM-yyyy HH:mm')"
    $c += "Mode:  $modeName"
    if ($ClientName) { $c += "Klant: $ClientName" }
    $c += ""

    # ----- SCORE -----
    $riskLabel = switch ($true) {
        ($RiskScore -le 10) { "GEZOND" }
        ($RiskScore -le 30) { "AANDACHTSPUNT" }
        ($RiskScore -le 60) { "PROBLEEM" }
        default { "ACTIE NODIG" }
    }
    $c += "Score: $RiskScore/100 ($riskLabel)"
    $c += ""

    # ----- SEGMENT STATUS MATRIX -----
    $c += "-----------------------------------------------------------------"
    $c += "NETWERK SEGMENT STATUS"
    $c += "-----------------------------------------------------------------"

    if ($Segments.LocalLAN) {
        $c += "LOCAL LAN   : $($Segments.LocalLAN.Icon) $($Segments.LocalLAN.Label.PadRight(12)) ($($Segments.LocalLAN.Detail))"
    }
    if ($Segments.Upstream) {
        $c += "UPSTREAM    : $($Segments.Upstream.Icon) $($Segments.Upstream.Label.PadRight(12)) ($($Segments.Upstream.Detail))"
    }
    if ($Segments.DNS) {
        $c += "DNS         : $($Segments.DNS.Icon) $($Segments.DNS.Label.PadRight(12)) ($($Segments.DNS.Detail))"
    }
    if ($Segments.IPv6) {
        $c += "IPv6        : $($Segments.IPv6.Icon) $($Segments.IPv6.Label.PadRight(12)) ($($Segments.IPv6.Detail))"
    }
    $c += ""

    # ----- HOOFDPROBLEEM -----
    $c += "-----------------------------------------------------------------"
    $c += "HOOFDPROBLEEM"
    $c += "-----------------------------------------------------------------"
    if ($TopConclusion) {
        $c += $TopConclusion
    }
    else {
        $c += "$iOK Geen significant probleem gedetecteerd."
    }
    $c += ""

    # ----- TOP 3 BEVINDINGEN -----
    if ($Global:AnalysisResults.Evidence.Count -gt 0 -or $Global:AnalysisResults.Issues.Count -gt 0) {
        $c += "-----------------------------------------------------------------"
        $c += "TOP 3 BEVINDINGEN"
        $c += "-----------------------------------------------------------------"

        $findings = @()

        # Evidence items (have Impact/Certainty)
        foreach ($ev in $Global:AnalysisResults.Evidence) {
            $impactRank = switch ($ev.Impact) { "Hoog" { 3 } "Middel" { 2 } default { 1 } }
            $certRank = switch ($ev.Certainty) { "Hoog" { 3 } "Middel" { 2 } default { 1 } }
            $findings += @{
                Text      = $ev.Finding
                File      = $ev.File
                Impact    = $ev.Impact
                Certainty = $ev.Certainty
                Rank      = ($impactRank * 2 + $certRank)
            }
        }

        # Issues without explicit evidence
        $evidenceFindings = @($Global:AnalysisResults.Evidence | ForEach-Object { $_.Finding })
        foreach ($iss in $Global:AnalysisResults.Issues) {
            $alreadyCovered = $false
            foreach ($ef in $evidenceFindings) {
                if ($iss -match [regex]::Escape($ef) -or $ef -match [regex]::Escape(($iss -replace '^[^:]+:\s*', ''))) {
                    $alreadyCovered = $true; break
                }
            }
            if (-not $alreadyCovered) {
                $findings += @{
                    Text = $iss; File = ""; Impact = "Hoog"; Certainty = "Middel"
                    Rank = 5
                }
            }
        }

        $topFindings = $findings | Sort-Object { $_.Rank } -Descending | Select-Object -First 3
        $nr = 0
        foreach ($f in $topFindings) {
            $nr++
            $c += "${nr}. $($f.Text)"
            if ($f.File) { $c += "   Evidence: $($f.File) | Impact: $($f.Impact) | Zekerheid: $($f.Certainty)" }
        }
        $c += ""
    }

    # ----- AANBEVOLEN ACTIES A/B/C -----
    if ($Global:AnalysisResults.AdviceItems.Count -gt 0) {
        $c += "-----------------------------------------------------------------"
        $c += "AANBEVOLEN ACTIES"
        $c += "-----------------------------------------------------------------"

        $sortedAdvice = $Global:AnalysisResults.AdviceItems | Sort-Object {
            switch ($_.Impact) { "Hoog" { 3 } "Middel" { 2 } default { 1 } }
        } -Descending | Select-Object -First 5

        $letter = [char]65  # 'A'
        foreach ($item in $sortedAdvice) {
            $c += ""
            $c += "$([char]$letter)) $($item.Problem)"
            $c += "   Impact: $($item.Impact) | Zekerheid: $($item.Certainty) | Moeite: $($item.Effort)"
            $c += "   Oorzaak: $($item.Cause)"
            $stepNr = 0
            foreach ($step in $item.Steps) {
                $stepNr++
                $c += "   $stepNr. $step"
            }
            if ($item.SourceFiles -and $item.SourceFiles.Count -gt 0) {
                $c += "   Bewijs: $($item.SourceFiles -join ', ')"
            }
            $letter++
        }
        $c += ""
    }
    else {
        $c += "$iOK Geen problemen gevonden die actie vereisen."
        $c += ""
    }

    # ----- EVIDENCE -----
    if ($Global:AnalysisResults.Evidence.Count -gt 0) {
        $c += "-----------------------------------------------------------------"
        $c += "EVIDENCE"
        $c += "-----------------------------------------------------------------"
        foreach ($ev in $Global:AnalysisResults.Evidence) {
            $c += "  [$($ev.Impact)] $($ev.Finding) -> $($ev.File) (zekerheid: $($ev.Certainty))"
        }
        $c += ""
    }

    # ----- OBSERVATIES -----
    if ($Global:AnalysisResults.Observations.Count -gt 0) {
        $c += "-----------------------------------------------------------------"
        $c += "OBSERVATIES"
        $c += "-----------------------------------------------------------------"
        foreach ($obs in $Global:AnalysisResults.Observations) { $c += "  - $obs" }
        $c += ""
    }

    # ----- AANDACHTSPUNTEN -----
    if ($Global:AnalysisResults.Warnings.Count -gt 0) {
        $c += "-----------------------------------------------------------------"
        $c += "AANDACHTSPUNTEN"
        $c += "-----------------------------------------------------------------"
        foreach ($w in $Global:AnalysisResults.Warnings) { $c += "  $iWarn $w" }
        $c += ""
    }

    # ----- CASE MODE SPECIFIEK -----
    if ($CaseMode) {
        $c += "-----------------------------------------------------------------"
        $c += "CASE MODE: $CaseMode"
        $c += "-----------------------------------------------------------------"
        switch ($CaseMode) {
            "VoIP" {
                $c += "  Focus: jitter, packet loss, bufferbloat"
                $c += "  Drempels: jitter <15ms, loss <1%, bufferbloat delta <30ms"
                $c += "  Let op: QoS/SQM op router, upload bandbreedte"
            }
            "Gaming" {
                $c += "  Focus: latency spikes, p95/p99, route stabiliteit"
                $c += "  Drempels: p95 <50ms, geen packet loss, stabiele route"
                $c += "  Let op: NAT type (open/moderate), port forwarding, CGNAT"
            }
            "WorkFromHome" {
                $c += "  Focus: DNS betrouwbaarheid, TLS connectiviteit, Teams/VPN"
                $c += "  Drempels: DNS p95 <200ms, alle cloud services bereikbaar"
                $c += "  Let op: split-tunnel VPN, DNS filtering, proxy settings"
            }
        }
        $c += ""
    }

    $c += "================================================================="
    $c += "SluisICT - Toolkit v3.5"
    $c += "================================================================="

    OutFile "99_advies.txt" $c
}

# =========================================================================
# MODULE: OUTPUT ANNOTATIES (POST-PROCESSING)
# =========================================================================
# Voegt inline annotaties toe aan output bestanden: "  <--- UITLEG"
# Ruwe data blijft intact; alleen suffix rechts op matchende regels.
# Thresholds worden geladen uit patterns.json benchmarks.
# =========================================================================

function Add-FileAnnotations {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][scriptblock]$Annotator,
        [hashtable]$Benchmarks = @{},
        [int]$MaxWidth = 120,
        [int]$MinPad = 2
    )

    if (-not (Test-Path $Path)) { return 0 }

    $lines = @(Get-Content -Path $Path -Encoding UTF8 -ErrorAction SilentlyContinue)
    if ($lines.Count -eq 0) { return 0 }

    $annotations = @(& $Annotator $lines $Benchmarks)
    $annotated = 0
    $result = [System.Collections.Generic.List[string]]::new()

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        $ann = if ($i -lt $annotations.Count) { $annotations[$i] } else { $null }

        if ($ann -and $line -notmatch '<---') {
            $suffix = " <--- $ann"
            $pad = [math]::Max($MinPad, $MaxWidth - $line.Length - $suffix.Length)
            $pad = [math]::Max($pad, $MinPad)
            $result.Add("$line$(' ' * $pad)$suffix")
            $annotated++
        }
        else {
            $result.Add($line)
        }
    }

    if ($annotated -gt 0) {
        $result | Set-Content -Path $Path -Encoding UTF8
    }

    return $annotated
}

function Invoke-OutputAnnotations {
    param(
        [string]$OutDir,
        [object]$Benchmarks,
        [switch]$FullMode
    )

    # Converteer PSCustomObject benchmarks naar hashtable
    $bm = @{}
    if ($Benchmarks) {
        $Benchmarks.PSObject.Properties | ForEach-Object { $bm[$_.Name] = $_.Value }
    }

    $totalAnnotated = 0
    $filesAnnotated = 0

    # -----------------------------------------------------------------
    # 02_routes.txt
    # -----------------------------------------------------------------
    $count = Add-FileAnnotations -Path (Join-Path $OutDir "02_routes.txt") -Benchmarks $bm -Annotator {
        param([string[]]$lines, [hashtable]$bm)
        $ann = @($null) * $lines.Count

        # Pre-pass: tel default routes
        $defaultCount = @($lines | Where-Object { $_ -match '^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+\d' }).Count
        $defaultSeen = 0

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $l = $lines[$i]

            if ($l -match '^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)') {
                $defaultSeen++
                if ($defaultCount -gt 1 -and $defaultSeen -gt 1) {
                    $ann[$i] = "EXTRA DEFAULT ROUTE (DUBBEL GATEWAY)"
                }
                else {
                    $ann[$i] = "DEFAULT ROUTE via $($Matches[1])"
                }
            }
            elseif ($l -match '169\.254\.' -and $l -match '\d+\.\d+\.\d+\.\d+') {
                $ann[$i] = "APIPA (GEEN DHCP)"
            }
            elseif ($l -match '172\.1[7-9]\.|172\.2[0-9]\.|172\.3[01]\.' -and $l -match 'On-link') {
                $ann[$i] = "VIRTUEEL (HYPER-V/DOCKER)"
            }
            elseif ($l -match '^\s*127\.\d' -and $l -match 'On-link') {
                $ann[$i] = "LOOPBACK"
            }
            elseif ($l -match '^\s*224\.' -or $l -match '^\s*239\.') {
                $ann[$i] = "MULTICAST"
            }
            elseif ($l -match '^\s*255\.255\.255\.255') {
                $ann[$i] = "BROADCAST"
            }
        }

        return $ann
    }
    if ($count -gt 0) { $totalAnnotated += $count; $filesAnnotated++ }

    # -----------------------------------------------------------------
    # 05_dns_nslookup.txt
    # -----------------------------------------------------------------
    $count = Add-FileAnnotations -Path (Join-Path $OutDir "05_dns_nslookup.txt") -Benchmarks $bm -Annotator {
        param([string[]]$lines, [hashtable]$bm)
        $ann = @($null) * $lines.Count

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $l = $lines[$i]

            if ($l -match '^Server:\s+(.+)') {
                $ann[$i] = "DNS SERVER"
            }
            elseif ($l -match 'timed?\s*out|timeout') {
                $ann[$i] = "DNS TIMEOUT (FAIL)"
            }
            elseif ($l -match '^Name:\s+(.+)') {
                $ann[$i] = "RESOLVED (OK)"
            }
            elseif ($l -match "can't find|NXDOMAIN|SERVFAIL") {
                $ann[$i] = "NIET GEVONDEN (FAIL)"
            }
            elseif ($l -match '^Addresses:') {
                $ann[$i] = "RESOLVED (OK)"
            }
        }

        return $ann
    }
    if ($count -gt 0) { $totalAnnotated += $count; $filesAnnotated++ }

    # -----------------------------------------------------------------
    # 06_ping_gateway.txt
    # -----------------------------------------------------------------
    $count = Add-FileAnnotations -Path (Join-Path $OutDir "06_ping_gateway.txt") -Benchmarks $bm -Annotator {
        param([string[]]$lines, [hashtable]$bm)
        $ann = @($null) * $lines.Count
        $gwLatOK = if ($bm.gateway_latency_ok) { $bm.gateway_latency_ok } else { 5 }
        $gwLatWarn = if ($bm.gateway_latency_warn) { $bm.gateway_latency_warn } else { 10 }
        $lossOK = if ($bm.packet_loss_acceptable) { $bm.packet_loss_acceptable } else { 1 }
        $lossWarn = if ($bm.packet_loss_warning) { $bm.packet_loss_warning } else { 5 }
        $spikeOK = if ($bm.ping_spike_ok) { $bm.ping_spike_ok } else { 20 }
        $spikeWarn = if ($bm.ping_spike_warn) { $bm.ping_spike_warn } else { 50 }

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $l = $lines[$i]

            if ($l -match 'Request timed out|Verzoek verlopen|Destination host unreachable') {
                $ann[$i] = "TIMEOUT/ONBEREIKBAAR"
            }
            elseif ($l -match 'Lost\s*=\s*\d+\s*\((\d+)%\s*(?:loss|verlies)\)') {
                $loss = [int]$Matches[1]
                if ($loss -eq 0) { $ann[$i] = "OK loss 0%" }
                elseif ($loss -le $lossOK) { $ann[$i] = "OK loss ${loss}% (<=${lossOK}%)" }
                elseif ($loss -le $lossWarn) { $ann[$i] = "LET OP loss ${loss}% (>${lossOK}%)" }
                else { $ann[$i] = "SLECHT loss ${loss}% (>${lossWarn}%)" }
            }
            elseif ($l -match '(?:Minimum|minimum)\s*=\s*(\d+)ms.*(?:Maximum|maximum)\s*=\s*(\d+)ms.*(?:Average|gemiddeld)\s*=\s*(\d+)ms') {
                $mn = [int]$Matches[1]; $mx = [int]$Matches[2]; $av = [int]$Matches[3]
                $parts = @()
                if ($av -le $gwLatOK) { $parts += "avg ${av}ms OK" }
                elseif ($av -le $gwLatWarn) { $parts += "avg ${av}ms LET OP (>${gwLatOK}ms)" }
                else { $parts += "avg ${av}ms HOOG (>${gwLatWarn}ms)" }
                if ($mx -gt $spikeWarn) { $parts += "SPIKE ${mx}ms!" }
                elseif ($mx -gt $spikeOK) { $parts += "spike ${mx}ms" }
                $ann[$i] = $parts -join " | "
            }
            elseif ($l -match 'Pinging\s+([\d.]+)') {
                $ann[$i] = "GATEWAY"
            }
        }

        return $ann
    }
    if ($count -gt 0) { $totalAnnotated += $count; $filesAnnotated++ }

    # -----------------------------------------------------------------
    # 07_ping_8.8.8.8.txt
    # -----------------------------------------------------------------
    $count = Add-FileAnnotations -Path (Join-Path $OutDir "07_ping_8.8.8.8.txt") -Benchmarks $bm -Annotator {
        param([string[]]$lines, [hashtable]$bm)
        $ann = @($null) * $lines.Count
        $latExc = if ($bm.latency_excellent) { $bm.latency_excellent } else { 10 }
        $latGood = if ($bm.latency_good) { $bm.latency_good } else { 30 }
        $latPoor = if ($bm.latency_poor) { $bm.latency_poor } else { 100 }
        $lossOK = if ($bm.packet_loss_acceptable) { $bm.packet_loss_acceptable } else { 1 }
        $lossWarn = if ($bm.packet_loss_warning) { $bm.packet_loss_warning } else { 5 }
        $spikeOK = if ($bm.ping_spike_ok) { $bm.ping_spike_ok } else { 20 }
        $spikeWarn = if ($bm.ping_spike_warn) { $bm.ping_spike_warn } else { 50 }

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $l = $lines[$i]

            if ($l -match 'Request timed out|Verzoek verlopen|Destination host unreachable') {
                $ann[$i] = "TIMEOUT/ONBEREIKBAAR"
            }
            elseif ($l -match 'Lost\s*=\s*\d+\s*\((\d+)%\s*(?:loss|verlies)\)') {
                $loss = [int]$Matches[1]
                if ($loss -eq 0) { $ann[$i] = "OK loss 0%" }
                elseif ($loss -le $lossOK) { $ann[$i] = "OK loss ${loss}% (<=${lossOK}%)" }
                elseif ($loss -le $lossWarn) { $ann[$i] = "LET OP loss ${loss}% (>${lossOK}%)" }
                else { $ann[$i] = "SLECHT loss ${loss}% (>${lossWarn}%)" }
            }
            elseif ($l -match '(?:Minimum|minimum)\s*=\s*(\d+)ms.*(?:Maximum|maximum)\s*=\s*(\d+)ms.*(?:Average|gemiddeld)\s*=\s*(\d+)ms') {
                $mn = [int]$Matches[1]; $mx = [int]$Matches[2]; $av = [int]$Matches[3]
                $parts = @()
                if ($av -le $latExc) { $parts += "avg ${av}ms UITSTEKEND" }
                elseif ($av -le $latGood) { $parts += "avg ${av}ms GOED (<${latGood}ms)" }
                elseif ($av -le $latPoor) { $parts += "avg ${av}ms MATIG" }
                else { $parts += "avg ${av}ms SLECHT (>${latPoor}ms)" }
                if ($mx -gt $spikeWarn) { $parts += "SPIKE ${mx}ms!" }
                elseif ($mx -gt $spikeOK) { $parts += "avg ${av}ms spike ${mx}ms" }
                $ann[$i] = $parts -join " | "
            }
            elseif ($l -match 'Pinging\s+([\d.]+)') {
                $ann[$i] = "INTERNET (Google DNS)"
            }
        }

        return $ann
    }
    if ($count -gt 0) { $totalAnnotated += $count; $filesAnnotated++ }

    # -----------------------------------------------------------------
    # 08_tracert_8.8.8.8.txt
    # -----------------------------------------------------------------
    $count = Add-FileAnnotations -Path (Join-Path $OutDir "08_tracert_8.8.8.8.txt") -Benchmarks $bm -Annotator {
        param([string[]]$lines, [hashtable]$bm)
        $ann = @($null) * $lines.Count

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $l = $lines[$i]

            if ($l -match '^\s*\d+\s.*\*\s.*\*\s.*\*') {
                $ann[$i] = "TIMEOUT (ICMP gefilterd)"
            }
            elseif ($l -match '^\s*\d+\s' -and $l -match '(\d+\.\d+\.\d+\.\d+)') {
                $ip = ([regex]::Matches($l, '(\d+\.\d+\.\d+\.\d+)') | Select-Object -Last 1).Value
                if ($ip -match '^10\.' -or $ip -match '^192\.168\.' -or $ip -match '^172\.(1[6-9]|2[0-9]|3[01])\.') {
                    $ann[$i] = "PRIVATE IP (NAT)"
                }
                elseif ($ip -match '^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.') {
                    $ann[$i] = "CGNAT (ISP NAT)"
                }
                else {
                    $ann[$i] = "PUBLIC"
                }
            }
        }

        return $ann
    }
    if ($count -gt 0) { $totalAnnotated += $count; $filesAnnotated++ }

    # -----------------------------------------------------------------
    # 12_speedtest_readable.txt
    # -----------------------------------------------------------------
    $count = Add-FileAnnotations -Path (Join-Path $OutDir "12_speedtest_readable.txt") -Benchmarks $bm -Annotator {
        param([string[]]$lines, [hashtable]$bm)
        $ann = @($null) * $lines.Count
        $dlExc = if ($bm.download_excellent) { $bm.download_excellent } else { 200 }
        $dlGood = if ($bm.download_good) { $bm.download_good } else { 100 }
        $dlMin = if ($bm.download_minimum) { $bm.download_minimum } else { 25 }
        $ulExc = if ($bm.upload_excellent) { $bm.upload_excellent } else { 100 }
        $ulGood = if ($bm.upload_good) { $bm.upload_good } else { 40 }
        $ulMin = if ($bm.upload_minimum) { $bm.upload_minimum } else { 10 }
        $latExc = if ($bm.latency_excellent) { $bm.latency_excellent } else { 10 }
        $latGood = if ($bm.latency_good) { $bm.latency_good } else { 30 }
        $latPoor = if ($bm.latency_poor) { $bm.latency_poor } else { 100 }

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $l = $lines[$i]

            if ($l -match 'Download:\s+([\d.]+)\s*Mbps') {
                $val = [double]$Matches[1]
                if ($val -ge $dlExc) { $ann[$i] = "UITSTEKEND (>$($dlExc) Mbps)" }
                elseif ($val -ge $dlGood) { $ann[$i] = "GOED (>$($dlGood) Mbps)" }
                elseif ($val -ge $dlMin) { $ann[$i] = "MATIG (>$($dlMin) minimum)" }
                else { $ann[$i] = "SLECHT (<$($dlMin) Mbps minimum)" }
            }
            elseif ($l -match 'Upload:\s+([\d.]+)\s*Mbps') {
                $val = [double]$Matches[1]
                if ($val -ge $ulExc) { $ann[$i] = "UITSTEKEND (>$($ulExc) Mbps)" }
                elseif ($val -ge $ulGood) { $ann[$i] = "GOED (>$($ulGood) Mbps)" }
                elseif ($val -ge $ulMin) { $ann[$i] = "MATIG (>$($ulMin) minimum)" }
                else { $ann[$i] = "SLECHT (<$($ulMin) Mbps minimum)" }
            }
            elseif ($l -match 'Latency:\s+([\d.]+)\s*ms') {
                $val = [double]$Matches[1]
                if ($val -le $latExc) { $ann[$i] = "UITSTEKEND (<$($latExc)ms)" }
                elseif ($val -le $latGood) { $ann[$i] = "GOED (<$($latGood)ms)" }
                elseif ($val -le $latPoor) { $ann[$i] = "MATIG" }
                else { $ann[$i] = "SLECHT (>$($latPoor)ms)" }
            }
        }

        return $ann
    }
    if ($count -gt 0) { $totalAnnotated += $count; $filesAnnotated++ }

    # -----------------------------------------------------------------
    # 17_security_adapters.txt
    # -----------------------------------------------------------------
    $count = Add-FileAnnotations -Path (Join-Path $OutDir "17_security_adapters.txt") -Benchmarks $bm -Annotator {
        param([string[]]$lines, [hashtable]$bm)
        $ann = @($null) * $lines.Count

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $l = $lines[$i]

            if ($l -match '^\s*\[FYSIEK\]') {
                $ann[$i] = "ACTIEF VOOR DIAGNOSE"
            }
            elseif ($l -match '^\s*\[VIRTUEEL\]') {
                $ann[$i] = "GENEGEERD VOOR DIAGNOSE"
            }
            elseif ($l -match '^\s*\[VPN\]') {
                $ann[$i] = "VPN ACTIEF (CHECK ROUTING)"
            }
            elseif ($l -match 'Dual-stack actief') {
                $ann[$i] = "IPv4 + IPv6 (OK)"
            }
            elseif ($l -match 'Niet beschikbaar') {
                $ann[$i] = "ALLEEN IPv4"
            }
        }

        return $ann
    }
    if ($count -gt 0) { $totalAnnotated += $count; $filesAnnotated++ }

    # -----------------------------------------------------------------
    # 18_jitter_analysis.txt
    # -----------------------------------------------------------------
    $count = Add-FileAnnotations -Path (Join-Path $OutDir "18_jitter_analysis.txt") -Benchmarks $bm -Annotator {
        param([string[]]$lines, [hashtable]$bm)
        $ann = @($null) * $lines.Count
        $jExc = if ($bm.jitter_excellent) { $bm.jitter_excellent } else { 5 }
        $jGood = if ($bm.jitter_good) { $bm.jitter_good } else { 15 }
        $jPoor = if ($bm.jitter_poor) { $bm.jitter_poor } else { 30 }

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $l = $lines[$i]

            if ($l -match 'Gemiddeld:\s*([\d.]+)ms') {
                $val = [double]$Matches[1]
                if ($val -le $jExc) { $ann[$i] = "STABIEL (<${jExc}ms)" }
                elseif ($val -le $jGood) { $ann[$i] = "MERKBAAR (${jExc}-${jGood}ms)" }
                elseif ($val -le $jPoor) { $ann[$i] = "MATIG (${jGood}-${jPoor}ms)" }
                else { $ann[$i] = "SLECHT (>${jPoor}ms) VoIP/gaming probleem" }
            }
            elseif ($l -match 'Kwaliteit:\s*(\w+)') {
                $q = $Matches[1]
                $ann[$i] = switch ($q) {
                    "UITSTEKEND" { "videobellen/gaming OK" }
                    "GOED" { "videobellen OK" }
                    "MATIG" { "videobellen kan haperen" }
                    "SLECHT" { "VoIP/gaming onbruikbaar" }
                    default { $null }
                }
            }
        }

        return $ann
    }
    if ($count -gt 0) { $totalAnnotated += $count; $filesAnnotated++ }

    # -----------------------------------------------------------------
    # 03_arp.txt
    # -----------------------------------------------------------------
    $count = Add-FileAnnotations -Path (Join-Path $OutDir "03_arp.txt") -Benchmarks $bm -Annotator {
        param([string[]]$lines, [hashtable]$bm)
        $ann = @($null) * $lines.Count

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $l = $lines[$i]

            if ($l -match '169\.254\.\d+\.\d+') {
                $ann[$i] = "APIPA (GEEN DHCP)"
            }
            elseif ($l -match '(\d+\.\d+\.\d+)\.(254|1)\s' -and $l -match 'dynamic') {
                $ann[$i] = "GATEWAY"
            }
            elseif ($l -match '(224|239)\.\d+\.\d+\.\d+|255\.255\.255\.255') {
                $ann[$i] = "MULTICAST/BROADCAST"
            }
        }

        return $ann
    }
    if ($count -gt 0) { $totalAnnotated += $count; $filesAnnotated++ }

    # -----------------------------------------------------------------
    # 04_netstat_ano.txt
    # -----------------------------------------------------------------
    $count = Add-FileAnnotations -Path (Join-Path $OutDir "04_netstat_ano.txt") -Benchmarks $bm -Annotator {
        param([string[]]$lines, [hashtable]$bm)
        $ann = @($null) * $lines.Count
        $synSentCount = @($lines | Where-Object { $_ -match 'SYN_SENT' }).Count

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $l = $lines[$i]

            if ($l -match 'SYN_SENT') {
                if ($synSentCount -ge 3) {
                    $ann[$i] = "VERBINDINGSPROBLEEM ($synSentCount x SYN_SENT)"
                }
                else {
                    $ann[$i] = "VERBINDING OPBOUWEN"
                }
            }
            elseif ($l -match 'CLOSE_WAIT') {
                $ann[$i] = "HALF GESLOTEN VERBINDING"
            }
        }

        return $ann
    }
    if ($count -gt 0) { $totalAnnotated += $count; $filesAnnotated++ }

    # -----------------------------------------------------------------
    # Full-only bestanden (13-16)
    # -----------------------------------------------------------------
    if ($FullMode) {

        # 13_dns_performance.txt
        $count = Add-FileAnnotations -Path (Join-Path $OutDir "13_dns_performance.txt") -Benchmarks $bm -Annotator {
            param([string[]]$lines, [hashtable]$bm)
            $ann = @($null) * $lines.Count
            $dnsExc = if ($bm.dns_excellent) { $bm.dns_excellent } else { 20 }
            $dnsGood = if ($bm.dns_good) { $bm.dns_good } else { 50 }
            $dnsPoor = if ($bm.dns_poor) { $bm.dns_poor } else { 100 }

            for ($i = 0; $i -lt $lines.Count; $i++) {
                $l = $lines[$i]

                if ($l -match 'FAILED') {
                    $ann[$i] = "DNS SERVER DOWN"
                }
                elseif ($l -match '(\d+)ms.*\[GECONFIGUREERD\]') {
                    $ms = [int]$Matches[1]
                    if ($ms -le $dnsExc) { $ann[$i] = "SNEL (<${dnsExc}ms) IN GEBRUIK" }
                    elseif ($ms -le $dnsGood) { $ann[$i] = "OK (<${dnsGood}ms) IN GEBRUIK" }
                    elseif ($ms -le $dnsPoor) { $ann[$i] = "TRAAG (>${dnsGood}ms) IN GEBRUIK" }
                    else { $ann[$i] = "ZEER TRAAG (>${dnsPoor}ms) - wissel DNS" }
                }
                elseif ($l -match '(\d+)ms' -and $l -notmatch '==' -and $l -match '\(') {
                    $ms = [int]$Matches[1]
                    if ($ms -le $dnsExc) { $ann[$i] = "SNEL" }
                    elseif ($ms -le $dnsPoor) { $ann[$i] = "OK" }
                    else { $ann[$i] = "TRAAG" }
                }
            }

            return $ann
        }
        if ($count -gt 0) { $totalAnnotated += $count; $filesAnnotated++ }

        # 14_mtu_test.txt
        $count = Add-FileAnnotations -Path (Join-Path $OutDir "14_mtu_test.txt") -Benchmarks $bm -Annotator {
            param([string[]]$lines, [hashtable]$bm)
            $ann = @($null) * $lines.Count

            for ($i = 0; $i -lt $lines.Count; $i++) {
                $l = $lines[$i]

                if ($l -match 'Optimale MTU:\s*(\d+)') {
                    $mtu = [int]$Matches[1]
                    if ($mtu -ge 1500) { $ann[$i] = "STANDAARD (OK)" }
                    elseif ($mtu -ge 1400) { $ann[$i] = "VERLAAGD (PPPoE/glasvezel normaal)" }
                    else { $ann[$i] = "LAAG (tunnel/VPN/dubbele NAT)" }
                }
                elseif ($l -match 'Standaard.*:\s*NEE') {
                    $ann[$i] = "OVERHEAD DOOR ENCAPSULATIE"
                }
            }

            return $ann
        }
        if ($count -gt 0) { $totalAnnotated += $count; $filesAnnotated++ }

        # 15_wifi_environment.txt
        $count = Add-FileAnnotations -Path (Join-Path $OutDir "15_wifi_environment.txt") -Benchmarks $bm -Annotator {
            param([string[]]$lines, [hashtable]$bm)
            $ann = @($null) * $lines.Count
            $sigGood = if ($bm.wifi_signal_good) { $bm.wifi_signal_good } else { 75 }
            $sigPoor = if ($bm.wifi_signal_poor) { $bm.wifi_signal_poor } else { 30 }

            for ($i = 0; $i -lt $lines.Count; $i++) {
                $l = $lines[$i]

                if ($l -match 'Signaal:\s*(\d+)%') {
                    $sig = [int]$Matches[1]
                    if ($sig -ge $sigGood) { $ann[$i] = "STERK SIGNAAL" }
                    elseif ($sig -ge $sigPoor) { $ann[$i] = "MATIG SIGNAAL" }
                    else { $ann[$i] = "ZWAK SIGNAAL" }
                }
                if ($l -match '\bOpen\b' -and $l -match 'Auth:') {
                    $current = $ann[$i]
                    $ann[$i] = if ($current) { "$current | OPEN (ONVEILIG)" } else { "OPEN NETWERK (ONVEILIG)" }
                }
            }

            return $ann
        }
        if ($count -gt 0) { $totalAnnotated += $count; $filesAnnotated++ }

        # 16_service_reachability.txt
        $count = Add-FileAnnotations -Path (Join-Path $OutDir "16_service_reachability.txt") -Benchmarks $bm -Annotator {
            param([string[]]$lines, [hashtable]$bm)
            $ann = @($null) * $lines.Count
            $failIcon = [char]0x274C
            $okIcon = [char]0x2705

            for ($i = 0; $i -lt $lines.Count; $i++) {
                $l = $lines[$i]

                if ($l -match [regex]::Escape($failIcon) -or ($l -match 'FAILED|False' -and $l -notmatch '==')) {
                    $ann[$i] = "GEBLOKKEERD/TIMEOUT"
                }
                elseif ($l -match [regex]::Escape($okIcon) -and $l -match '(\d+)ms') {
                    $ms = [int]$Matches[1]
                    if ($ms -gt 3000) { $ann[$i] = "TRAAG (>${ms}ms)" }
                    elseif ($ms -gt 1000) { $ann[$i] = "LANGZAAM" }
                    else { $ann[$i] = "OK" }
                }
            }

            return $ann
        }
        if ($count -gt 0) { $totalAnnotated += $count; $filesAnnotated++ }
    }

    # -----------------------------------------------------------------
    # 19_stability_monitor.txt (beide modes)
    # -----------------------------------------------------------------
    $count = Add-FileAnnotations -Path (Join-Path $OutDir "19_stability_monitor.txt") -Benchmarks $bm -Annotator {
        param([string[]]$lines, [hashtable]$bm)
        $ann = @($null) * $lines.Count
        $lossOK = if ($bm.stability_loss_acceptable) { $bm.stability_loss_acceptable } else { 0.5 }
        $lossWarn = if ($bm.stability_loss_warning) { $bm.stability_loss_warning } else { 2 }
        $p50Good = if ($bm.stability_p50_good) { $bm.stability_p50_good } else { 10 }
        $p99Good = if ($bm.stability_p99_good) { $bm.stability_p99_good } else { 80 }
        $p99Poor = if ($bm.stability_p99_poor) { $bm.stability_p99_poor } else { 250 }

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $l = $lines[$i]

            if ($l -match 'Loss:\s*([\d.]+)%') {
                $loss = [double]$Matches[1]
                if ($loss -eq 0) { $ann[$i] = "GEEN VERLIES (STABIEL)" }
                elseif ($loss -le $lossOK) { $ann[$i] = "ACCEPTABEL (<${lossOK}%)" }
                elseif ($loss -le $lossWarn) { $ann[$i] = "LET OP (>${lossOK}%)" }
                else { $ann[$i] = "INSTABIEL (>${lossWarn}%)" }
            }
            elseif ($l -match 'P99:\s*(\d+)ms') {
                $p99 = [int]$Matches[1]
                if ($p99 -le $p99Good) { $ann[$i] = "P99 OK (<${p99Good}ms)" }
                elseif ($p99 -le $p99Poor) { $ann[$i] = "P99 VERHOOGD" }
                else { $ann[$i] = "P99 SLECHT (>${p99Poor}ms) - SPIKES!" }
            }
            elseif ($l -match 'P50:\s*(\d+)ms') {
                $p50 = [int]$Matches[1]
                if ($p50 -le $p50Good) { $ann[$i] = "P50 OK" }
                else { $ann[$i] = "P50 HOOG (>${p50Good}ms)" }
            }
            elseif ($l -match 'Spikes.*:\s*(\d+)' -and [int]$Matches[1] -gt 0) {
                $ann[$i] = "$($Matches[1]) SPIKES GEDETECTEERD"
            }
            elseif ($l -match 'Outages:\s*(\d+)' -and [int]$Matches[1] -gt 0) {
                $ann[$i] = "ONDERBREKINGEN GEDETECTEERD"
            }
            elseif ($l -match 'LOKAAL.*instabiel') {
                $ann[$i] = "WIFI/KABEL OF ROUTER PROBLEEM"
            }
            elseif ($l -match 'EXTERN instabiel') {
                $ann[$i] = "ISP/UPSTREAM PROBLEEM"
            }
        }

        return $ann
    }
    if ($count -gt 0) { $totalAnnotated += $count; $filesAnnotated++ }

    # -----------------------------------------------------------------
    # 20_dns_battle.txt (beide modes)
    # -----------------------------------------------------------------
    $count = Add-FileAnnotations -Path (Join-Path $OutDir "20_dns_battle.txt") -Benchmarks $bm -Annotator {
        param([string[]]$lines, [hashtable]$bm)
        $ann = @($null) * $lines.Count
        $p95Good = if ($bm.dns_battle_p95_good) { $bm.dns_battle_p95_good } else { 80 }
        $p95Poor = if ($bm.dns_battle_p95_poor) { $bm.dns_battle_p95_poor } else { 200 }

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $l = $lines[$i]

            if ($l -match 'WINNAAR:\s*(.+)') {
                $ann[$i] = "SNELSTE DNS RESOLVER"
            }
            elseif ($l -match 'p95\s+(\d+)ms') {
                $p95 = [int]$Matches[1]
                if ($p95 -le $p95Good) { $ann[$i] = "P95 OK (<${p95Good}ms)" }
                elseif ($p95 -le $p95Poor) { $ann[$i] = "P95 VERHOOGD" }
                else { $ann[$i] = "P95 TRAAG (>${p95Poor}ms)" }
            }
            elseif ($l -match 'FAILED') {
                $ann[$i] = "DNS RESOLVER NIET BEREIKBAAR"
            }
            elseif ($l -match 'Timeouts:\s*(\d+)' -and [int]$Matches[1] -gt 0) {
                $ann[$i] = "DNS TIMEOUTS GEDETECTEERD"
            }
            elseif ($l -match 'DoH.*HTTPS') {
                $ann[$i] = "ALLEEN GEMETEN, NIET GECONFIGUREERD"
            }
        }

        return $ann
    }
    if ($count -gt 0) { $totalAnnotated += $count; $filesAnnotated++ }

    Write-Host "    -> Annotaties: $totalAnnotated regels in $filesAnnotated bestanden" -ForegroundColor $(if ($totalAnnotated -gt 0) { "Cyan" } else { "Gray" })

    return $totalAnnotated
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
Write-Host "Mode: $modeName$(if (-not $SpeedtestOnly) { " | Stappen: $totalSteps" })" -ForegroundColor White
if ($ClientName) { Write-Host "Klant: $ClientName" -ForegroundColor White }
Write-Host ""

# =========================================================================
# SPEEDTEST-ONLY MODE (skip alle diagnose)
# =========================================================================

if ($SpeedtestOnly) {
    if (-not (Test-Path $speedtestExe)) {
        Write-Host "$iFail speedtest.exe niet gevonden: $speedtestExe" -ForegroundColor Red
        Write-Host ""
        return
    }

    Write-Host "[SPEEDTEST] Uitvoeren..." -ForegroundColor Cyan
    Write-Host ""

    try {
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo.FileName = $speedtestExe
        $proc.StartInfo.Arguments = "--accept-license --accept-gdpr --progress=yes -f json"
        $proc.StartInfo.UseShellExecute = $false
        $proc.StartInfo.RedirectStandardOutput = $true
        $proc.StartInfo.RedirectStandardError = $true
        $proc.StartInfo.CreateNoWindow = $true

        $jsonOutput = [System.Text.StringBuilder]::new()

        $errEvent = Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived -Action {
            if ($EventArgs.Data) {
                $line = $EventArgs.Data
                if ($line -match 'Download|Upload|Idle Latency|Result URL|Latency|Packet Loss') {
                    Write-Host "`r    $line                              " -NoNewline -ForegroundColor Cyan
                }
            }
        }

        $null = $proc.Start()
        $proc.BeginErrorReadLine()

        while (-not $proc.StandardOutput.EndOfStream) {
            $line = $proc.StandardOutput.ReadLine()
            if ($line) { [void]$jsonOutput.AppendLine($line) }
        }

        $proc.WaitForExit()
        Unregister-Event -SourceIdentifier $errEvent.Name -ErrorAction SilentlyContinue
        Write-Host ""
        Write-Host ""

        $speedtestOutput = $jsonOutput.ToString() -split "`n"
        OutFile "11_speedtest_cli.json" $speedtestOutput

        # Parse JSON resultaat
        $jsonString = ""
        $jsonLines = $speedtestOutput | Where-Object { $_ }
        foreach ($jl in $jsonLines) {
            if ($jl -match '^\s*\{"type":"result"') { $jsonString = $jl; break }
        }
        if (-not $jsonString) {
            $jsonString = ($jsonLines | Where-Object { $_ -match '^\s*\{.*\}\s*$' } | Select-Object -Last 1)
        }

        if ($jsonString) {
            $obj = $jsonString | ConvertFrom-Json
            if ($obj.download -and $obj.upload -and $obj.ping) {
                $dlMbps = [math]::Round(($obj.download.bandwidth * 8) / 1000000, 2)
                $ulMbps = [math]::Round(($obj.upload.bandwidth * 8) / 1000000, 2)
                $latMs = $obj.ping.latency
                $isp = $obj.isp
                $srv = $obj.server.name

                OutFile "12_speedtest_readable.txt" @(
                    "================================================================="
                    "SPEEDTEST RESULTAAT"
                    "================================================================="
                    ""
                    "Download:  $dlMbps Mbps"
                    "Upload:    $ulMbps Mbps"
                    "Latency:   $latMs ms"
                    "ISP:       $isp"
                    "Server:    $srv"
                    "Tijd:      $(Get-Date -Format 'HH:mm:ss')"
                    $(if ($ClientName) { "Klant:     $ClientName" } else { "" })
                )

                Write-Host "=================================================================" -ForegroundColor Green
                Write-Host "  SPEEDTEST RESULTAAT" -ForegroundColor Green
                Write-Host "=================================================================" -ForegroundColor Green
                Write-Host ""
                Write-Host "  Download:  $dlMbps Mbps" -ForegroundColor White
                Write-Host "  Upload:    $ulMbps Mbps" -ForegroundColor White
                Write-Host "  Latency:   $latMs ms" -ForegroundColor White
                Write-Host "  ISP:       $isp" -ForegroundColor Gray
                Write-Host "  Server:    $srv" -ForegroundColor Gray
                Write-Host ""

                # Beoordeling
                $dlIcon = if ($dlMbps -ge 200) { $iOK } elseif ($dlMbps -ge 50) { $iWarn } else { $iFail }
                $ulIcon = if ($ulMbps -ge 100) { $iOK } elseif ($ulMbps -ge 20) { $iWarn } else { $iFail }
                $latIcon = if ($latMs -lt 10) { $iOK } elseif ($latMs -lt 30) { $iWarn } else { $iFail }

                Write-Host "  $dlIcon Download: $(if ($dlMbps -ge 200) { 'Uitstekend' } elseif ($dlMbps -ge 100) { 'Goed' } elseif ($dlMbps -ge 50) { 'Voldoende' } else { 'Traag' })" -ForegroundColor White
                Write-Host "  $ulIcon Upload:   $(if ($ulMbps -ge 100) { 'Uitstekend' } elseif ($ulMbps -ge 50) { 'Goed' } elseif ($ulMbps -ge 20) { 'Voldoende' } else { 'Traag' })" -ForegroundColor White
                Write-Host "  $latIcon Latency:  $(if ($latMs -lt 10) { 'Uitstekend' } elseif ($latMs -lt 20) { 'Goed' } elseif ($latMs -lt 30) { 'Redelijk' } else { 'Hoog' })" -ForegroundColor White
                Write-Host ""
                Write-Host "  Output: $outDir" -ForegroundColor Cyan
            }
            else { Write-Host "$iFail Speedtest JSON onvolledig" -ForegroundColor Red }
        }
        else { Write-Host "$iFail Geen JSON resultaat van speedtest" -ForegroundColor Red }
    }
    catch {
        Write-Host "$iFail Speedtest fout: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "=================================================================" -ForegroundColor Green
    Write-Host ""
    Start-Process explorer.exe $outDir
    return
}

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
# STAP 5: OMGEVING SNAPSHOT + SPLIT-TEST
# =========================================================================

Show-Step "Omgeving + split-test"

# Environment snapshot (beide modes)
$envSnapshot = Get-EnvironmentSnapshot

# Split-test lokalisatie (beide modes - is snel)
$splitTest = $null
if ($physicalGateways.Count -ge 1) {
    Write-Host "    -> Split-test: LAN vs Router vs ISP..." -ForegroundColor Gray
    $splitTest = Test-SplitLocalization -Gateway $physicalGateways[0] -PingCount $(if ($Full) { 10 } else { 5 })
}

# =========================================================================
# BEIDE MODES: STABILITEITSMONITOR + DNS BATTLE
# =========================================================================

$dnsPerformanceData = @{ DNS = @(); DoH = @() }
$dnsPerformance = @()
$mtuResult = @{ OptimalMTU = 0; StandardMTU = $true; Issue = "" }
$serviceResults = @()
$ipv6Deep = @{ HasGlobalIPv6 = $false; Status = "NIET_GETEST" }
$ipv6Status = @{ HasIPv6 = $false; Connectivity = $false; DualStack = $false }
$wifiEnvironment = @()
$stabilityMonitor = $null
$bufferbloatResult = $null
$dnsBattleData = $null

# ----- SECURITY + IPv6 (beide modes) -----
Show-Step "Security + IPv6 check"
if ($Full) {
    $ipv6Status = Test-SecurityAndIPv6 -WifiNetworks @() -OwnSSID $wifiSSID -FullMode
    $ipv6Deep = Test-IPv6Deep -FullMode
}
else {
    $ipv6Status = Test-SecurityAndIPv6 -WifiNetworks @() -OwnSSID ""
    $ipv6Deep = Test-IPv6Deep
}

# ----- STABILITEITSMONITOR (beide modes: Quick=60s, Full=300s) -----
Show-Step "Stabiliteitsmonitor ($monitorDuration sec)"
if ($physicalGateways.Count -ge 1) {
    $stabilityMonitor = Test-StabilityMonitor -Gateway $physicalGateways[0] `
        -ExternalIPs @("1.1.1.1", "8.8.8.8") `
        -DurationSec $monitorDuration -IntervalMs $monitorInterval
    Analyze-StabilityMonitor -MonitorResult $stabilityMonitor
}
else {
    Write-Host "    -> Overgeslagen (geen gateway)" -ForegroundColor DarkGray
}

# ----- DNS BATTLE (beide modes: Quick=10q, Full=20q per target) -----
Show-Step "DNS Battle ($dnsBattleQueries queries/target)"
$dnsBattleData = Invoke-DnsBattle -SystemDnsServers $dnsServers `
    -QueriesPerTarget $dnsBattleQueries -Deep:$Full

# Backward compatible: ook $dnsPerformance vullen voor summary
if ($dnsBattleData) {
    $dnsPerformance = @()
    foreach ($sys in $dnsBattleData.SystemDNS) {
        $dnsPerformance += @{
            Server = $sys.Server; Label = $sys.Label; AvgMs = $sys.Avg
            MedianMs = $sys.Median; P95Ms = $sys.P95; P99Ms = $sys.P99
            Times = $sys.Times; Successes = ($sys.Queries - $sys.Failures)
            Failures = $sys.Failures; IsConfigured = $true; NXDOMAIN = 0
            AAAATimes = @(); AAAAFailures = 0
        }
    }
    foreach ($pub in $dnsBattleData.PublicDNS) {
        $dnsPerformance += @{
            Server = $pub.Server; Label = $pub.Label; AvgMs = $pub.Avg
            MedianMs = $pub.Median; P95Ms = $pub.P95; P99Ms = $pub.P99
            Times = $pub.Times; Successes = ($pub.Queries - $pub.Failures)
            Failures = $pub.Failures; IsConfigured = $false; NXDOMAIN = 0
            AAAATimes = @(); AAAAFailures = 0
        }
    }
}

# =========================================================================
# FULL MODE: EXTRA TESTS
# =========================================================================

if ($Full) {
    # ----- WIFI OMGEVINGSSCAN -----
    Show-Step "WiFi omgevingsscan"
    $wifiEnvironment = Scan-WiFiEnvironment
    $ownCh = 0
    if ($wifiChan -match "(\d+)") { $ownCh = [int]$Matches[1] }
    Analyze-WiFiEnvironment -Networks $wifiEnvironment -OwnChannel $ownCh -OwnSSID $wifiSSID

    # ----- MTU DISCOVERY -----
    Show-Step "MTU discovery (max 90 sec)"
    $mtuResult = Find-OptimalMTU -Target "1.1.1.1" -MaxSeconds 90

    # ----- SERVICE BEREIKBAARHEID -----
    $svcCount = if ($CaseMode) { "9+" } else { "9" }
    Show-Step "Service bereikbaarheid ($svcCount services)"
    $serviceResults = Test-ServiceReachability -CaseMode $CaseMode
    Analyze-ServiceResults -Results $serviceResults
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
            Write-Host ""

            # Draai speedtest met live voortgang zichtbaar in terminal
            $savedPref = $ProgressPreference
            $ProgressPreference = "Continue"

            $proc = New-Object System.Diagnostics.Process
            $proc.StartInfo.FileName = $speedtestExe
            $proc.StartInfo.Arguments = "--accept-license --accept-gdpr --progress=yes -f json"
            $proc.StartInfo.UseShellExecute = $false
            $proc.StartInfo.RedirectStandardOutput = $true
            $proc.StartInfo.RedirectStandardError = $true
            $proc.StartInfo.CreateNoWindow = $true

            $jsonOutput = [System.Text.StringBuilder]::new()
            $lastProgressLine = ""

            # Event handler voor stderr (progress output)
            $errBuilder = [System.Text.StringBuilder]::new()
            $errEvent = Register-ObjectEvent -InputObject $proc -EventName ErrorDataReceived -Action {
                if ($EventArgs.Data) {
                    $line = $EventArgs.Data
                    # Progress regels bevatten download/upload voortgang
                    if ($line -match 'Download|Upload|Idle Latency|Result URL|Latency|Packet Loss') {
                        # Overschrijf huidige regel voor live progress effect
                        Write-Host "`r    $line                              " -NoNewline -ForegroundColor Cyan
                    }
                }
            }

            $null = $proc.Start()
            $proc.BeginErrorReadLine()

            # Lees stdout (JSON result)
            while (-not $proc.StandardOutput.EndOfStream) {
                $line = $proc.StandardOutput.ReadLine()
                if ($line) { [void]$jsonOutput.AppendLine($line) }
            }

            $proc.WaitForExit()
            Unregister-Event -SourceIdentifier $errEvent.Name -ErrorAction SilentlyContinue

            Write-Host ""  # Nieuwe regel na progress output
            Write-Host ""

            $ProgressPreference = $savedPref
            $speedtestOutput = $jsonOutput.ToString() -split "`n"

            OutFile "11_speedtest_cli.json" $speedtestOutput

            $jsonString = ""
            $jsonLines = $speedtestOutput | Where-Object { $_ }
            foreach ($jl in $jsonLines) {
                if ($jl -match '^\s*\{"type":"result"') { $jsonString = $jl; break }
            }
            if (-not $jsonString) {
                $jsonString = ($jsonLines | Where-Object { $_ -match '^\s*\{.*\}\s*$' } | Select-Object -Last 1)
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
# BUFFERBLOAT TEST (Full mode, na speedtest)
# =========================================================================

if ($Full -and $speedtestSuccess) {
    Show-Step "Bufferbloat detectie"
    $bufferbloatResult = Test-Bufferbloat -Target "1.1.1.1" -BaselinePings 10 -LoadedDurationSec 15 -IntervalMs 200
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

# Security + adapters (ALTIJD)
$secContent = @("=================================================================", "SECURITY & ADAPTERS", "=================================================================", "")
$secContent += "IPv6: $(if ($ipv6Deep.Status -eq 'VOLLEDIG_WERKEND') { 'Dual-stack werkend' } elseif ($ipv6Deep.Status -eq 'BROKEN') { 'BROKEN (adres aanwezig, niet werkend)' } elseif ($ipv6Deep.HasGlobalIPv6) { 'Aanwezig (status: ' + $ipv6Deep.Status + ')' } else { 'Niet beschikbaar' })"
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

# ----- OUTPUT FILES 19-20 -----

# 19: Stability Monitor (beide modes)
if ($stabilityMonitor -and $stabilityMonitor.Samples -gt 0) {
    $smContent = @(
        "================================================================="
        "STABILITEITSMONITOR"
        "================================================================="
        ""
        "Mode: $modeName | Duur: $($stabilityMonitor.DurationSec)s | Interval: ${monitorInterval}ms | Samples: $($stabilityMonitor.Samples)"
        ""
    )
    if ($stabilityMonitor.Gateway.Stats.Count -gt 0) {
        $gwS = $stabilityMonitor.Gateway.Stats
        $smContent += "GATEWAY:"
        $smContent += "  P50: $($gwS.P50)ms | P95: $($gwS.P95)ms | P99: $($gwS.P99)ms | Avg: $($gwS.Avg)ms"
        $smContent += "  Min: $($gwS.Min)ms | Max: $($gwS.Max)ms | Spikes(>100ms): $($gwS.Spikes)"
        $smContent += "  Loss: $($gwS.LossPercent)% | Timeouts: $($stabilityMonitor.Gateway.Timeouts) | Outages: $($stabilityMonitor.Gateway.Outages) (${($stabilityMonitor.Gateway.OutageDurationSec)}s)"
        if ($gwS.Jitter) { $smContent += "  Jitter: $($gwS.Jitter)ms | Jitter P95: $($gwS.JitterP95)ms | Jitter P99: $($gwS.JitterP99)ms" }
        $smContent += ""
    }
    if ($stabilityMonitor.External.Stats.Count -gt 0) {
        $extS = $stabilityMonitor.External.Stats
        $smContent += "EXTERN (1.1.1.1 / 8.8.8.8):"
        $smContent += "  P50: $($extS.P50)ms | P95: $($extS.P95)ms | P99: $($extS.P99)ms | Avg: $($extS.Avg)ms"
        $smContent += "  Min: $($extS.Min)ms | Max: $($extS.Max)ms | Spikes(>100ms): $($extS.Spikes)"
        $smContent += "  Loss: $($extS.LossPercent)% | Timeouts: $($stabilityMonitor.External.Timeouts) | Outages: $($stabilityMonitor.External.Outages) (${($stabilityMonitor.External.OutageDurationSec)}s)"
        if ($extS.Jitter) { $smContent += "  Jitter: $($extS.Jitter)ms | Jitter P95: $($extS.JitterP95)ms | Jitter P99: $($extS.JitterP99)ms" }
        $smContent += ""
    }
    if ($stabilityMonitor.DNS.Stats.Count -gt 0) {
        $dnsS = $stabilityMonitor.DNS.Stats
        $smContent += "DNS RESOLVE (elke 3 ticks):"
        $smContent += "  P50: $($dnsS.P50)ms | P95: $($dnsS.P95)ms | P99: $($dnsS.P99)ms | Max: $($dnsS.Max)ms"
        $smContent += "  Failures: $($dnsS.Failures) / $($stabilityMonitor.DNS.Times.Count + $dnsS.Failures)"
        $smContent += ""
    }
    if ($stabilityMonitor.HTTP.Stats.Count -gt 0) {
        $httpS = $stabilityMonitor.HTTP.Stats
        $smContent += "HTTP HEAD (elke 10 ticks):"
        $smContent += "  P50: $($httpS.P50)ms | P95: $($httpS.P95)ms | P99: $($httpS.P99)ms"
        $smContent += "  Failures: $($httpS.Failures)"
        $smContent += ""
    }

    # Human-readable summary
    $smContent += "-----------------------------------------------------------------"
    $smContent += "INTERPRETATIE"
    $smContent += "-----------------------------------------------------------------"
    if ($stabilityMonitor.Gateway.Stats.Count -gt 0 -and $stabilityMonitor.External.Stats.Count -gt 0) {
        $gwLoss = $stabilityMonitor.Gateway.Stats.LossPercent
        $extLoss = $stabilityMonitor.External.Stats.LossPercent
        $extP99 = $stabilityMonitor.External.Stats.P99

        if ($gwLoss -eq 0 -and $extLoss -eq 0 -and $extP99 -lt 100) {
            $smContent += "Verbinding stabiel gedurende $($stabilityMonitor.DurationSec)s monitoring."
        }
        elseif ($gwLoss -gt 0 -and $extLoss -gt 0) {
            $smContent += "LOKAAL + EXTERN instabiel: probleem waarschijnlijk WiFi/kabel of router."
        }
        elseif ($gwLoss -eq 0 -and $extLoss -gt 0) {
            $smContent += "Lokaal OK, EXTERN instabiel: probleem bij ISP/upstream."
        }
        elseif ($gwLoss -eq 0 -and $extLoss -eq 0 -and $extP99 -gt 200) {
            $smContent += "Geen loss maar hoge p99 ($($extP99)ms): incidentele spikes bij ISP."
        }

        if ($extLoss -gt 0.3 -or $extP99 -gt 200) {
            $smContent += "Impact: $($extLoss)% loss + p99 $($extP99)ms = merkbaar bij videobellen/gaming."
        }
    }

    OutFile "19_stability_monitor.txt" $smContent
}

# 20: DNS Battle
if ($dnsBattleData) {
    $dbContent = @(
        "================================================================="
        "DNS BATTLE"
        "================================================================="
        ""
        "Queries per target: $($dnsBattleData.QueriesPerTarget)"
        "Tijd: $($dnsBattleData.Timestamp)"
        ""
    )

    $dbContent += "SYSTEEM DNS RESOLVERS:"
    foreach ($sys in $dnsBattleData.SystemDNS) {
        $status = if ($sys.Avg -gt 0) { "median $($sys.Median)ms | p95 $($sys.P95)ms | p99 $($sys.P99)ms | avg $($sys.Avg)ms" } else { "FAILED" }
        $dbContent += "  $($sys.Server): $status"
        $dbContent += "    Queries: $($sys.Queries) | Failures: $($sys.Failures) | Timeouts: $($sys.Timeouts)"
    }
    $dbContent += ""

    $dbContent += "PUBLIEKE DNS (direct queries):"
    foreach ($pub in $dnsBattleData.PublicDNS) {
        $status = if ($pub.Avg -gt 0) { "median $($pub.Median)ms | p95 $($pub.P95)ms | p99 $($pub.P99)ms | avg $($pub.Avg)ms" } else { "FAILED" }
        $dbContent += "  $($pub.Server) ($($pub.Label)): $status"
        $dbContent += "    Queries: $($pub.Queries) | Failures: $($pub.Failures) | Timeouts: $($pub.Timeouts)"
    }
    $dbContent += ""

    $dbContent += "DoH (HTTPS DNS - meten, geen config wijziging):"
    foreach ($doh in $dnsBattleData.DoH) {
        $status = if ($doh.Avg -gt 0) { "median $($doh.Median)ms | p95 $($doh.P95)ms | avg $($doh.Avg)ms" } else { "FAILED" }
        $dbContent += "  $($doh.Name): $status"
        $dbContent += "    Queries: $($doh.Queries) | Failures: $($doh.Failures)"
    }
    $dbContent += ""

    # Winner determination
    $allTargets = @()
    $dnsBattleData.SystemDNS | Where-Object { $_.Avg -gt 0 } | ForEach-Object { $allTargets += @{ Name = "$($_.Server) (Systeem)"; Median = $_.Median } }
    $dnsBattleData.PublicDNS | Where-Object { $_.Avg -gt 0 } | ForEach-Object { $allTargets += @{ Name = "$($_.Server) ($($_.Label))"; Median = $_.Median } }
    $dnsBattleData.DoH | Where-Object { $_.Avg -gt 0 } | ForEach-Object { $allTargets += @{ Name = "$($_.Name)"; Median = $_.Median } }

    if ($allTargets.Count -gt 0) {
        $winner = $allTargets | Sort-Object { $_.Median } | Select-Object -First 1
        $dbContent += "-----------------------------------------------------------------"
        $dbContent += "WINNAAR: $($winner.Name) (median $($winner.Median)ms)"
        $dbContent += "-----------------------------------------------------------------"
    }

    OutFile "20_dns_battle.txt" $dbContent
}

# Full-only output files
if ($Full) {
    # DNS performance (backward compatible format)
    $dnsContent = @("=================================================================", "DNS PRESTATIE ANALYSE", "=================================================================", "")
    foreach ($d in $dnsPerformance) {
        $status = if ($d.AvgMs -gt 0) { "avg $($d.AvgMs)ms | median $($d.MedianMs)ms | p95 $($d.P95Ms)ms | p99 $($d.P99Ms)ms" } else { "FAILED" }
        $cfg = if ($d.IsConfigured) { " [GECONFIGUREERD]" } else { "" }
        $dnsContent += "$($d.Server) ($($d.Label)): $status (succes: $($d.Successes)/$($d.Successes + $d.Failures))$cfg"
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

    # Services (met categorie)
    $svcContent = @("=================================================================", "SERVICE BEREIKBAARHEID$(if ($CaseMode) { " ($CaseMode)" })", "=================================================================", "")
    $categories = $serviceResults | Group-Object { $_.Category } | Sort-Object Name
    foreach ($cat in $categories) {
        $catOK = ($cat.Group | Where-Object { $_.Reachable }).Count
        $svcContent += "[$($cat.Name)] ($catOK/$($cat.Count) OK)"
        foreach ($sv in $cat.Group) {
            $icon = if ($sv.Reachable) { "$iOK" } else { "$iFail" }
            $svcContent += "  $icon $($sv.Name) ($($sv.Host)) - $($sv.LatencyMs)ms"
        }
        $svcContent += ""
    }
    OutFile "16_service_reachability.txt" $svcContent
}
else {
    # Quick mode: DNS performance uit DNS Battle data
    if ($dnsPerformance.Count -gt 0) {
        $dnsContent = @("=================================================================", "DNS PRESTATIE (vanuit DNS Battle)", "=================================================================", "")
        foreach ($d in $dnsPerformance) {
            $status = if ($d.AvgMs -gt 0) { "avg $($d.AvgMs)ms | median $($d.MedianMs)ms | p95 $($d.P95Ms)ms | p99 $($d.P99Ms)ms" } else { "FAILED" }
            $cfg = if ($d.IsConfigured) { " [GECONFIGUREERD]" } else { "" }
            $dnsContent += "$($d.Server) ($($d.Label)): $status (succes: $($d.Successes)/$($d.Successes + $d.Failures))$cfg"
        }
        OutFile "13_dns_performance.txt" $dnsContent
    }
}

# =========================================================================
# RISICO SCORE BEREKENING (voor adviesrapport)
# =========================================================================

$riskScore = 0

# Gateway bereikbaarheid
if (-not $gatewayPing.Success) { $riskScore += 50 }
else {
    if ($gatewayPing.LostPercent -gt 10) { $riskScore += 30 }
    elseif ($gatewayPing.LostPercent -gt 2) { $riskScore += 15 }
    elseif ($gatewayPing.LostPercent -gt 0) { $riskScore += 5 }
    if ($gatewayPing.AvgLatency -gt 50) { $riskScore += 15 }
    elseif ($gatewayPing.AvgLatency -gt 10) { $riskScore += 5 }
}

# Internet
if (-not $internetPing.Success) { $riskScore += 25 }
else {
    if ($internetPing.LostPercent -gt 5) { $riskScore += 15 }
    elseif ($internetPing.LostPercent -gt 1) { $riskScore += 8 }
    if ($internetPing.AvgLatency -gt 100) { $riskScore += 10 }
    elseif ($internetPing.AvgLatency -gt 50) { $riskScore += 5 }
}

# Jitter
if ($internetJitter -and $internetJitter.Jitter -ge 0) {
    switch ($internetJitter.Quality) { "SLECHT" { $riskScore += 15 } "MATIG" { $riskScore += 8 } "GOED" { $riskScore += 2 } }
}

# Stability monitor
if ($stabilityMonitor -and $stabilityMonitor.External.Stats.Count -gt 0) {
    if ($stabilityMonitor.External.Stats.LossPercent -gt 2) { $riskScore += 15 }
    elseif ($stabilityMonitor.External.Stats.LossPercent -gt 0.5) { $riskScore += 8 }
    if ($stabilityMonitor.Gateway.Outages -gt 0) { $riskScore += 10 }
}

# Split-test
if ($splitTest -and $splitTest.Verdict -match "LOCAL|ISP") { $riskScore += 10 }

# Bufferbloat
if ($bufferbloatResult -and $bufferbloatResult.Grade -eq "F") { $riskScore += 10 }
elseif ($bufferbloatResult -and $bufferbloatResult.Grade -eq "C") { $riskScore += 5 }

# IPv6 broken
if ($ipv6Deep.Status -eq "BROKEN") { $riskScore += 5 }

# Speed
if ($speedtestSuccess) {
    if ($downloadMbps -lt 10) { $riskScore += 15 }
    elseif ($downloadMbps -lt 25) { $riskScore += 10 }
    elseif ($downloadMbps -lt 50) { $riskScore += 5 }
}

# Issues & warnings
$riskScore += [Math]::Min(($Global:AnalysisResults.Issues.Count * 10), 30)
$riskScore += [Math]::Min(($Global:AnalysisResults.Warnings.Count * 3), 15)

# WiFi
$wifiConnected = ($wifiState -match "connected|Verbonden")
if ($wifiConnected -and $wifiSignal -match "(\d+)") {
    $wSig = [int]$Matches[1]
    if ($wSig -lt 30) { $riskScore += 15 }
    elseif ($wSig -lt 50) { $riskScore += 8 }
    elseif ($wSig -lt 60) { $riskScore += 3 }
}

$riskScore = [Math]::Min($riskScore, 100)
$riskScore = [Math]::Max($riskScore, 0)

# Build top conclusion
$topConclusion = ""
if ($Global:AnalysisResults.Evidence.Count -gt 0) {
    $topEvidence = $Global:AnalysisResults.Evidence | Sort-Object {
        switch ($_.Impact) { "Hoog" { 3 } "Middel" { 2 } default { 1 } }
    } -Descending | Select-Object -First 1
    $topConclusion = $topEvidence.Finding
}
elseif ($Global:AnalysisResults.Issues.Count -gt 0) {
    $topConclusion = $Global:AnalysisResults.Issues[0]
}
elseif ($riskScore -le 10) {
    $topConclusion = "Netwerk gezond en stabiel"
    if ($speedtestSuccess) { $topConclusion += " ($downloadMbps Mbps)" }
}
elseif ($Global:AnalysisResults.Warnings.Count -gt 0) {
    $topConclusion = $Global:AnalysisResults.Warnings[0]
}

# Build network segment conclusion
$networkSegments = Build-NetworkConclusion -GatewayPing $gatewayPing `
    -StabilityMonitor $stabilityMonitor -DnsBattle $dnsBattleData `
    -IPv6Deep $ipv6Deep -SplitTest $splitTest -BufferbloatResult $bufferbloatResult

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
    -WifiEnvironment $wifiEnvironment `
    -StabilityMonitor $stabilityMonitor -SplitTest $splitTest `
    -IPv6Deep $ipv6Deep -BufferbloatResult $bufferbloatResult `
    -EnvSnapshot $envSnapshot -Segments $networkSegments `
    -DnsBattleData $dnsBattleData -CaseModeLabel $CaseMode `
    -ExternalRiskScore $riskScore

Generate-AdviceReport -RiskScore $riskScore -TopConclusion $topConclusion -Segments $networkSegments

# =========================================================================
# OUTPUT ANNOTATIES (POST-PROCESSING)
# =========================================================================

Write-Host "    -> Output annotaties toevoegen..." -ForegroundColor Gray

# Laad benchmarks uit patterns.json voor thresholds
$annotationBenchmarks = $null
$annPatternsFile = Join-Path $PSScriptRoot "patterns.json"
if (Test-Path $annPatternsFile) {
    try {
        $annPatternsData = Get-Content -Path $annPatternsFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $annotationBenchmarks = $annPatternsData.benchmarks
    }
    catch {
        Write-Host "    [i] Annotatie: patterns.json niet leesbaar" -ForegroundColor DarkGray
    }
}

Invoke-OutputAnnotations -OutDir $outDir -Benchmarks $annotationBenchmarks -FullMode:$Full

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
if ($CaseMode) { Write-Host "Case:   $CaseMode" -ForegroundColor Cyan }
Write-Host ""
Write-Host "Bekijk:" -ForegroundColor Yellow
Write-Host "  -> 00_summary.txt           (overzicht)" -ForegroundColor White
Write-Host "  -> 99_advies.txt            (aanbevelingen)" -ForegroundColor White
Write-Host "  -> 98_ai_analyse.txt        (AI analyse)" -ForegroundColor White
Write-Host "  -> 19_stability_monitor.txt (stabiliteitsmonitor)" -ForegroundColor White
Write-Host "  -> 20_dns_battle.txt        (DNS vergelijking)" -ForegroundColor White
Write-Host ""

Start-Process explorer.exe $outDir
