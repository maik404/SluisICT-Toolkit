# SluisICT Netwerk Diagnose Toolkit v3.5

Professionele Windows netwerk-diagnose tool voor veldwerk.
**Read-only**: wijzigt nooit netwerkinstellingen, adapters, DNS, registry of andere systeemconfiguratie.
**Risicoscore**: elke diagnose geeft direct een score 0-100 bovenaan het rapport.

---

## Installatie

1. Kopieer de hele `SluisICT` map naar een USB-stick of lokale schijf
2. Geen installatie nodig - de scripts draaien direct

### Mapstructuur

```
SluisICT/
  src/
    netwerk-diagnose-v3_5.ps1        # Hoofdscript
    Invoke-SluisICT-AIAnalysis.ps1   # AI analyse module
    patterns.json                     # Patroon definities (12 patronen)
    netwerk-diagnose-v3_5-run.bat    # Dubbelklik launcher
  Tools/
    Portable/
      SpeedtestCLI/
        speedtest.exe                 # Ookla Speedtest CLI
  output/
    2025-01-15_14-30-00/             # Voorbeeld diagnose output
      00_summary.txt
      01_ipconfig_all.txt
      ...
      98_ai_analyse.txt
      99_advies.txt
  Data/
    klanten/                          # Klant historie (automatisch)
  docs/
    README.md                         # Dit bestand
```

---

## Gebruik

### Methode 1: Dubbelklik (aanbevolen)

1. Open `src/netwerk-diagnose-v3_5-run.bat`
2. Kies een modus:
   - **[1] Quick** - 60-90 sec - basis diagnose
   - **[2] Full** - 3-8 min - alle tests inclusief DNS, MTU, WiFi scan, services
   - **[3] Quick zonder speedtest** - 30 sec
   - **[4] Full zonder speedtest** - 2-5 min
3. Optioneel: voer klantnaam in voor historie tracking
4. Wacht tot het klaar is - de output map opent automatisch

### Methode 2: PowerShell

```powershell
# Quick
.\src\netwerk-diagnose-v3_5.ps1

# Full
.\src\netwerk-diagnose-v3_5.ps1 -Full

# Quick zonder speedtest
.\src\netwerk-diagnose-v3_5.ps1 -NoSpeedtest

# Full met klantnaam
.\src\netwerk-diagnose-v3_5.ps1 -Full -ClientName "Jansen"
```

---

## Quick vs Full

| Test                       | Quick | Full |
| -------------------------- | :---: | :--: |
| Adapter classificatie      |   x   |  x   |
| WiFi snapshot              |   x   |  x   |
| Ping + traceroute          |   x   |  x   |
| Netwerk analyse (NAT/DHCP) |   x   |  x   |
| Speedtest                  |   x   |  x   |
| Security + adapters        |   x   |  x   |
| Jitter analyse             |   x   |  x   |
| AI analyse                 |   x   |  x   |
| DNS prestatie              |       |  x   |
| WiFi omgevingsscan         |       |  x   |
| MTU discovery              |       |  x   |
| Service bereikbaarheid     |       |  x   |
| IPv6 connectiviteitstest   |       |  x   |

---

## Output bestanden

### Beide modes (Quick + Full)

| Nr  | Bestand                   | Inhoud                           |
| --- | ------------------------- | -------------------------------- |
| 00  | summary.txt               | Overzicht met emoji status       |
| 01  | ipconfig_all.txt          | Volledige IP configuratie        |
| 02  | routes.txt                | Routing tabel                    |
| 03  | arp.txt                   | ARP cache                        |
| 04  | netstat_ano.txt           | Open poorten en verbindingen     |
| 05  | dns_nslookup.txt          | DNS lookup tests                 |
| 06  | ping_gateway.txt          | Ping naar gateway                |
| 07  | ping_8.8.8.8.txt          | Ping naar Google DNS             |
| 08  | tracert_8.8.8.8.txt       | Traceroute                       |
| 09  | wifi_netsh_interfaces.txt | WiFi interface details           |
| 10  | wifi_profiles.txt         | Opgeslagen WiFi profielen        |
| 11  | speedtest_cli.json        | Speedtest ruwe data              |
| 12  | speedtest_readable.txt    | Speedtest leesbaar               |
| 17  | security_adapters.txt     | Security + adapter classificatie |
| 18  | jitter_analysis.txt       | Jitter analyse resultaten        |
| 98  | ai_analyse.txt            | AI patroonherkenning resultaat   |
| 99  | advies.txt                | Adviesrapport met acties         |

### Alleen Full mode

| Nr  | Bestand                  | Inhoud                           |
| --- | ------------------------ | -------------------------------- |
| 13  | dns_performance.txt      | DNS server snelheidsvergelijking |
| 14  | mtu_test.txt             | Optimale MTU waarde              |
| 15  | wifi_environment.txt     | WiFi omgevingsscan               |
| 16  | service_reachability.txt | Service bereikbaarheid (8 sites) |

---

## AI Analyse

Het systeem gebruikt **12 patroon-definities** om veelvoorkomende netwerkproblemen te herkennen:

1. **Dubbele NAT** - Router-op-router detectie via traceroute (filtert virtuele adapters)
2. **Dubbele DHCP** - Meerdere DHCP servers op hetzelfde netwerk
3. **Zwak WiFi signaal** - Signaalsterkte onder drempel
4. **WiFi 2.4 GHz** - Verbonden op tragere band
5. **Pakketverlies** - Gateway en/of internet packet loss
6. **Hoge latency** - Internet latency boven normaal
7. **Trage snelheid** - Download onder NL markt minimum
8. **Hoge jitter** - Instabiele verbinding (VoIP/gaming probleem)
9. **Trage DNS** - DNS response tijd boven 100ms
10. **MTU probleem** - Verlaagde MTU door tunnel/encapsulatie
11. **WiFi congestie** - Te veel netwerken op hetzelfde kanaal
12. **Service blokkering** - Online services geblokkeerd door firewall/proxy

Elke bevinding bevat **evidence lines**: citaten uit de bronbestanden met bestandsnaam en matchende regel.

---

## Troubleshooting

### Speedtest werkt niet

- Download Ookla Speedtest CLI van https://www.speedtest.net/apps/cli
- Plaats `speedtest.exe` in `Tools/Portable/SpeedtestCLI/`
- Of gebruik `-NoSpeedtest` parameter om speedtest over te slaan

### Script wordt geblokkeerd

```powershell
# Open PowerShell als Administrator en voer uit:
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

Of gebruik de BAT launcher - die stelt ExecutionPolicy automatisch in.

### Geen WiFi informatie

- WiFi tests werken alleen als de computer een WiFi adapter heeft
- Op desktops zonder WiFi worden WiFi secties overgeslagen
- Dit is normaal gedrag, geen fout

### Diagnose duurt te lang

- Gebruik Quick mode voor snelle scan (60-90 sec)
- Gebruik `-NoSpeedtest` als speedtest het probleem is
- Full mode MTU discovery kan tot 90 sec duren bij lage MTU

### Emoji worden niet goed weergegeven

- Output bestanden zijn opgeslagen in UTF-8 encoding
- Open de bestanden in een editor die UTF-8 ondersteunt (Notepad, VS Code)
- Windows Kladblok (Windows 10+) ondersteunt UTF-8

---

## Privacy

**Dit script is volledig read-only en privacy-veilig:**

- Leest ALLEEN netwerkconfiguratie en -status (wat `ipconfig`, `ping`, `tracert` al laten zien)
- Wijzigt NOOIT instellingen, adapters, DNS, registry of andere systeemconfiguratie
- Verstuurt GEEN data naar externe servers (behalve de optionele Speedtest CLI)
- Slaat output ALLEEN lokaal op in de `output/` map
- WiFi profielen worden opgehaald met `netsh wlan show profiles` (toont namen, geen wachtwoorden)
- Klanthistorie wordt lokaal opgeslagen in `Data/klanten/` en nooit verstuurd

De Speedtest CLI (Ookla) communiceert met speedtest.net servers om snelheid te meten.
Dit is hetzelfde als handmatig speedtest.net bezoeken in een browser.

---

## Veldgebruik Handleiding

### Bij de klant binnenkomen

```
1. Laptop aansluiten (bekabeld als het kan)
2. Dubbelklik: netwerk-diagnose-v3_5-run.bat
3. Kies [1] Quick
4. Wacht 60-90 seconden
5. Kijk naar 00_summary.txt → Score bovenaan
```

### Score-actie tabel

| Score     | Wat je doet                                                       |
| --------- | ----------------------------------------------------------------- |
| **0-10**  | "Verbinding is prima." → Probleem zit elders (WiFi, PC, software) |
| **11-30** | Lees summary. Klein punt. Meestal WiFi of DNS. Quick is genoeg.   |
| **31-60** | Draai Full-mode. Er is een structureel probleem. Noteer alles.    |
| **61+**   | Niet weggaan zonder fix. Router/kabel/ISP issue.                  |

### Beslisboom

```
Score 0-10?
  └─ Klant klaagt over WiFi?
       ├─ Ja → Draai Full op de probleemplek (zolder/slaapkamer)
       └─ Nee → Probleem is software/PC, niet het netwerk

Score 11-30?
  └─ Lees DIAGNOSE sectie
       ├─ WiFi punt → Check kanaal, signaal, 2.4 vs 5 GHz
       ├─ DNS punt → Noteer, meestal niet urgent
       └─ CGNAT info → Alleen relevant bij port forwarding/gaming

Score 31-60?
  └─ Draai Full-mode diagnose
       ├─ Packet loss? → Check kabel, switch, router
       ├─ Hoge latency? → Check router belasting, dubbele NAT
       ├─ Trage speed? → Vergelijk met abonnement
       └─ MTU laag? → Check PPPoE/VPN configuratie

Score 61+?
  └─ Er is een concreet probleem
       ├─ Gateway down → Kabel/router defect
       ├─ Veel loss → Slechte kabel of overbelaste router
       ├─ Alles traag → ISP probleem, bel provider
       └─ Lees 99_advies.txt voor concrete stappen
```

### Wanneer Full-mode draaien?

- Score 31+ op Quick
- Klant klaagt over WiFi en Quick toont "bekabeld = prima"
- Je wilt DNS/MTU/service data voor documentatie
- Klant heeft gaming/VoIP problemen (jitter + MTU relevant)

### Wanneer stoppen?

- Score 0-10 en bekabeld getest → verbinding is niet het probleem
- Score 0-10 op WiFi probleemplek → WiFi is ook prima, probleem is software
- Alle pings 0% loss + jitter <5ms → netwerk is stabiel

### De 3 vragen die je altijd checkt

1. **Loss = 0%?** → Ja = mooi, Nee = probleem
2. **Latency stabiel?** → Geen spikes in max vs avg = mooi
3. **Jitter <15ms?** → Ja = videobellen/gaming OK

Als alle 3 OK zijn en score <10: het netwerk is niet de oorzaak.

### Na het bezoek

- Output map staat in `output/YYYY-MM-DD_HH-MM-SS/`
- Kopieer of mail de hele map als bewijs
- `00_summary.txt` + `99_advies.txt` = klantrapport
- `98_ai_analyse.txt` = technische onderbouwing

---

## Vereisten

- Windows 10 of 11
- PowerShell 5.1+ (standaard aanwezig)
- Geen installatie of admin-rechten nodig
- Optioneel: Speedtest CLI in `Tools/Portable/SpeedtestCLI/`

---

_SluisICT Netwerk Diagnose Toolkit v3.5_
