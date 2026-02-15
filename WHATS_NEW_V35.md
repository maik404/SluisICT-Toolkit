# SluisICT Netwerk Diagnose v3.5 - Professional

## Wat is nieuw in v3.5?

### RISICO SCORE (nieuw)

Bovenaan elke summary: één getal, direct duidelijk.

```
Score:    0/100 ✅ GEZOND
```

| Score | Label           | Betekenis                          |
| ----- | --------------- | ---------------------------------- |
| 0-10  | ✅ GEZOND       | Geen actie nodig                   |
| 11-30 | ⚠ AANDACHTSPUNT | Klein verbeterpunt                 |
| 31-60 | ❌ PROBLEEM     | Structureel issue, onderzoek nodig |
| 61+   | ❌ ACTIE NODIG  | Direct ingrijpen                   |

Factoren: gateway loss/latency, internet loss/latency, jitter, snelheid, WiFi signaal, gevonden issues/warnings.

### VELD-PROOF MELDINGEN

Meldingen zijn **professioneel gekalibreerd** — geen valse alarmen:

- **DHCP handmatig IP** → `✅ OK (handmatig IP)` (geen waarschuwing tenzij connectivity faalt)
- **Veel DNS servers** → `✅ OK (7 servers)` (aantal ≠ probleem, prestatie wel)
- **CGNAT** → `ℹ INFO` in aparte sectie (niet `⚠`) — alleen relevant bij port forwarding/gaming
- **Conclusie consistent** — als "geen actie nodig" → dan is conclusie `✅ GEZOND`

### KLANT-INTERPRETATIE

Elke summary bevat nu één menselijke regel:

```
Voor deze verbinding (bekabeld): videobellen/gaming uitstekend.
port forwarding mogelijk lastig door CGNAT.
```

Contextbewust: past aan op basis van WiFi/bekabeld, jitter-kwaliteit en CGNAT-status.

### ADAPTER INTELLIGENTIE

Herkent automatisch **virtuele adapters** (Docker, WSL, Hyper-V, VMware, VirtualBox) en **VPN adapters**. Worden genegeerd bij NAT-detectie → geen valse "dubbele NAT" meldingen.

Classificatie:

- **Fysiek**: Echte netwerkkaart (Ethernet, WiFi)
- **Virtueel**: Docker vEthernet, WSL, Hyper-V, VMware, VirtualBox
- **VPN**: WireGuard, OpenVPN, Cisco AnyConnect, NordVPN, etc.

### AI ANALYSE v3.5

12 detectie-patronen met **AND-logica** (evidence + condition moeten beide waar zijn):

1. Dubbele NAT (adapter-aware)
2. Dubbele DHCP
3. Zwak WiFi signaal
4. 2.4GHz WiFi gebruik
5. Packet loss
6. Hoge latency
7. Trage internetsnelheid
8. Hoge jitter
9. Trage DNS
10. MTU probleem
11. WiFi congestie
12. Service blokkering

Patronen zijn configureerbaar via `patterns.json`. Geen false positives meer door verbeterde trigger-logica.

## Diagnose modes

### Quick (7 stappen) — standaard

| Stap | Beschrijving                        |
| ---- | ----------------------------------- |
| 1/7  | Netwerkdata + adapter classificatie |
| 2/7  | WiFi snapshot                       |
| 3/7  | Ping + traceroute                   |
| 4/7  | Netwerk analyse                     |
| 5/7  | Speedtest                           |
| 6/7  | Raw data + rapportage               |
| 7/7  | AI analyse                          |

### Full (13 stappen) — met `-Full`

| Stap  | Beschrijving                        |
| ----- | ----------------------------------- |
| 1/13  | Netwerkdata + adapter classificatie |
| 2/13  | WiFi snapshot                       |
| 3/13  | Ping + traceroute                   |
| 4/13  | Netwerk analyse                     |
| 5/13  | DNS prestatie analyse               |
| 6/13  | WiFi omgevingsscan                  |
| 7/13  | MTU discovery                       |
| 8/13  | Service bereikbaarheid (8 services) |
| 9/13  | Security + IPv6                     |
| 10/13 | Speedtest                           |
| 11/13 | Raw data + rapportage               |
| 12/13 | Extra Full-mode bestanden           |
| 13/13 | AI analyse                          |

## Output bestanden

### Altijd (Quick + Full)

| Bestand                      | Inhoud                    |
| ---------------------------- | ------------------------- |
| 00_summary.txt               | Overzicht + risicoscore   |
| 01_ipconfig_all.txt          | Volledige IP configuratie |
| 02_routes.txt                | Route tabel               |
| 03_arp.txt                   | ARP cache                 |
| 04_netstat_ano.txt           | Actieve verbindingen      |
| 05_dns_nslookup.txt          | DNS resolution test       |
| 06_ping_gateway.txt          | Gateway ping (10x)        |
| 07_ping_8.8.8.8.txt          | Internet ping (20x)       |
| 08_tracert_8.8.8.8.txt       | Traceroute                |
| 09_wifi_netsh_interfaces.txt | WiFi interface details    |
| 10_wifi_profiles.txt         | Opgeslagen WiFi profielen |
| 11_speedtest_cli.json        | Speedtest ruwe data       |
| 12_speedtest_readable.txt    | Speedtest leesbaar        |
| 17_security_adapters.txt     | Security + adapter info   |
| 18_jitter_analysis.txt       | Jitter analyse            |
| 98_ai_analyse.txt            | AI analyse rapport        |
| 99_advies.txt                | Concrete aanbevelingen    |

### Alleen Full-mode

| Bestand                     | Inhoud                  |
| --------------------------- | ----------------------- |
| 13_dns_performance.txt      | DNS server prestaties   |
| 14_mtu_test.txt             | MTU discovery resultaat |
| 15_wifi_environment.txt     | WiFi omgevingsscan      |
| 16_service_reachability.txt | Service bereikbaarheid  |

## Bestanden

```
src/
  netwerk-diagnose-v3_5.ps1          # Hoofdscript (~1800 regels)
  Invoke-SluisICT-AIAnalysis.ps1     # AI analyse module (~580 regels)
  patterns.json                       # 12 detectie-patronen
  netwerk-diagnose-v3_5-run.bat      # Windows launcher (4 opties)
docs/
  README.md                           # Troubleshooting + privacy
```

## Launcher opties

```
1. Quick diagnose (standaard)
2. Full diagnose (alle 13 stappen)
3. Quick zonder speedtest
4. Full zonder speedtest
```

## Risicoscore berekening

| Factor                | Gewicht      |
| --------------------- | ------------ |
| Gateway onbereikbaar  | +50          |
| Gateway loss >10%     | +30          |
| Gateway loss >2%      | +15          |
| Gateway latency >50ms | +15          |
| Internet down         | +25          |
| Internet loss >5%     | +15          |
| Internet latency >100 | +10          |
| Jitter SLECHT         | +15          |
| Jitter MATIG          | +8           |
| Speed <10 Mbps        | +15          |
| Speed <25 Mbps        | +10          |
| WiFi <30%             | +15          |
| WiFi <50%             | +8           |
| Per Issue             | +10 (max 30) |
| Per Warning           | +3 (max 15)  |

Maximum: 100 (geclamped).
