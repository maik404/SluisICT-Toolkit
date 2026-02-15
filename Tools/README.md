# Tools – Downloadlinks

Deze tools worden **niet** meegeleverd in de Git repository (te groot / third-party licenties).  
Download ze handmatig en plaats ze in de juiste map.

---

## Netwerk

| Tool | Map | Download |
|------|-----|----------|
| Advanced IP Scanner | `Tools/Netwerk/AdvancedIPScanner/` | https://www.advanced-ip-scanner.com/nl/ |
| Angry IP Scanner | `Tools/Netwerk/AngryIPScanner/` | https://angryip.org/download/ |
| Speedtest CLI (Ookla) | `Tools/Netwerk/SpeedtestCLI/` | https://www.speedtest.net/apps/cli |
| WinMTR | `Tools/Netwerk/WinMTR/` | https://sourceforge.net/projects/winmtr/ |
| WiFi Analyzer | `Tools/Netwerk/WifiAnalyzer/` | Microsoft Store of https://github.com/vrem/WiFiAnalyzer |

## Portable

| Tool | Map | Download |
|------|-----|----------|
| 7-Zip Portable | `Tools/Portable/7zip/` | https://www.7-zip.org/download.html |
| NirSoft Tools | `Tools/Portable/NirSoft/` | https://www.nirsoft.net/ |
| Notepad++ Portable | `Tools/Portable/NotepadPP/` | https://notepad-plus-plus.org/downloads/ |
| Patch My PC | `Tools/Portable/PatchMyPC/` | https://patchmypc.com/home-updater |
| Speedtest CLI (Ookla) | `Tools/Portable/SpeedtestCLI/` | https://www.speedtest.net/apps/cli |

## Recovery

| Tool | Map | Download |
|------|-----|----------|
| Hiren's Boot CD PE | `Tools/recovery/Hiren/` | https://www.hirensbootcd.org/ |
| LinuxLive USB Creator | `Tools/recovery/LinuxLive/` | https://www.linuxliveusb.com/ |
| MemTest86 | `Tools/recovery/MemTest86/` | https://www.memtest86.com/ |
| Ventoy | `Tools/recovery/Ventoy/` | https://www.ventoy.net/ |
| Windows ISO | `Tools/recovery/WindowsISO/` | https://www.microsoft.com/software-download/windows11 |

## Security

| Tool | Map | Download |
|------|-----|----------|
| Malwarebytes | `Tools/security/Malwarebytes/` | https://www.malwarebytes.com/mwb-download |
| O&O ShutUp10++ | `Tools/security/OOSU10/` | https://www.oo-software.com/en/shutup10 |

## System

| Tool | Map | Download |
|------|-----|----------|
| Autoruns | `Tools/system/Autoruns/` | https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns |
| CrystalDiskInfo | `Tools/system/CrystalDiskInfo/` | https://crystalmark.info/en/software/crystaldiskinfo/ |
| HWiNFO | `Tools/system/HWInfo/` | https://www.hwinfo.com/download/ |
| Sysinternals Suite | `Tools/system/SysinternalsSuite/` | https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite |
| TCPView | `Tools/system/TCPView/` | https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview |

---

## Snel installeren

Na het clonen van de repo:

```powershell
# Maak de mappen aan
$dirs = @(
    "Tools/Netwerk/AdvancedIPScanner",
    "Tools/Netwerk/AngryIPScanner",
    "Tools/Netwerk/SpeedtestCLI",
    "Tools/Netwerk/WinMTR",
    "Tools/Netwerk/WifiAnalyzer",
    "Tools/Portable/7zip",
    "Tools/Portable/NirSoft",
    "Tools/Portable/NotepadPP",
    "Tools/Portable/PatchMyPC",
    "Tools/Portable/SpeedtestCLI",
    "Tools/recovery/Hiren",
    "Tools/recovery/LinuxLive",
    "Tools/recovery/MemTest86",
    "Tools/recovery/Ventoy",
    "Tools/recovery/WindowsISO",
    "Tools/security/Malwarebytes",
    "Tools/security/OOSU10",
    "Tools/system/Autoruns",
    "Tools/system/CrystalDiskInfo",
    "Tools/system/HWInfo",
    "Tools/system/SysinternalsSuite",
    "Tools/system/TCPView"
)
$dirs | ForEach-Object { New-Item -ItemType Directory -Path $_ -Force }
```

Download daarna de tools via de links hierboven en pak ze uit in de juiste map.

> **Let op:** Alleen `speedtest.exe` in `Tools/Portable/SpeedtestCLI/` is vereist voor het diagnose script. De rest is optioneel.
