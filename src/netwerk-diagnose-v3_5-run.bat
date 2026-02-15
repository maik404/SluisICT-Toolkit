@echo off
title SluisICT Netwerk Diagnose v3.5
color 0F
echo.
echo ===========================================
echo  SluisICT Netwerk Diagnose v3.5
echo ===========================================
echo.
echo  Kies uw diagnose modus:
echo.
echo    [1]  Quick diagnose          (60-90 sec)
echo    [2]  Volledige diagnose      (3-8 min)
echo    [3]  Quick zonder speedtest  (30 sec)
echo    [4]  Full zonder speedtest   (2-5 min)
echo.

set "MODUS=1"
set /p MODUS="  Keuze (1/2/3/4) [1]: "

echo.
set "KLANT="
set /p KLANT="  Klantnaam (optioneel, Enter = overslaan): "

echo.
set "PARAMS="
if "%MODUS%"=="1" (
    set "PARAMS="
    echo  Modus: QUICK
)
if "%MODUS%"=="2" (
    set "PARAMS=-Full"
    echo  Modus: FULL
)
if "%MODUS%"=="3" (
    set "PARAMS=-NoSpeedtest"
    echo  Modus: QUICK zonder speedtest
)
if "%MODUS%"=="4" (
    set "PARAMS=-Full -NoSpeedtest"
    echo  Modus: FULL zonder speedtest
)

if not "%KLANT%"=="" (
    set "PARAMS=%PARAMS% -ClientName "%KLANT%""
    echo  Klant: %KLANT%
)

echo.
echo  Start diagnose...
echo  ===========================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0netwerk-diagnose-v3_5.ps1" %PARAMS%

echo.
echo  ===========================================
echo  Diagnose voltooid. Druk op een toets.
echo  ===========================================
pause >nul
