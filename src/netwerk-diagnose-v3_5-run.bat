@echo off
title SluisICT Netwerk Diagnose v3.5
color 0F

:MENU
cls
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
echo    [5]  Alleen speedtest        (30-60 sec)
echo.
echo    [0]  Afsluiten
echo.

set "MODUS=1"
set /p MODUS="  Keuze (0/1/2/3/4/5) [1]: "

if "%MODUS%"=="0" goto EXIT

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
if "%MODUS%"=="5" (
    set "PARAMS=-SpeedtestOnly"
    echo  Modus: ALLEEN SPEEDTEST
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
echo  Diagnose voltooid.
echo  Druk op een toets om terug te gaan naar het menu...
echo  ===========================================
pause >nul
goto MENU

:EXIT
echo.
echo  Tot ziens!
echo.
