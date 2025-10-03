@echo off
setlocal enableextensions enabledelayedexpansion

set "ADB_CMD="
set "ADB_BASE=platform-tools"

if not exist "%ADB_BASE%\adb.exe" (
    if exist "platform-tools.zip" (
        echo [INFO] Extracting platform-tools.zip...
        powershell -NoProfile -Command "Expand-Archive -LiteralPath 'platform-tools.zip' -DestinationPath '.' -Force" >nul 2>&1
    )
)

if exist "%ADB_BASE%\adb.exe" set "ADB_CMD=%ADB_BASE%\adb.exe"

if not defined ADB_CMD (
    for /f "delims=" %%F in ('dir /b /s "platform-tools\adb.exe" 2^>nul') do (
        if not defined ADB_CMD set "ADB_CMD=%%F"
    )
)

if not defined ADB_CMD (
    for %%F in (adb.exe) do (
        if not defined ADB_CMD set "ADB_CMD=%%~$PATH:F"
    )
)

if not defined ADB_CMD (
    echo [ERROR] Unable to locate adb.exe. Make sure platform-tools.zip is present or adb is in PATH.
    pause
    exit /b 1
)

echo ====================================================================================================
echo COMPLETE CAPTURE WITH DECRYPTION
echo ====================================================================================================
echo.
echo This script captures ALL layers: HTTP + Cipher + UDP
echo.
echo INSTRUCTIONS:
echo  1. Wait for hooks to install
echo  2. App will auto-launch
echo  3. UNLOCK or LOCK a scooter
echo  4. Watch for "[COROUTINE]" messages with unlock/lock data
echo  5. Press Ctrl+C when done
echo.
echo ====================================================================================================
echo.

echo [1/5] Killing old Frida server...
"%ADB_CMD%" shell su -c "pkill frida-server" >nul 2>&1
timeout /t 2 >nul
echo [OK] Kill command sent
echo.

echo [2/5] Starting Frida server...
echo [DEBUG] Checking if frida-server exists...
"%ADB_CMD%" shell "su -c 'ls -l /data/local/tmp/frida-server'" 2>nul | find "frida-server" >nul
if %errorlevel% NEQ 0 (
    echo [ERROR] frida-server not found at /data/local/tmp/frida-server
    echo [INFO] Please push frida-server first:
    echo        adb push frida-server-17.3.2-android-arm /data/local/tmp/frida-server
    echo        adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
    pause
    exit /b 1
)
echo [OK] frida-server binary found

echo [DEBUG] Checking if already running...
"%ADB_CMD%" shell "su -c 'ps | grep frida-server'" 2>nul | find "frida-server" >nul
if %errorlevel% EQU 0 (
    echo [OK] frida-server already running - skipping start
    goto :frida_running
)

echo [DEBUG] Starting frida-server in background...
"%ADB_CMD%" shell "su -c 'nohup /data/local/tmp/frida-server >/dev/null 2>&1 &'" 2>nul
timeout /t 3 /nobreak >nul

echo [DEBUG] Verifying frida-server started...
"%ADB_CMD%" shell "su -c 'ps | grep frida-server'" 2>nul | find "frida-server" >nul
if %errorlevel% NEQ 0 (
    echo [ERROR] frida-server failed to start!
    pause
    exit /b 1
)

:frida_running
echo [OK] frida-server is running
echo.

echo [3/5] Force-stopping MaynDrive app...
"%ADB_CMD%" shell am force-stop fr.mayndrive.app
timeout /t 1 >nul
echo.

echo [4/5] Verifying Frida connection...
py -m frida_tools.ps -U
echo.

echo [5/5] Starting enhanced capture with decryption hooks...
echo.

echo ====================================================================================================
echo CAPTURE STARTING - APP WILL AUTO-LAUNCH
echo ====================================================================================================
echo.

py capture_decrypt.py
