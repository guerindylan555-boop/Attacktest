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
echo [+] NEW ACCOUNT TOKEN CAPTURE & CROSS-ACCOUNT TEST
echo ====================================================================================================
echo [!] This script will capture a token from your NEW account.
echo [!] Log in with your NEW account and perform an UNLOCK/LOCK operation.
echo ====================================================================================================

rem Kill old Frida server
echo [1/5] Killing old Frida server...
"%ADB_CMD%" shell "su -c 'pkill frida-server'" >nul 2>&1
echo [OK] Kill command sent

rem Start Frida server
echo [2/5] Starting Frida server...
echo [DEBUG] Checking if frida-server exists...
"%ADB_CMD%" shell "su -c 'ls /data/local/tmp/frida-server'" >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] frida-server not found in /data/local/tmp/. Please push it to the device.
    pause
    exit /b 1
)
echo [OK] frida-server binary found

echo [DEBUG] Checking if already running...
"%ADB_CMD%" shell "su -c 'pgrep frida-server'" >nul 2>&1
if %errorlevel% neq 0 (
    echo [DEBUG] Starting frida-server in background...
    "%ADB_CMD%" shell "su -c '/data/local/tmp/frida-server >/dev/null 2>&1 &'" >nul 2>&1
) else (
    echo [DEBUG] frida-server already running
)

echo [DEBUG] Verifying frida-server started...
timeout /t 2 /nobreak >nul
"%ADB_CMD%" shell "su -c 'pgrep frida-server'" >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] frida-server failed to start
    pause
    exit /b 1
)
echo [OK] frida-server is running

rem Force-stop MaynDrive app
echo [3/5] Force-stopping MaynDrive app...
"%ADB_CMD%" shell "am force-stop fr.mayndrive.app" >nul 2>&1
echo [OK] App force-stopped

rem Verify Frida connection
echo [4/5] Verifying Frida connection...
py -m frida_tools.ps -U
echo.

rem Run the Python script to capture
echo [5/5] Starting new account capture...
echo ====================================================================================================
echo CAPTURE STARTING - APP WILL AUTO-LAUNCH
echo ====================================================================================================
echo.

set ADB_PATH=%ADB_CMD%
py capture_new_account.py
if %errorlevel% neq 0 (
    echo [ERROR] Python script failed.
    pause
    exit /b 1
)

echo.
echo [+] Capture complete!
echo [OK] Token automatically saved to LATEST_TOKEN.txt
echo [OK] You can now run: py test_tuf061_unlock.py
echo.
pause