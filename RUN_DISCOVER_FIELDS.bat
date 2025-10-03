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
    echo [ERROR] Unable to locate adb.exe
    pause
    exit /b 1
)

echo ====================================================================================================
echo FIELD DISCOVERY - Find Correct Field Names
echo ====================================================================================================
echo.
echo This will show ALL fields in unlock/lock coroutines
echo so we can identify the correct field names for Bearer token, serial, etc.
echo.
echo ====================================================================================================
echo.

echo [1/3] Killing old Frida server...
"%ADB_CMD%" shell su -c "pkill frida-server" >nul 2>&1
timeout /t 2 >nul
echo [OK] Kill command sent
echo.

echo [2/3] Starting Frida server...
"%ADB_CMD%" shell "su -c 'nohup /data/local/tmp/frida-server >/dev/null 2>&1 &'" 2>nul
timeout /t 3 /nobreak >nul
echo [OK] frida-server started
echo.

echo [3/3] Force-stopping MaynDrive app...
"%ADB_CMD%" shell am force-stop fr.mayndrive.app
timeout /t 1 >nul
echo.

echo ====================================================================================================
echo DISCOVERY STARTING - APP WILL AUTO-LAUNCH
echo ====================================================================================================
echo.

py -c "import frida; import sys; d=frida.get_usb_device(); pid=d.spawn(['fr.mayndrive.app']); s=d.attach(pid); script=s.create_script(open('capture_DISCOVER_FIELDS.js').read()); script.load(); d.resume(pid); print('[+] App launched! Now UNLOCK or LOCK a scooter...'); print('[+] Watch for field values - look for Bearer tokens and serials'); print(''); sys.stdin.read()"

echo.
echo [+] Discovery complete!
echo.
pause

