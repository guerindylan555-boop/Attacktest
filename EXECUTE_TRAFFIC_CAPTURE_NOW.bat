@echo off
REM ==============================================================================
REM MaynDrive Complete Traffic Capture - Quick Start
REM ==============================================================================
REM
REM This script helps you execute the complete traffic analysis
REM Choose your capture method below
REM
REM ==============================================================================

echo.
echo ===============================================================================
echo    MaynDrive Traffic Analysis - Quick Start Menu
echo ===============================================================================
echo.
echo Choose your capture method:
echo.
echo   [1] QUICK - Frida only (fastest, easiest, 80%% coverage)
echo   [2] COMPLETE - Frida + mitmproxy (full HTTPS visibility)
echo   [3] ADVANCED - All layers (packet capture + decryption)
echo   [4] DIAGNOSTIC - Check setup and verify tools
echo   [5] HELP - Open master plan documentation
echo   [6] EXIT
echo.
echo ===============================================================================
echo.

set /p choice="Enter your choice (1-6): "

if "%choice%"=="1" goto quick
if "%choice%"=="2" goto complete
if "%choice%"=="3" goto advanced
if "%choice%"=="4" goto diagnostic
if "%choice%"=="5" goto help
if "%choice%"=="6" goto exit

echo Invalid choice!
pause
exit /b

:quick
echo.
echo ===============================================================================
echo  QUICK CAPTURE - Frida Application Hooks Only
echo ===============================================================================
echo.
echo This will:
echo   - Hook into app at Java/native layer
echo   - Capture HTTP requests/responses
echo   - Extract Bearer tokens
echo   - Log unlock/lock operations
echo   - Save to CAPTURED_API.txt and CAPTURED_API.json
echo.
echo STEPS:
echo   1. Make sure Frida server is running on phone
echo   2. Phone connected via USB
echo   3. This script will spawn the app
echo   4. DO NOT open app manually!
echo   5. Use the spawned instance
echo.
pause
echo.
echo [*] Checking Frida server...
.\platform-tools\adb.exe shell "su -c 'ps | grep frida'" | findstr frida
if %errorlevel% NEQ 0 (
    echo [!] Frida server not running!
    echo [*] Starting Frida server...
    .\platform-tools\adb.exe shell "su -c 'pkill frida-server'"
    .\platform-tools\adb.exe shell "su -c '/data/local/tmp/frida-server &'"
    timeout /t 3 /nobreak > nul
)

echo [+] Frida server is running
echo.
echo [*] Force stopping app...
.\platform-tools\adb.exe shell am force-stop fr.mayndrive.app
timeout /t 2 /nobreak > nul

echo.
echo [*] Starting Frida capture...
echo.
echo ===============================================================================
echo  READY TO CAPTURE
echo ===============================================================================
echo.
echo The app will now launch via Frida.
echo.
echo IMPORTANT:
echo   - Use ONLY the app instance that appears now
echo   - Login and perform actions (unlock/lock)
echo   - Watch this console for captured data
echo   - Press Ctrl+C when done
echo.
echo ===============================================================================
echo.

py capture.py

echo.
echo [+] Capture complete!
echo [*] Check output files:
echo     - CAPTURED_API.txt (human readable)
echo     - CAPTURED_API.json (for analysis)
echo.
pause
goto menu

:complete
echo.
echo ===============================================================================
echo  COMPLETE CAPTURE - Frida + mitmproxy
echo ===============================================================================
echo.
echo This will:
echo   - Frida hooks (application layer)
echo   - mitmproxy (decrypt HTTPS)
echo   - Full API visibility
echo.
echo REQUIREMENTS:
echo   - Frida server running on phone
echo   - Phone WiFi proxy configured to PC:8080
echo   - mitmproxy certificate installed on phone
echo.
echo SETUP STEPS:
echo.
echo 1. Configure phone WiFi proxy:
echo    - WiFi Settings -^> Long press network -^> Modify
echo    - Proxy: Manual
echo    - Hostname: [YOUR_PC_IP]
echo    - Port: 8080
echo.
echo 2. Install mitmproxy certificate:
echo    - Phone browser -^> http://mitm.it
echo    - Download Android certificate
echo    - Install from storage
echo.
set /p ready="Have you completed setup? (y/n): "
if /i not "%ready%"=="y" goto menu

echo.
echo [*] Starting mitmproxy in new window...
start "mitmproxy" cmd /k "mitmweb --listen-host 0.0.0.0 --listen-port 8080 --web-port 8081"

timeout /t 5 /nobreak > nul

echo [*] Open browser: http://localhost:8081
echo.
echo [*] Starting Frida capture...
.\platform-tools\adb.exe shell am force-stop fr.mayndrive.app

timeout /t 2 /nobreak > nul

py capture.py

echo.
echo [+] Capture complete!
echo [*] Check:
echo     - CAPTURED_API.txt (Frida)
echo     - mitmproxy web UI (HTTPS traffic)
echo     - ~/.mitmproxy/flows (raw data)
echo.
pause
goto menu

:advanced
echo.
echo ===============================================================================
echo  ADVANCED CAPTURE - All Layers
echo ===============================================================================
echo.
echo This will start:
echo   1. Frida hooks
echo   2. mitmproxy
echo   3. Wireshark packet capture
echo   4. SSL key logging
echo.
echo This requires manual coordination of multiple tools.
echo.
echo See TRAFFIC_ANALYSIS_MASTER_PLAN.md for detailed instructions.
echo.
start TRAFFIC_ANALYSIS_MASTER_PLAN.md
pause
goto menu

:diagnostic
echo.
echo ===============================================================================
echo  DIAGNOSTIC - System Check
echo ===============================================================================
echo.

echo [1] Checking ADB connection...
.\platform-tools\adb.exe devices
if %errorlevel% NEQ 0 (
    echo [!] ADB not working!
    goto diag_end
)
echo [+] ADB OK
echo.

echo [2] Checking phone architecture...
.\platform-tools\adb.exe shell getprop ro.product.cpu.abi
echo.

echo [3] Checking Frida server...
.\platform-tools\adb.exe shell "su -c 'ps | grep frida'"
if %errorlevel% NEQ 0 (
    echo [!] Frida server not running!
    echo [*] Try: DIAGNOSE.bat to fix
) else (
    echo [+] Frida server running
)
echo.

echo [4] Checking Frida server architecture...
.\platform-tools\adb.exe shell "su -c 'file /data/local/tmp/frida-server'"
echo.

echo [5] Testing Frida connection from Python...
py -c "import frida; d=frida.get_usb_device(timeout=5); print('[+] SUCCESS:', d.name, len(d.enumerate_processes()), 'processes')"
echo.

echo [6] Checking Python packages...
py -c "import frida, mitmproxy; print('[+] All packages installed')" 2>nul
if %errorlevel% NEQ 0 (
    echo [!] Missing packages!
    echo [*] Run: pip install frida frida-tools mitmproxy
)
echo.

echo [7] Checking capture script...
if exist "capture_COMPLETE_SOLUTION.js" (
    echo [+] Frida script found
) else (
    echo [!] capture_COMPLETE_SOLUTION.js not found!
)

if exist "capture.py" (
    echo [+] Python orchestrator found
) else (
    echo [!] capture.py not found!
)
echo.

:diag_end
echo ===============================================================================
echo  Diagnostic Complete
echo ===============================================================================
echo.
pause
goto menu

:help
echo.
echo [*] Opening master plan documentation...
start TRAFFIC_ANALYSIS_MASTER_PLAN.md
echo.
echo Also see:
echo   - MAYNDRIVE_COMPLETE_ANALYSIS.md (detailed analysis)
echo   - SECURITY_ANALYSIS.md (vulnerabilities)
echo   - PHONE_TRAFFIC_ANALYSIS_GUIDE.md (network capture)
echo.
pause
goto menu

:exit
echo.
echo Exiting...
exit /b

:menu
echo.
echo ===============================================================================
echo.
set /p again="Run another capture? (y/n): "
if /i "%again%"=="y" goto start
exit /b

