@echo off
echo.
echo ╔═══════════════════════════════════════════════════════════╗
echo ║   Authorize Device and Install APK                       ║
echo ╚═══════════════════════════════════════════════════════════╝
echo.

set ADB=platform-tools\adb.exe

echo ⚠️  IMPORTANT: Check your phone NOW!
echo.
echo You should see a popup asking:
echo   "Allow USB debugging?"
echo   [ ] Always allow from this computer
echo   [Deny] [Allow]
echo.
echo 1. Check the box "Always allow from this computer"
echo 2. Tap "Allow"
echo.
pause

echo.
echo Checking device status...
%ADB% devices
echo.

echo Attempting installation...
echo.

echo [1/3] Uninstalling original app...
%ADB% uninstall fr.mayndrive.app
if %errorlevel% neq 0 (
    echo   Original app not found or already uninstalled - OK
)
echo.

echo [2/3] Installing modified APK...
%ADB% install mayndrive_frida_injected.apk
if %errorlevel% neq 0 (
    echo.
    echo ❌ Installation failed!
    echo.
    echo Possible solutions:
    echo 1. Make sure you authorized USB debugging on your phone
    echo 2. Run: platform-tools\adb kill-server
    echo 3. Then run this script again
    echo.
    pause
    exit /b 1
)
echo   ✓ APK installed successfully!
echo.

echo [3/3] Pushing SSL unpinning script...
%ADB% push ssl-unpinning.js /data/local/tmp/
%ADB% shell chmod 644 /data/local/tmp/ssl-unpinning.js
echo   ✓ Script pushed successfully!
echo.

echo ╔═══════════════════════════════════════════════════════════╗
echo ║   ✅ Installation Complete!                               ║
echo ╚═══════════════════════════════════════════════════════════╝
echo.
echo Your phone should now have MaynDrive with Frida Gadget!
echo.
echo Next steps:
echo.
echo 1. Launch MaynDrive app on your phone
echo.
echo 2. Install Frida on your PC (if not already):
echo    pip install frida-tools
echo.
echo 3. Run Frida:
echo    frida -U Gadget -l ssl-unpinning.js
echo.
echo 4. Configure WiFi proxy on phone:
echo    Find your PC IP: ipconfig
echo    Then on phone: Settings → WiFi → Modify → Proxy Manual
echo    Hostname: [Your PC IP]
echo    Port: 8080
echo.
echo 5. Start mitmproxy:
echo    mitmweb -p 8080
echo.
echo 6. Use MaynDrive and watch traffic in browser at:
echo    http://localhost:8081
echo.
pause

