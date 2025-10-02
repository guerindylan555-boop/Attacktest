@echo off
echo.
echo ╔═══════════════════════════════════════════════════════════╗
echo ║   ADB Installation Helper                                 ║
echo ╚═══════════════════════════════════════════════════════════╝
echo.

REM Check if ADB is already available
where adb >nul 2>&1
if %errorlevel% equ 0 (
    echo ✓ ADB is already installed!
    adb version
    goto :install_apk
)

echo ADB not found in PATH. Let's install it...
echo.

REM Option 1: Download platform-tools
echo Downloading Android Platform Tools...
echo.

powershell -Command "& {Invoke-WebRequest -Uri 'https://dl.google.com/android/repository/platform-tools-latest-windows.zip' -OutFile 'platform-tools.zip'}"

if exist platform-tools.zip (
    echo ✓ Downloaded successfully!
    echo.
    echo Extracting...
    powershell -Command "Expand-Archive -Path 'platform-tools.zip' -DestinationPath '.' -Force"
    
    if exist platform-tools\adb.exe (
        echo ✓ Extracted successfully!
        echo.
        
        REM Add to PATH for current session
        set PATH=%CD%\platform-tools;%PATH%
        
        echo ✓ ADB is now available!
        platform-tools\adb.exe version
        echo.
        
        goto :install_apk
    ) else (
        echo ❌ Extraction failed
        pause
        exit /b 1
    )
) else (
    echo ❌ Download failed
    echo.
    echo Please download manually from:
    echo https://developer.android.com/tools/releases/platform-tools
    echo.
    pause
    exit /b 1
)

:install_apk
echo.
echo ═══════════════════════════════════════════════════════════
echo   Installing Modified APK
echo ═══════════════════════════════════════════════════════════
echo.

REM Set ADB path
if exist platform-tools\adb.exe (
    set ADB=platform-tools\adb.exe
) else (
    set ADB=adb
)

REM Check device connection
echo [1/4] Checking device connection...
%ADB% devices
echo.

set /p continue="Is your device listed above? (y/n): "
if /i not "%continue%"=="y" (
    echo.
    echo ❌ Device not found!
    echo.
    echo Troubleshooting:
    echo 1. Enable USB Debugging on your phone:
    echo    Settings → About Phone → Tap "Build Number" 7 times
    echo    Settings → Developer Options → Enable "USB Debugging"
    echo.
    echo 2. Connect your phone via USB
    echo.
    echo 3. Check "Always allow from this computer" when prompted
    echo.
    pause
    exit /b 1
)

echo.
echo [2/4] Uninstalling original app...
%ADB% uninstall fr.mayndrive.app
echo.

echo [3/4] Installing modified APK...
%ADB% install mayndrive_frida_injected.apk
echo.

echo [4/4] Pushing SSL unpinning script...
%ADB% push ssl-unpinning.js /data/local/tmp/
%ADB% shell chmod 644 /data/local/tmp/ssl-unpinning.js
echo.

echo ╔═══════════════════════════════════════════════════════════╗
echo ║   ✅ Installation Complete!                               ║
echo ╚═══════════════════════════════════════════════════════════╝
echo.
echo Next steps:
echo.
echo 1. Launch MaynDrive app on your phone
echo.
echo 2. On your PC, run:
echo    frida -U Gadget -l ssl-unpinning.js
echo.
echo    (If frida not found, install with: pip install frida-tools)
echo.
echo 3. Configure WiFi proxy on your phone:
echo    - Settings → WiFi → Long press network → Modify
echo    - Proxy: Manual
echo    - Hostname: (your PC IP - use 'ipconfig' to find)
echo    - Port: 8080
echo.
echo 4. Start mitmproxy:
echo    mitmweb -p 8080
echo.
echo 5. Use MaynDrive app and capture traffic!
echo.
pause

