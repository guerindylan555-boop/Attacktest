@echo off
REM ============================================================================
REM MaynDrive APK Repackaging Script with Frida Gadget (Non-Root)
REM For Windows - Automates the Frida Gadget injection process
REM ============================================================================

setlocal enabledelayedexpansion

echo.
echo ╔═══════════════════════════════════════════════════════════╗
echo ║   MaynDrive APK Frida Gadget Injector                    ║
echo ║   Non-Root SSL Unpinning for Redmi 13C 4G                ║
echo ╚═══════════════════════════════════════════════════════════╝
echo.

REM Configuration
set APK_NAME=mayndrive_original.apk
set DECOMPILED_DIR=mayndrive_decompiled
set GADGET_FILE=frida-gadget-android-arm64.so
set OUTPUT_APK=mayndrive_signed.apk
set KEYSTORE=my-release-key.keystore
set KEYSTORE_ALIAS=my-key-alias

REM Check if original APK exists
if not exist "%APK_NAME%" (
    echo ❌ Error: %APK_NAME% not found!
    echo.
    echo Please extract the APK first:
    echo   adb shell pm path city.knot.mayndrive
    echo   adb pull /data/app/city.knot.mayndrive-xxx/base.apk %APK_NAME%
    echo.
    pause
    exit /b 1
)

REM Check if Frida Gadget exists
if not exist "%GADGET_FILE%" (
    echo ❌ Error: %GADGET_FILE% not found!
    echo.
    echo Please download Frida Gadget from:
    echo   https://github.com/frida/frida/releases
    echo.
    echo Download: frida-gadget-*-android-arm64.so
    echo Rename it to: %GADGET_FILE%
    echo.
    pause
    exit /b 1
)

echo ✓ Found: %APK_NAME%
echo ✓ Found: %GADGET_FILE%
echo.

REM ============================================================================
echo [1/7] Decompiling APK...
REM ============================================================================
if exist "%DECOMPILED_DIR%" (
    echo   Removing old decompiled directory...
    rmdir /s /q "%DECOMPILED_DIR%"
)

apktool d "%APK_NAME%" -o "%DECOMPILED_DIR%"
if errorlevel 1 (
    echo ❌ Failed to decompile APK
    pause
    exit /b 1
)
echo   ✓ APK decompiled to %DECOMPILED_DIR%
echo.

REM ============================================================================
echo [2/7] Adding Frida Gadget library...
REM ============================================================================
set LIB_DIR=%DECOMPILED_DIR%\lib\arm64-v8a
if not exist "%LIB_DIR%" mkdir "%LIB_DIR%"

copy "%GADGET_FILE%" "%LIB_DIR%\libfrida-gadget.so" >nul
if errorlevel 1 (
    echo ❌ Failed to copy Gadget library
    pause
    exit /b 1
)
echo   ✓ Gadget library added to %LIB_DIR%
echo.

REM ============================================================================
echo [3/7] Finding MainActivity...
REM ============================================================================
findstr /s /i "android.intent.action.MAIN" "%DECOMPILED_DIR%\AndroidManifest.xml" >nul
if errorlevel 1 (
    echo ⚠️  Could not find MainActivity automatically
    echo   Please edit the smali file manually
    pause
)
echo   ✓ Check AndroidManifest.xml for MainActivity
echo.

echo   ⚠️  MANUAL STEP REQUIRED:
echo   1. Open: %DECOMPILED_DIR%\smali\city\knot\mayndrive\MainActivity.smali
echo   2. Find the ^<init^> method (constructor)
echo   3. Add these lines after invoke-direct:
echo.
echo      const-string v0, "frida-gadget"
echo      invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
echo.
echo   4. Increment .locals count by 1
echo.
set /p continue="Press Enter after editing the smali file..."
echo.

REM ============================================================================
echo [4/7] Rebuilding APK...
REM ============================================================================
apktool b "%DECOMPILED_DIR%" -o "%DECOMPILED_DIR%.apk"
if errorlevel 1 (
    echo ❌ Failed to rebuild APK
    pause
    exit /b 1
)
echo   ✓ APK rebuilt: %DECOMPILED_DIR%.apk
echo.

REM ============================================================================
echo [5/7] Aligning APK...
REM ============================================================================
zipalign -v -p 4 "%DECOMPILED_DIR%.apk" "%DECOMPILED_DIR%_aligned.apk"
if errorlevel 1 (
    echo ❌ Failed to align APK
    pause
    exit /b 1
)
echo   ✓ APK aligned
echo.

REM ============================================================================
echo [6/7] Signing APK...
REM ============================================================================
if not exist "%KEYSTORE%" (
    echo   Creating new keystore...
    keytool -genkey -v -keystore "%KEYSTORE%" ^
            -keyalg RSA -keysize 2048 -validity 10000 ^
            -alias "%KEYSTORE_ALIAS%"
    if errorlevel 1 (
        echo ❌ Failed to create keystore
        pause
        exit /b 1
    )
)

apksigner sign --ks "%KEYSTORE%" --out "%OUTPUT_APK%" "%DECOMPILED_DIR%_aligned.apk"
if errorlevel 1 (
    echo ❌ Failed to sign APK
    pause
    exit /b 1
)

apksigner verify "%OUTPUT_APK%"
if errorlevel 1 (
    echo ❌ APK signature verification failed
    pause
    exit /b 1
)
echo   ✓ APK signed: %OUTPUT_APK%
echo.

REM ============================================================================
echo [7/7] Installing modified APK...
REM ============================================================================
echo   Uninstalling original app...
adb uninstall city.knot.mayndrive
echo.

echo   Installing modified app...
adb install "%OUTPUT_APK%"
if errorlevel 1 (
    echo ❌ Failed to install APK
    echo   Try installing manually: adb install %OUTPUT_APK%
    pause
    exit /b 1
)
echo   ✓ Modified APK installed
echo.

REM ============================================================================
echo ╔═══════════════════════════════════════════════════════════╗
echo ║   SUCCESS! Modified APK Ready                            ║
echo ╚═══════════════════════════════════════════════════════════╝
echo.
echo Next steps:
echo.
echo 1. Launch MaynDrive app on your phone
echo.
echo 2. Run Frida unpinning script from PC:
echo    frida -U Gadget -l ssl-unpinning.js
echo.
echo 3. Configure proxy on phone (WiFi settings):
echo    - Hostname: [Your PC IP]
echo    - Port: 8080
echo.
echo 4. Launch HTTP Toolkit or mitmproxy:
echo    mitmweb -p 8080
echo.
echo 5. Use the app and capture traffic!
echo.
echo ═══════════════════════════════════════════════════════════
echo.
pause

