@echo off
setlocal enableextensions

set "ADB_CMD=.\platform-tools\adb.exe"

echo ====================================================================================================
echo FRIDA DIAGNOSTIC - MaynDrive Analysis
echo ====================================================================================================
echo.

echo [1] Device connected?
%ADB_CMD% devices
echo.

echo [2] Device architecture?
for /f "tokens=*" %%A in ('%ADB_CMD% shell getprop ro.product.cpu.abi 2^>nul') do (
    set "CPU_ABI=%%A"
    echo CPU ABI: %%A
    
    echo %%A | findstr /C:"arm64" >nul && (
        echo Architecture: 64-bit ARM
        echo Required: frida-server-*-android-arm64
    ) || (
        echo Architecture: 32-bit ARM
        echo Required: frida-server-*-android-arm ^(NOT arm64!^)
    )
)
echo.

echo [3] Frida server running?
%ADB_CMD% shell "su -c 'ps | grep frida'" 2>nul
if errorlevel 1 (
    echo WARNING: Frida server not found!
) else (
    echo OK: Frida server is running
)
echo.

echo [4] Frida server architecture?
%ADB_CMD% shell "su -c 'file /data/local/tmp/frida-server'" 2>nul
echo.

echo [5] Python can connect to Frida?
py -c "import frida; d=frida.get_usb_device(timeout=5); print('SUCCESS:', d.name, '-', len(d.enumerate_processes()), 'processes')" 2>nul
if errorlevel 1 (
    echo ERROR: Python cannot connect to Frida
    echo.
    echo TROUBLESHOOTING:
    echo - Check that Frida server is running ^(step 3^)
    echo - Check that Frida server matches device architecture ^(step 2 vs step 4^)
    echo - Try: pip install frida frida-tools
) else (
    echo OK: Python-Frida connection working!
)
echo.

echo ====================================================================================================
echo DIAGNOSIS COMPLETE
echo ====================================================================================================
echo.
echo Next steps:
echo 1. If architecture mismatch, download correct Frida server:
echo    https://github.com/frida/frida/releases/tag/17.3.2
echo.
echo 2. Extract and push:
echo    7z x frida-server-17.3.2-android-arm.xz
echo    %ADB_CMD% push frida-server-17.3.2-android-arm /data/local/tmp/frida-server
echo.
echo 3. Restart Frida server:
echo    %ADB_CMD% shell "su -c 'pkill frida-server'"
echo    %ADB_CMD% shell "su -c '/data/local/tmp/frida-server &'"
echo.
echo 4. Run capture:
echo    RUN_CAPTURE.bat
echo.
pause





