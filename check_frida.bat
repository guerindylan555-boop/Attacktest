@echo off
SET ADB=platform-tools\adb.exe

echo ====================================================================================================
echo FRIDA DIAGNOSTIC
====================================================================================================
echo.

echo [1] ADB connection...
%ADB% devices
echo.

echo [2] Frida server running?
%ADB% shell "su -c 'ps | grep frida'"
echo.

echo [3] Test Frida from Python...
py -c "import frida; print('Connecting...'); d = frida.get_usb_device(timeout=5); print('SUCCESS:', d.name); procs = d.enumerate_processes(); print('Found', len(procs), 'processes')"
echo.

echo ====================================================================================================
pause
