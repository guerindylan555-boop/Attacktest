@echo off
echo ====================================================================================================
echo FRESH TOKEN CAPTURE - First Account
echo ====================================================================================================
echo This will capture a fresh token from your first account
echo ====================================================================================================

echo [1/3] Killing old Frida server...
adb shell "su -c 'pkill frida-server'" >nul 2>&1
echo [OK] Kill command sent

echo [2/3] Starting Frida server...
adb shell "su -c '/data/local/tmp/frida-server &'" >nul 2>&1
timeout /t 2 /nobreak >nul
echo [OK] Frida server started

echo [3/3] Starting fresh token capture...
echo ====================================================================================================
echo FRESH TOKEN CAPTURE STARTING
echo ====================================================================================================
echo Follow these steps:
echo 1. Wait for the app to launch
echo 2. Log in with your FIRST account (the one that unlocked TUF061)
echo 3. Navigate to any scooter
echo 4. Press UNLOCK (this will generate a fresh token)
echo 5. Watch for Bearer token in the output
echo 6. Press Ctrl+C when done
echo ====================================================================================================

py -c "import frida,sys;d=frida.get_usb_device();pid=d.spawn(['fr.mayndrive.app']);s=d.attach(pid);sc=s.create_script(open('capture_WORKING_FINAL.js').read());sc.load();d.resume(pid);print('[+] FRESH TOKEN CAPTURE READY!');print('[!] Log in with FIRST account and unlock a scooter');print('');sys.stdin.read()"

echo.
echo [OK] Capture stopped
echo [+] Fresh token data saved to:
echo    - CAPTURED_WORKING_FINAL.txt
echo    - CAPTURED_WORKING_FINAL.json
echo.
pause
