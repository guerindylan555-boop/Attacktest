@echo off
setlocal enableextensions enabledelayedexpansion

echo ====================================================================================================
echo [+] SXB306 SCOOTER UNLOCK TEST
echo ====================================================================================================
echo [!] This script will test if the captured token can unlock SXB306 scooter.
echo [!] This tests for cross-account access vulnerabilities.
echo ====================================================================================================

rem Run the Python test script
echo [1/1] Running SXB306 unlock test...
py test_sxb306_unlock.py
if %errorlevel% neq 0 (
    echo [ERROR] Test script failed.
    pause
    exit /b 1
)

echo [OK] Test complete. Check results above.
pause