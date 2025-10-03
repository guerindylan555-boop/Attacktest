@echo off
setlocal enableextensions enabledelayedexpansion

echo ====================================================================================================
echo [+] SXB306 ADMIN UNLOCK TEST
echo ====================================================================================================
echo [!] This script will test admin privilege escalation on SXB306 scooter.
echo [!] This tests if regular users can perform admin operations.
echo [!] WARNING: This is a critical security test!
echo ====================================================================================================

rem Run the Python test script
echo [1/1] Running SXB306 admin unlock test...
py test_sxb306_admin_unlock.py
if %errorlevel% neq 0 (
    echo [ERROR] Test script failed.
    pause
    exit /b 1
)

echo [OK] Admin test complete. Check results above.
pause
