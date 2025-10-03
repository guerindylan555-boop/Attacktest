@echo off
setlocal enableextensions enabledelayedexpansion

echo ====================================================================================================
echo [+] SXB306 ADMIN ESCALATION TEST
echo ====================================================================================================
echo [!] This script will test SXB306 unlock using admin privilege escalation.
echo [!] This uses the discovered vulnerability to bypass restrictions.
echo [!] WARNING: This is a critical security test!
echo ====================================================================================================

rem Run the Python test script
echo [1/1] Running SXB306 admin escalation test...
py test_sxb306_admin_escalation.py
if %errorlevel% neq 0 (
    echo [ERROR] Test script failed.
    pause
    exit /b 1
)

echo [OK] Admin escalation test complete. Check results above.
pause
