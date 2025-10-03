@echo off
setlocal enableextensions enabledelayedexpansion

echo ====================================================================================================
echo [+] SXB306 JWT ADMIN UNLOCK TEST
echo ====================================================================================================
echo [!] This script will test JWT token manipulation for admin privileges on SXB306.
echo [!] This tests if JWT tokens can be manipulated to gain admin access.
echo [!] WARNING: This is a critical JWT security test!
echo ====================================================================================================

rem Run the Python test script
echo [1/1] Running SXB306 JWT admin unlock test...
py test_sxb306_jwt_admin.py
if %errorlevel% neq 0 (
    echo [ERROR] Test script failed.
    pause
    exit /b 1
)

echo [OK] JWT admin test complete. Check results above.
pause
