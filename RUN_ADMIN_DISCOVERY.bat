@echo off
setlocal enableextensions enabledelayedexpansion

echo ====================================================================================================
echo [+] ADMIN ENDPOINT DISCOVERY
echo ====================================================================================================
echo [!] This script will test ALL possible admin endpoints until we find one that works.
echo [!] This is a comprehensive discovery attack.
echo [!] WARNING: This will test hundreds of endpoint combinations!
echo ====================================================================================================

rem Run the Python discovery script
echo [1/1] Running admin endpoint discovery...
py test_admin_endpoint_discovery.py
if %errorlevel% neq 0 (
    echo [ERROR] Discovery script failed.
    pause
    exit /b 1
)

echo [OK] Admin endpoint discovery complete. Check results above.
pause
