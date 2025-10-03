@echo off
echo ====================================================================================================
echo [+] ADMIN TEST WITH EXISTING FRESH TOKEN
echo ====================================================================================================
echo [!] This script tests admin endpoints with the fresh token we already captured.
echo [!] Theory: Fresh token might have admin privileges or bypass restrictions.
echo ====================================================================================================

rem Run the Python script
echo [1/1] Running admin test with existing fresh token...
py test_admin_with_existing_fresh_token.py
if %errorlevel% neq 0 (
    echo [ERROR] Admin test script failed.
    pause
    exit /b 1
)

echo [OK] Admin test with existing token complete. Check results above.
pause
