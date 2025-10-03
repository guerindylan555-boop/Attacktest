@echo off
setlocal enableextensions enabledelayedexpansion

echo ====================================================================================================
echo [+] OTHER VULNERABILITIES TEST
echo ====================================================================================================
echo [!] This script will test for additional security vulnerabilities.
echo [!] Testing mass unlock, lock, info access, and injection vulnerabilities.
echo [!] WARNING: This is a comprehensive security test!
echo ====================================================================================================

rem Run the Python test script
echo [1/1] Running other vulnerabilities test...
py test_other_vulnerabilities.py
if %errorlevel% neq 0 (
    echo [ERROR] Test script failed.
    pause
    exit /b 1
)

echo [OK] Other vulnerabilities test complete. Check results above.
pause
