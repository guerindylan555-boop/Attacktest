@echo off
setlocal enableextensions enabledelayedexpansion

echo ====================================================================================================
echo [+] DEEP APP ANALYSIS
echo ====================================================================================================
echo [!] This script will perform deep analysis to find hidden vulnerabilities.
echo [!] Testing: IDOR, Business Logic, Rate Limiting, Information Disclosure, Auth Bypass
echo [!] WARNING: This is a comprehensive deep security analysis!
echo ====================================================================================================

rem Run the Python deep analysis script
echo [1/1] Running deep app analysis...
py deep_app_analysis.py
if %errorlevel% neq 0 (
    echo [ERROR] Deep analysis script failed.
    pause
    exit /b 1
)

echo [OK] Deep app analysis complete. Check results above.
pause