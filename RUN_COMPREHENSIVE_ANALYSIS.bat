@echo off
setlocal enableextensions enabledelayedexpansion

echo ====================================================================================================
echo [+] COMPREHENSIVE SECURITY ANALYSIS
echo ====================================================================================================
echo [!] This script will test both TUF061 and SXB306 to understand the security model.
echo [!] This will reveal the exact nature of the vulnerabilities.
echo [!] WARNING: This is a comprehensive security assessment!
echo ====================================================================================================

rem Run the Python analysis script
echo [1/1] Running comprehensive security analysis...
py test_comprehensive_security_analysis.py
if %errorlevel% neq 0 (
    echo [ERROR] Analysis script failed.
    pause
    exit /b 1
)

echo [OK] Comprehensive analysis complete. Check results above.
pause
