@echo off
setlocal enableextensions enabledelayedexpansion

echo ====================================================================================================
echo [+] COMPREHENSIVE SECURITY REPORT
echo ====================================================================================================
echo [!] This script will generate a comprehensive security report for MaynDrive app.
echo [!] Testing additional endpoints, lock manipulation, and system access.
echo [!] WARNING: This is a complete security assessment!
echo ====================================================================================================

rem Run the Python comprehensive report script
echo [1/1] Running comprehensive security report generation...
py comprehensive_security_report.py
if %errorlevel% neq 0 (
    echo [ERROR] Comprehensive report script failed.
    pause
    exit /b 1
)

echo [OK] Comprehensive security report complete. Check MAYNDRIVE_SECURITY_REPORT.json
pause
