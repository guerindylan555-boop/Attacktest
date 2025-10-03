@echo off
setlocal enableextensions enabledelayedexpansion

echo ====================================================================================================
echo [+] PRIVILEGE ESCALATION ATTACK
echo ====================================================================================================
echo [!] This script will test various privilege escalation techniques.
echo [!] Testing: JWT manipulation, admin endpoints, query parameters, headers, JSON payloads
echo [!] WARNING: This is an advanced security test for privilege escalation!
echo ====================================================================================================

rem Run the Python privilege escalation script
echo [1/1] Running privilege escalation attack...
py privilege_escalation_attack.py
if %errorlevel% neq 0 (
    echo [ERROR] Privilege escalation script failed.
    pause
    exit /b 1
)

echo [OK] Privilege escalation attack complete. Check results above.
pause
