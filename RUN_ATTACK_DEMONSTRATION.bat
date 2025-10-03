@echo off
setlocal enableextensions enabledelayedexpansion

echo ====================================================================================================
echo [+] ATTACK DEMONSTRATION
echo ====================================================================================================
echo [!] This script will demonstrate actual attacks against the MaynDrive app.
echo [!] WARNING: This is for educational and security testing purposes only!
echo [!] Demonstrating: Information disclosure, JSON injection, session manipulation, parameter pollution
echo ====================================================================================================

rem Run the Python attack demonstration script
echo [1/1] Running attack demonstration...
py demonstrate_attacks.py
if %errorlevel% neq 0 (
    echo [ERROR] Attack demonstration script failed.
    pause
    exit /b 1
)

echo [OK] Attack demonstration complete. Check ATTACK_DEMONSTRATION_REPORT.json
pause
