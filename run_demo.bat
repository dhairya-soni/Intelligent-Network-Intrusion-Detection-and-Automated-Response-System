@echo off
if "%1"=="" (
    echo Usage: run_demo.bat [attack_type]
    echo.
    echo Available attack types:
    echo   - brute_force   : Brute force attack simulation
    echo   - port_scan     : Port scanning activity
    echo   - sql_injection : SQL injection attempts
    echo   - ddos          : DDoS attack simulation
    echo   - malware       : Malware activity
    echo   - normal        : Normal traffic baseline
    echo.
    echo Example: run_demo.bat brute_force
    pause
    exit /b 1
)

python demo.py %1
pause
