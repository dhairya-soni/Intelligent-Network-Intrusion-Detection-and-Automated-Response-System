@echo off
if "%1"=="" (
    echo ====================================================================
    echo   INIDARS Attack Simulator - Enhanced Version
    echo ====================================================================
    echo.
    echo Usage: run_demo.bat [scenario]
    echo.
    echo Available scenarios:
    echo.
    echo   mixed_traffic   - Realistic blend (60%% normal, 30%% suspicious, 10%% attacks)
    echo                     RECOMMENDED for best demo!
    echo.
    echo   brute_force     - Brute force attack with varied IPs and severities
    echo   port_scan       - Port scanning activity
    echo   sql_injection   - SQL injection attempts
    echo   ddos            - DDoS attack simulation
    echo   malware         - Malware activity detection
    echo.
    echo   normal          - Normal traffic baseline (mostly no alerts)
    echo   suspicious      - Borderline activity (MEDIUM/LOW alerts)
    echo.
    echo ====================================================================
    echo.
    echo Examples:
    echo   run_demo.bat mixed_traffic    ^(Best for showing all features^)
    echo   run_demo.bat brute_force
    echo   run_demo.bat normal
    echo.
    echo ====================================================================
    pause
    exit /b 1
)

echo.
echo Starting simulation: %1
echo.
python demo.py %1
echo.
pause