@echo off
REM ============================================================
REM  Vanguard-OOB :: Windows Quick-Install Script
REM  Run this ONCE to install all dependencies.
REM  Requires: Python 3.9+ and pip (python.org/downloads)
REM ============================================================

echo.
echo  ==========================================
echo   VANGUARD-OOB :: Dependency Installer
echo  ==========================================
echo.

python --version >nul 2>&1
IF ERRORLEVEL 1 (
    echo  [ERROR] Python not found. Install from https://python.org/downloads
    echo          Make sure to tick "Add Python to PATH" during install.
    pause
    exit /b 1
)

echo  [OK] Python found:
python --version

echo.
echo  Installing Host Control Plane dependencies...
pip install -r host_control_plane\requirements.txt
IF ERRORLEVEL 1 (
    echo  [ERROR] Failed to install host dependencies.
    pause
    exit /b 1
)

echo.
echo  Installing Sentry Agent dependencies...
pip install -r guest_production_vm\requirements.txt
IF ERRORLEVEL 1 (
    echo  [ERROR] Failed to install guest dependencies.
    pause
    exit /b 1
)

echo.
echo  Installing Blue Team Suite dependencies (21 tools)...
pip install -r blue_team\requirements.txt
IF ERRORLEVEL 1 (
    echo  [ERROR] Failed to install blue team dependencies.
    pause
    exit /b 1
)

echo.
echo  ==========================================
echo   [SUCCESS] All dependencies installed!
echo  ==========================================
echo.
echo  Next steps:
echo    0. FASTEST: see the whole thing in one command:
echo         python demo.py
echo    -  Verify the logic (23 assertions):  python verify.py
echo.
echo    Manual run:
echo    1. Edit: host_control_plane\hypervisor_config.json
echo    2. Start Control Center (in a new terminal):
echo         cd host_control_plane
echo         python control_center.py
echo    3. Start Sentry Agent (in guest VM, new terminal):
echo         cd guest_production_vm
echo         python sentry_agent.py --controller-host 127.0.0.1
echo    4. Run test simulation (new terminal):
echo         python test_harness.py --host 127.0.0.1 --scenario ransomware
echo    5. Open SOC Dashboard: http://127.0.0.1:5000
echo.
echo    NOTE: For real deployments set VANGUARD_MASTER_KEY (same value on the
echo          controller and every guest) or telemetry will be rejected.
echo.
echo  ==========================================
echo   BLUE TEAM SUITE (21 tools)
echo  ==========================================
echo    See everything available:
echo         cd blue_team
echo         python vanguard.py tools
echo    Run a full audit:
echo         python vanguard.py audit --path C:\Windows\System32
echo    Launch Master SOC Dashboard:
echo         python vanguard.py dashboard --port 8080
echo         http://127.0.0.1:8080
echo.
pause
