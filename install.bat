@echo off
echo ============================================
echo  WScan - Web Security Scanner
echo  Setup Script
echo ============================================
echo.

:: Check Python (requires 3.11+)
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.11+
    pause
    exit /b 1
)
for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
for /f "tokens=1,2 delims=." %%a in ("%PYVER%") do (
    set PYMAJOR=%%a
    set PYMINOR=%%b
)
if %PYMAJOR% LSS 3 (
    echo [ERROR] Python 3.11+ is required. Detected: %PYVER%
    pause
    exit /b 1
)
if %PYMAJOR% EQU 3 if %PYMINOR% LSS 11 (
    echo [ERROR] Python 3.11+ is required. Detected: %PYVER%
    pause
    exit /b 1
)

echo [1/3] Installing Python dependencies...
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] pip install failed.
    pause
    exit /b 1
)

echo.
echo [2/3] Installing Playwright browsers (Chromium)...
python -m playwright install chromium
if errorlevel 1 (
    echo [ERROR] Playwright browser install failed.
    pause
    exit /b 1
)

echo.
echo [3/3] Creating output directory...
if not exist "output" mkdir output

echo.
echo ============================================
echo  Setup complete!
echo.
echo  Usage:
echo    python main.py scan https://target.com
echo    python main.py scan https://target.com --payloads custom.yaml
echo    python main.py scan https://target.com --checks sqli xss
echo    python main.py --help
echo ============================================
echo.
pause
