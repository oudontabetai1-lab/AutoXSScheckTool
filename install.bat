@echo off
echo ============================================
echo  WScan - Web Security Scanner
echo  Setup Script
echo ============================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.10+
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
