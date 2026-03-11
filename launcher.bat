@echo off
:: UTF-8 に切り替え (日本語パス対応)
chcp 65001 > nul 2>&1
python -X utf8 "%~dp0launcher.py"
pause
