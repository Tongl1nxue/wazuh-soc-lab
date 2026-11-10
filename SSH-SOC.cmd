@echo off
cd /d "%~dp0"
python scripts\start-soc.py --shell
if errorlevel 1 pause
