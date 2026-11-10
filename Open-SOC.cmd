@echo off
cd /d "%~dp0"
python scripts\start-soc.py
if errorlevel 1 pause
