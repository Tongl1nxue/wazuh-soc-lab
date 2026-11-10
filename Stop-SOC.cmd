@echo off
cd /d "%~dp0"
python scripts\stop-soc.py
if errorlevel 1 pause
