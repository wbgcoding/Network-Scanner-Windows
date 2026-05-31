@echo off
title Network Scanner
rem ===========================================================================
rem  start.bat - run the Network Scanner directly from source.
rem  No prompts, no auto-install: it just launches the scanner. Python 3 must be
rem  on PATH (get it from https://python.org/downloads if the launch fails).
rem ===========================================================================
cd /d "%~dp0"

python network_scanner.py
if errorlevel 1 (
    echo.
    echo  [!] The scanner could not start. Make sure Python 3 is installed
    echo      and on your PATH:  https://python.org/downloads
    pause
)
