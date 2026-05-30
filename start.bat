@echo off
title Network Scanner
setlocal EnableDelayedExpansion

:: ════════════════════════════════════════════════════════════════════════
::  STEP 1 — Elevation
::  fltmc (Filter Manager) requires admin; failure means we need UAC lift.
:: ════════════════════════════════════════════════════════════════════════
fltmc >nul 2>&1
if %errorLevel% neq 0 (
    powershell -NoProfile -Command ^
        "Start-Process cmd -ArgumentList '/c \"%~f0\"' -Verb RunAs"
    exit /b 0
)

:: Working directory = folder containing this script
cd /d "%~dp0"

:: ════════════════════════════════════════════════════════════════════════
::  STEP 2 — Python presence check
:: ════════════════════════════════════════════════════════════════════════
where python >nul 2>&1
if %errorLevel% neq 0 (
    echo  [INSTALL] Python not found -- installing via winget ...
    winget install Python.Python.3 --silent ^
        --accept-package-agreements --accept-source-agreements
    if %errorLevel% neq 0 (
        echo  [ERROR] winget install failed.
        echo          Download Python manually: https://python.org/downloads
        pause
        exit /b 1
    )
    :: Reload system PATH so python.exe is visible in this session
    for /f "tokens=*" %%p in ('powershell -NoProfile -Command ^
        "[Environment]::GetEnvironmentVariable(\"PATH\",\"Machine\")"') do (
        set "PATH=%%p;%PATH%"
    )
    where python >nul 2>&1
    if %errorLevel% neq 0 (
        echo  [INFO] Python installed. Please close this window and run start.bat again.
        pause
        exit /b 0
    )
)

:: ════════════════════════════════════════════════════════════════════════
::  STEP 3 — Python version check (requires 3.x)
:: ════════════════════════════════════════════════════════════════════════
for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYVER=%%v
for /f "tokens=1 delims=." %%m in ("!PYVER!") do set PYMAJ=%%m
if !PYMAJ! lss 3 (
    echo  [ERROR] Python 3 required, found !PYVER!
    pause
    exit /b 1
)

:: ════════════════════════════════════════════════════════════════════════
::  STEP 4 — Run scanner
:: ════════════════════════════════════════════════════════════════════════
python network_scanner.py
if %errorLevel% neq 0 (
    echo.
    echo  [!] Exited with code %errorLevel%
    pause
)
