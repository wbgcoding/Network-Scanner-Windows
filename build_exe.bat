@echo off
REM ============================================================================
REM  build_exe.bat — build the Network Scanner as a ONE-FOLDER app.
REM
REM  One-folder (--onedir) instead of one-file: the .exe runs straight from the
REM  dist\NetworkScanner folder with NO temp extraction, so it starts faster and
REM  — most importantly — closes INSTANTLY on ESC (a one-file build has to delete
REM  its extracted _MEI temp dir on exit, which made ESC feel like a crash).
REM
REM  The config (network_scanner.conf) and the known-devices database
REM  (scanner.db) are NOT bundled — they stay as external files next to the .exe
REM  so they can be edited without rebuilding.
REM
REM  PyInstaller notes:
REM   --collect-binaries _sqlite3  : bundles _sqlite3.pyd (Windows C extension)
REM                                  which PyInstaller does not auto-detect.
REM   --collect-all sqlite3        : bundles the full sqlite3 Python package.
REM   --hidden-import _sqlite3     : makes the import visible to the analysis.
REM ============================================================================
setlocal
cd /d "%~dp0"

set "APPNAME=NetworkScanner"
set "ENTRY=network_scanner.py"

echo  [1/4] Checking Python ...
where python >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found on PATH. Install from https://python.org/downloads
    pause
    exit /b 1
)

echo  [2/4] Ensuring PyInstaller is installed ...
python -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo        Installing PyInstaller ...
    python -m pip install --upgrade pyinstaller
    if errorlevel 1 (
        echo  [ERROR] Failed to install PyInstaller.
        pause
        exit /b 1
    )
)

echo  [3/4] Cleaning previous build artifacts ...
if exist "build"          rmdir /s /q "build"
if exist "dist"           rmdir /s /q "dist"
if exist "%APPNAME%.spec" del /q "%APPNAME%.spec"

echo  [4/4] Building %APPNAME% (one-folder) ...
python -m PyInstaller ^
    --onedir --console --clean --noconfirm ^
    --name "%APPNAME%" ^
    --collect-all sqlite3 ^
    --collect-binaries _sqlite3 ^
    --hidden-import _sqlite3 ^
    --hidden-import sqlite3 ^
    --hidden-import csv ^
    "%ENTRY%"
if errorlevel 1 (
    echo.
    echo  [ERROR] Build failed. See output above.
    pause
    exit /b 1
)

REM Drop the template config next to the .exe (inside the app folder) if no
REM config exists there yet.
if exist "network_scanner.conf.template" (
    if not exist "dist\%APPNAME%\network_scanner.conf" (
        copy /y "network_scanner.conf.template" "dist\%APPNAME%\network_scanner.conf" >nul
    )
)

echo.
echo  ============================================================
echo   Done:  %~dp0dist\%APPNAME%\%APPNAME%.exe
echo   Run the .exe inside the dist\%APPNAME% folder. Closes instantly on ESC.
echo   Put network_scanner.conf next to the .exe to configure it.
echo  ============================================================
echo.
pause
endlocal
