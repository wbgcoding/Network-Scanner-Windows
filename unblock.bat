@echo off
:: Removes the "Mark of the Web" flag that Windows sets on downloaded files.
:: Run this once if Windows shows a SmartScreen warning for NetworkScanner.exe.
powershell -NoProfile -Command "Unblock-File -Path '%~dp0NetworkScanner.exe'" 2>nul
if %errorlevel% == 0 (
    echo NetworkScanner.exe is now unblocked.
) else (
    echo Could not unblock the file. Run as administrator or unblock manually:
    echo   Right-click NetworkScanner.exe -^> Properties -^> tick Unblock -^> OK
)
pause
