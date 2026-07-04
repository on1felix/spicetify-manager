@echo off
setlocal

cd /d "%~dp0"

echo Building SpicetifyManager.exe...
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo Python was not found in PATH.
    echo Install Python or add it to PATH, then run this file again.
    echo.
    pause
    exit /b 1
)

python -m PyInstaller --version >nul 2>nul
if errorlevel 1 (
    echo PyInstaller is not installed.
    echo Install it with:
    echo python -m pip install pyinstaller
    echo.
    pause
    exit /b 1
)

python -m PyInstaller SpicetifyManager.spec --noconfirm
if errorlevel 1 (
    echo.
    echo Build failed.
    pause
    exit /b 1
)

echo.
echo Build complete:
echo %CD%\dist\SpicetifyManager.exe
echo.
pause
