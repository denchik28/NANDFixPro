@echo off
setlocal

REM --- Auto-elevate to Administrator ---
net session >nul 2>&1
if errorlevel 1 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

set "SCRIPT_DIR=%~dp0"
set "VENV_DIR=%SCRIPT_DIR%venv"
set "PYTHON_EXE=C:\Program Files\Python313\python.exe"

REM --- Check Python exists ---
if not exist "%PYTHON_EXE%" (
    echo ERROR: Python not found at "%PYTHON_EXE%"
    echo Please install Python 3.13 from https://www.python.org/downloads/
    pause
    exit /b 1
)

REM --- Create venv if it doesn't exist ---
if not exist "%VENV_DIR%\Scripts\python.exe" (
    echo Setting up virtual environment...
    "%PYTHON_EXE%" -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo Installing dependencies...
    "%VENV_DIR%\Scripts\pip.exe" install -r "%SCRIPT_DIR%requirements.txt" --quiet
    if errorlevel 1 (
        echo ERROR: Failed to install dependencies.
        pause
        exit /b 1
    )
    echo Setup complete.
    echo.
)

REM --- Launch NANDFixPro ---
cd /d "%SCRIPT_DIR%"
"%VENV_DIR%\Scripts\python.exe" "%SCRIPT_DIR%nandfixpro.py"
