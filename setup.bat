@echo off
REM Quick setup script for Vulnerability Scanner on Windows

echo Setting up Vulnerability Scanner...
echo.

REM Create virtual environment if it doesn't exist
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Install dependencies
echo Installing dependencies...
python -m pip install -r requirements.txt --upgrade

REM Done
echo.
echo Setup complete! Run scanner with:
echo   python main.py --help
echo   python main.py --target 127.0.0.1 --no-report
echo.
pause

