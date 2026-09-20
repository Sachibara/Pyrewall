@echo off
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if not "%errorlevel%"=="0" (
  echo PyreWall needs Administrator privileges for WinDivert and Windows Firewall.
  echo Requesting elevation...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

echo Starting PyreWall Web Firewall...
echo Open http://127.0.0.1:8765 in your browser.
echo.
python web_app.py
pause
