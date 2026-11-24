@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0campus_capture.ps1" %*
exit /b %ERRORLEVEL%
