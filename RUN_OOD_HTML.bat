@echo off
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\run_ood_crawl.ps1" -HtmlPass
echo.
pause
