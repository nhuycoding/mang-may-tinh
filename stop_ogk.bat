@echo off
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'server\.app\.main|agent\.src' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"
echo Da tat sach OGK Server, Agent va Tray UI!
timeout /t 2 >nul