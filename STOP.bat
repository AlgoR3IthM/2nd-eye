@echo off
rem 2nd Eye (AlgoR3IthM): stop the detector, the watchers and the alert window. The local model stays loaded in LM Studio.
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Get-CimInstance Win32_Process | Where-Object { ($_.Name -match '^pythonw?\.exe$' -and $_.CommandLine -match 'backend\.server:app|watcher\.py|mail_watcher\.py|notifier\.py') -or ($_.Name -eq 'chrome.exe' -and $_.CommandLine -match 'watcher\\\.profile') } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }; Write-Host '2nd Eye stopped.'"
ping -n 3 127.0.0.1 >nul
