<#
  2nd Eye: start the whole local stack hidden. Each piece starts only if it is not already running.
  Paths are relative to this script, so the folder can be moved. Prints no message content (it never sees any).
  Run:  powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File integrations\notifier\start_all.ps1
#>
$ErrorActionPreference = 'Continue'
$Root   = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Py     = Join-Path $Root '.venv\Scripts\python.exe'
$Pyw    = Join-Path $Root '.venv\Scripts\pythonw.exe'
$Watch  = Join-Path $Root 'integrations\watcher\watcher.py'
$Notif  = Join-Path $PSScriptRoot 'notifier.py'

if (-not $env:SCAMSHIELD_MODEL) { $env:SCAMSHIELD_MODEL = 'google/gemma-4-26b-a4b' }
if (-not $env:SCAMSHIELD_GPU)   { $env:SCAMSHIELD_GPU   = '0.85' }
if (-not $env:SCAMSHIELD_CTX)   { $env:SCAMSHIELD_CTX   = '4096' }

function Test-Running([string]$Needle) {
    $hit = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine -like "*$Needle*" -and $_.ProcessId -ne $PID }
    return [bool]$hit
}
function Test-Port([int]$Port) {
    return [bool](Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
}

# 1. Detector API on port 8000 (same command as run.bat, no access log, no window)
if (-not (Test-Port 8000)) {
    Start-Process -FilePath $Py -WorkingDirectory $Root -WindowStyle Hidden `
        -ArgumentList '-m', 'uvicorn', 'backend.server:app', '--host', '0.0.0.0', '--port', '8000', '--no-access-log'
}

# 2. LM Studio server + model (as run.bat does), in one hidden background PowerShell so a slow model load blocks nothing
#    The job is idempotent (starts the server, loads the model only if missing) and a mutex stops two copies at once.
if ($true) {
    $lms = (Get-Command lms -ErrorAction SilentlyContinue).Source
    if (-not $lms) {
        $cand = Join-Path $env:USERPROFILE '.lmstudio\bin\lms.exe'
        if (Test-Path $cand) { $lms = $cand }
    }
    if ($lms) {
        $job = @"
`$m = New-Object Threading.Mutex(`$false, 'Local\ScutulBunicidLms')
if (-not `$m.WaitOne(0)) { exit }
& '$lms' server start *> `$null
`$loaded = & '$lms' ps 2>`$null | Select-String -SimpleMatch `$env:SCAMSHIELD_MODEL
if (-not `$loaded) {
    & '$lms' unload --all *> `$null
    & '$lms' load `$env:SCAMSHIELD_MODEL --context-length `$env:SCAMSHIELD_CTX --parallel 1 --gpu `$env:SCAMSHIELD_GPU -y *> `$null
}
"@
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($job))
        Start-Process -FilePath 'powershell.exe' -WindowStyle Hidden `
            -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $enc
    }
}

# 3. Watcher in background mode (default = hidden, no --show / --login), only if it exists
if ((Test-Path $Watch) -and -not (Test-Running 'watcher.py')) {
    Start-Process -FilePath $Py -WorkingDirectory $Root -WindowStyle Hidden -ArgumentList "`"$Watch`""
}

# 4. Notifier (pythonw = no console at all)
if (-not (Test-Running 'notifier.py')) {
    $exe = if (Test-Path $Pyw) { $Pyw } else { $Py }
    Start-Process -FilePath $exe -WorkingDirectory $Root -WindowStyle Hidden -ArgumentList "`"$Notif`""
}
