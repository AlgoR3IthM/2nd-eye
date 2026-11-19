# 2nd Eye (AlgoR3IthM) - one-click start.
# Sets up whatever is missing (Python environment, Gmail app password, WhatsApp login), loads the local model,
# starts the detector, the WhatsApp and Gmail watchers and the alert window, then opens the web page.
# Everything runs on this laptop. Run STOP.bat to stop it all.
$ErrorActionPreference = "Continue"
$Root = $PSScriptRoot
Set-Location $Root
$Py = Join-Path $Root ".venv\Scripts\python.exe"
$Pyw = Join-Path $Root ".venv\Scripts\pythonw.exe"
$Model = if ($env:SCAMSHIELD_MODEL) { $env:SCAMSHIELD_MODEL } else { "qwen/qwen3-4b-2507" }
$Logs = Join-Path $env:TEMP "2ndeye"
New-Item -ItemType Directory -Force $Logs | Out-Null
$Host.UI.RawUI.WindowTitle = "2nd Eye - AlgoR3IthM"

function Say($msg, $color = "Gray") { Write-Host $msg -ForegroundColor $color }
function Running($pattern) {
    @(Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" |
      Where-Object { $_.CommandLine -match $pattern }).Count -gt 0
}
function ApiUp {
    try { $null = Invoke-RestMethod "http://127.0.0.1:8000/api/health" -TimeoutSec 3; return $true } catch { return $false }
}
function StartHidden($exe, $argList, $name) {
    Start-Process $exe -ArgumentList $argList -WindowStyle Hidden -WorkingDirectory $Root `
        -RedirectStandardOutput (Join-Path $Logs "$name.log") -RedirectStandardError (Join-Path $Logs "$name.err") | Out-Null
}

Write-Host ""
Say "  2nd Eye  ·  AlgoR3IthM" "Cyan"
Say "  Pornesc paza mesajelor... / Starting message protection..." "Cyan"
Write-Host ""

# ---------------------------------------------------------------- 1. Python environment
if (-not (Test-Path $Py)) {
    Say "[setup] Python environment missing - creating it (one time, about a minute)..." "Yellow"
    $uv = (Get-Command uv -ErrorAction SilentlyContinue).Source
    if ($uv) {
        & $uv venv .venv --python 3.13 | Out-Null
        & $uv pip install --python $Py fastapi "uvicorn[standard]" httpx python-dotenv playwright windows-toasts | Out-Null
    } else {
        python -m venv .venv
        & $Py -m pip install -q fastapi "uvicorn[standard]" httpx python-dotenv playwright windows-toasts
    }
}
& $Py -c "import fastapi, uvicorn, playwright" 2>$null
if ($LASTEXITCODE -ne 0) {
    Say "[setup] Installing missing packages..." "Yellow"
    & $Py -m pip install -q fastapi "uvicorn[standard]" httpx python-dotenv playwright windows-toasts
}

# ---------------------------------------------------------------- 2. Gmail app password (.env)
$EnvFile = Join-Path $Root ".env"
$envText = if (Test-Path $EnvFile) { Get-Content $EnvFile -Raw } else { "" }
if ($envText -notmatch "(?m)^GMAIL_APP_PASSWORD=\S") {
    Say "[setup] Gmail is not set up yet." "Yellow"
    Say "        You need an app password: myaccount.google.com/apppasswords (2-Step Verification must be on)."
    $addr = Read-Host "        Gmail address (leave empty to skip Gmail)"
    if ($addr) {
        $pw = Read-Host "        App password (16 letters)"
        $keep = ($envText -split "`r?`n") | Where-Object { $_ -and $_ -notmatch "^GMAIL_(ADDRESS|APP_PASSWORD)=" }
        (@($keep) + "GMAIL_ADDRESS=$addr" + "GMAIL_APP_PASSWORD=$pw") -join "`r`n" | Set-Content -Encoding utf8 $EnvFile
        Say "        Saved in .env (this file never goes into git)." "Green"
    }
}
$HaveGmail = (Test-Path $EnvFile) -and ((Get-Content $EnvFile -Raw) -match "(?m)^GMAIL_APP_PASSWORD=\S")

# ---------------------------------------------------------------- 3. WhatsApp login (one time)
$WaProfile = Join-Path $Root "integrations\watcher\.profile"
# the watcher keeps one browser profile per browser (chrome, msedge, ...) under .profile
$linked = @(Get-ChildItem $WaProfile -Directory -ErrorAction SilentlyContinue | Where-Object { Test-Path (Join-Path $_.FullName "Default") }).Count -gt 0
if (-not $linked) {
    Say "[setup] WhatsApp is not linked yet. A browser window opens now:" "Yellow"
    Say "        on the phone: WhatsApp > Linked devices > Link a device, scan the QR code, then CLOSE the window."
    & $Py integrations\watcher\watcher.py --login --services whatsapp
}

# ---------------------------------------------------------------- 4. Local model (LM Studio)
$lms = (Get-Command lms -ErrorAction SilentlyContinue).Source
if (-not $lms) { $c = Join-Path $env:USERPROFILE ".lmstudio\bin\lms.exe"; if (Test-Path $c) { $lms = $c } }
$apiAlready = ApiUp
if ($lms -and -not $apiAlready) {
    Say "[1/4] Local AI model..."
    & $lms server start *> $null
    if ($LASTEXITCODE -ne 0) {
        $loc = Join-Path $env:USERPROFILE ".lmstudio\.internal\app-install-location.json"
        if (Test-Path $loc) { try { Start-Process ((Get-Content $loc -Raw | ConvertFrom-Json).path); Start-Sleep 15 } catch {} }
        & $lms server start *> $null
    }
    & $lms unload --all *> $null
    & $lms load $Model --identifier $Model --context-length 8192 --parallel 1 --gpu 1.0 -y *> $null
    if ($LASTEXITCODE -eq 0) { Say "      model ready ($Model)" "Green" }
    else { Say "      model did not load - 2nd Eye still works with rules and link checks only" "Yellow" }
} elseif (-not $lms) {
    Say "[1/4] LM Studio not found - 2nd Eye works with rules and link checks only" "Yellow"
}

# ---------------------------------------------------------------- 5. Detector API
if (-not $apiAlready) {
    Say "[2/4] Detector..."
    StartHidden $Py @("-m", "uvicorn", "backend.server:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log") "api"
    for ($i = 0; $i -lt 30 -and -not (ApiUp); $i++) { Start-Sleep 1 }
    if (ApiUp) { Say "      detector ready" "Green" } else { Say "      detector did not start - see $Logs\api.err" "Red" }
} else { Say "[2/4] Detector already running" "Green" }

# ---------------------------------------------------------------- 6. Watchers and alert window
Say "[3/4] Watching messages..."
if (-not (Running "watcher\.py")) { StartHidden $Py @("integrations\watcher\watcher.py", "--services", "whatsapp", "--poll", "2") "whatsapp" }
Say "      WhatsApp: unknown numbers are checked in the background" "Green"
if ($HaveGmail) {
    if (-not (Running "mail_watcher\.py")) { StartHidden $Py @("-u", "integrations\mail\mail_watcher.py", "--days", "1", "--max-threads", "12", "--interval", "2") "gmail" }
    Say "      Gmail: new mail is checked every 2 seconds" "Green"
} else { Say "      Gmail: skipped (no app password)" "Yellow" }
if (-not (Running "notifier\.py")) { Start-Process $Pyw -ArgumentList "integrations\notifier\notifier.py","--interval","1" -WorkingDirectory $Root }
Say "      Alert window: on" "Green"

# ---------------------------------------------------------------- 7. Web page
Say "[4/4] Opening 2nd Eye..."
Start-Process "http://localhost:8000"
Write-Host ""
Say "  Gata! 2nd Eye vă păzește mesajele. / Done! 2nd Eye is watching your messages." "Cyan"
Say "  Web page: http://localhost:8000   WhatsApp alerts: http://127.0.0.1:8010   Gmail alerts: http://127.0.0.1:8011"
Say "  To stop everything: double-click STOP.bat"
Write-Host ""
Start-Sleep 6
