<#
  Register the Scheduled Task "ScutulBunicii": runs start_all.ps1 hidden when the current user signs in.
  Default: RunLevel Highest (needs an elevated PowerShell, so there is no UAC prompt at sign-in).
  -Unelevated: same task with standard rights (no admin needed to install). See README.md.
#>
param([switch]$Unelevated)

$TaskName = 'ScutulBunicii'
$Script   = Join-Path $PSScriptRoot 'start_all.ps1'
if (-not (Test-Path $Script)) { Write-Error "start_all.ps1 not found next to this script."; exit 1 }

$id    = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $Unelevated -and -not $admin) {
    Write-Host 'This needs an elevated PowerShell (registering a task with highest privileges requires administrator rights).'
    Write-Host 'Right-click Start > Terminal (Admin) or "Windows PowerShell (Admin)", then run:'
    Write-Host "  powershell -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    Write-Host 'Or, to register with standard rights instead (no admin needed):'
    Write-Host "  powershell -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Unelevated"
    exit 1
}

$arg = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Script`""
$action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg -WorkingDirectory (Split-Path $Script)
$trigger   = New-ScheduledTaskTrigger -AtLogOn -User $id.Name
$runLevel  = if ($Unelevated) { 'Limited' } else { 'Highest' }
# Interactive logon = runs in the signed-in user's session (needed for toasts and the user's browser), never as SYSTEM.
$principal = New-ScheduledTaskPrincipal -UserId $id.Name -LogonType Interactive -RunLevel $runLevel
$settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew

try {
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
        -Settings $settings -Description '2nd Eye: local scam-protection stack, started hidden at sign-in.' `
        -Force -ErrorAction Stop | Out-Null
} catch {
    Write-Error "Could not register the task: $($_.Exception.Message)"
    exit 1
}
Write-Host "Task '$TaskName' registered ($runLevel) for $($id.Name). It starts at the next sign-in."
Write-Host "Start it now without signing out:  Start-ScheduledTask -TaskName $TaskName"
Write-Host "Remove it:  powershell -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $PSScriptRoot 'uninstall_autostart.ps1')`""
