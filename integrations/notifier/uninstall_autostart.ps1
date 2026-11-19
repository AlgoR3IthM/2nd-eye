<#
  Remove the Scheduled Task "ScutulBunicii". Removing a task registered with highest privileges needs an elevated PowerShell.
  This does not stop processes that are already running; sign out or end them from Task Manager (python / pythonw).
#>
$TaskName = 'ScutulBunicii'
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if (-not $task) { Write-Host "Task '$TaskName' is not registered. Nothing to do."; exit 0 }
try {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
    Write-Host "Task '$TaskName' removed."
} catch {
    Write-Host "Could not remove the task: $($_.Exception.Message)"
    Write-Host 'If it was registered elevated, run this script from an elevated PowerShell (Terminal (Admin)).'
    exit 1
}
