$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$BundledPython = 'C:\Users\adminpc\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$PythonCommand = Get-Command python -ErrorAction SilentlyContinue
if ($PythonCommand) { $PythonExe = $PythonCommand.Source }
elseif (Test-Path -LiteralPath $BundledPython) { $PythonExe = $BundledPython }
else { throw 'Python 3.10+ is required.' }
$ScriptPath = Join-Path $ProjectRoot 'scripts\backup_database.py'
$Action = New-ScheduledTaskAction -Execute $PythonExe -Argument ('"' + $ScriptPath + '"') -WorkingDirectory $ProjectRoot
$Trigger = New-ScheduledTaskTrigger -Daily -At '02:00'
$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable
Register-ScheduledTask -TaskName 'Inventory Audit Management Daily Backup' -Action $Action -Trigger $Trigger -Settings $Settings -Description 'Daily verified SQLite backup for Inventory Audit Management' -Force

