$action = New-ScheduledTaskAction -Execute 'C:\Users\HP\bloatware-guard\src\bin\Debug\net8.0-windows\BloatwareGuard.exe' -Argument 'scan'
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'BloatwareGuardAdminScan' -Action $action -Principal $principal -Settings $settings -Force
Start-ScheduledTask -TaskName 'BloatwareGuardAdminScan'
Start-Sleep -Seconds 45
Get-ScheduledTaskInfo -TaskName 'BloatwareGuardAdminScan' | Format-Table State,LastRunTime,LastResult
Unregister-ScheduledTask -TaskName 'BloatwareGuardAdminScan' -Confirm:$false
