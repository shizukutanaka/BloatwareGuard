Get-AppxPackage | Where-Object {!$_.IsFramework} | Select-Object Name, PackageFullName, IsFramework | Format-List
