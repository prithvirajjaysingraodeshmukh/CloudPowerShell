# Simple benign PowerShell script
# This script performs basic system information gathering

Write-Host "System Information Report" -ForegroundColor Green

# Get computer information
$computerInfo = Get-ComputerInfo
Write-Host "Computer Name: $($computerInfo.CsName)"
Write-Host "Operating System: $($computerInfo.WindowsProductName)"
Write-Host "Total Memory: $([math]::Round($computerInfo.TotalPhysicalMemory / 1GB, 2)) GB"

# Get disk information
$disks = Get-WmiObject -Class Win32_LogicalDisk
foreach ($disk in $disks) {
    $freeSpace = [math]::Round($disk.FreeSpace / 1GB, 2)
    $totalSpace = [math]::Round($disk.Size / 1GB, 2)
    Write-Host "Drive $($disk.DeviceID) - Free: $freeSpace GB / Total: $totalSpace GB"
}

# Get running services
$services = Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object -First 10
Write-Host "`nTop 10 Running Services:"
$services | Format-Table Name, Status -AutoSize

Write-Host "Report completed successfully!" -ForegroundColor Green