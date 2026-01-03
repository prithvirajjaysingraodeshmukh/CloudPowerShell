# Test script with hardcoded credentials
# This script should trigger POL-003 policy violation

$username = "admin"
$password = "MySecretPassword123!"
$apiKey = "sk-1234567890abcdef"

# Connect to Azure
Connect-AzAccount -Credential (New-Object System.Management.Automation.PSCredential($username, (ConvertTo-SecureString $password -AsPlainText -Force)))

# Make API call with hardcoded key
$headers = @{
    "Authorization" = "Bearer $apiKey"
}
Invoke-RestMethod -Uri "https://api.example.com/data" -Headers $headers

Write-Host "Connection successful"

