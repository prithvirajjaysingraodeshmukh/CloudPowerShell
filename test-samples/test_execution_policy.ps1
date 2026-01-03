# Test script with execution policy bypass
# This script should trigger POL-002 policy violation

# Bypass execution policy
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Run as administrator
Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File script.ps1"

# Privilege escalation attempt
$cred = Get-Credential
Invoke-Command -Credential $cred -ScriptBlock {
    New-AzRoleAssignment -RoleDefinitionName "Owner" -SignInName "user@example.com"
}

Write-Host "Execution policy bypassed"

