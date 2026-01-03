# Suspicious script with Base64 encoding
# This script contains encoded content that could be malicious

$encodedCommand = "V3JpdGUtSG9zdCAiVGhpcyBpcyBhIHRlc3QgbWVzc2FnZSI="
$decodedBytes = [System.Convert]::FromBase64String($encodedCommand)
$decodedText = [System.Text.Encoding]::UTF8.GetString($decodedBytes)

# Another encoded string
$payload = "UG93ZXJTaGVsbCBpcyBhIHBvd2VyZnVsIHNjcmlwdGluZyBsYW5ndWFnZQ=="
$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($payload))

# Suspicious function names
function Invoke-CustomCommand {
    param($Command)
    Write-Host "Executing: $Command"
}

# Multiple Base64 strings
$config = @{
    "key1" = "SGVsbG8gV29ybGQ="
    "key2" = "VGhpcyBpcyBhbm90aGVyIGVuY29kZWQgc3RyaW5n"
    "key3" = "QmFzZTY0IGVuY29kaW5nIGlzIGNvbW1vbiBpbiBtYWx3YXJl"
}

foreach ($key in $config.Keys) {
    $value = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($config[$key]))
    Write-Host "$key : $value"
}

# Execution policy bypass attempt
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

Invoke-CustomCommand -Command $decodedText