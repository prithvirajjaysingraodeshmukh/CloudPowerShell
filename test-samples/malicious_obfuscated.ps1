# Heavily obfuscated malicious-looking script
# Contains multiple suspicious indicators

$a='iex';$b='Invoke-Expression';$c='bypass';$d='hidden';$e='downloadstring'
$f="V2ViQ2xpZW50";$g="bmV0LndlYmNsaWVudA==";$h="ZG93bmxvYWRmaWxl"
$i="aW52b2tlLWNvbW1hbmQ=";$j="c3RhcnQtcHJvY2Vzcw==";$k="bmV3LW9iamVjdA=="

# Obfuscated variable names and high entropy strings
$xYz123 = "aHR0cDovL2V4YW1wbGUuY29tL21hbGljaW91cy5wczE=";
$AbC456 = [System.Convert]::FromBase64String($xYz123);
$DeF789 = [System.Text.Encoding]::UTF8.GetString($AbC456);

# Suspicious PowerShell techniques
$GhI012 = "UG93ZXJTaGVsbC5leGUgLVdpbmRvd1N0eWxlIEhpZGRlbiAtTm9Qcm9maWxlIC1FeGVjdXRpb25Qb2xpY3kgQnlwYXNz";
$JkL345 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($GhI012));

# Multiple layers of encoding
$layer1 = "VjJWaVEyeHBaVzUwSUVsdWRtOXJaUzFGZUhCeVpYTnphVzl1";
$layer2 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($layer1));
$layer3 = [System.Convert]::FromBase64String($layer2);
$finalPayload = [System.Text.Encoding]::UTF8.GetString($layer3);

# Reflection and assembly loading patterns
$MnO678 = "U3lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHk=";
$PqR901 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($MnO678));

# Network download simulation
$StuVwx = "bmV3LW9iamVjdCBzeXN0ZW0ubmV0LndlYmNsaWVudA==";
$webClientCmd = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($StuVwx));

# Cryptography references
$crypto1 = "U3lzdGVtLlNlY3VyaXR5LkNyeXB0b2dyYXBoeQ==";
$crypto2 = "QUVTLFJpam5kYWVsLERFUw==";
$aesRef = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($crypto1));

# Process manipulation
$procCmd = "c3RhcnQtcHJvY2VzcyAtZmlsZXBhdGggcG93ZXJzaGVsbC5leGUgLWFyZ3VtZW50bGlzdA==";
$startProc = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($procCmd));

# Registry manipulation
$regCmd = "bmV3LWl0ZW1wcm9wZXJ0eSAtcGF0aCBIS0xNOlxTb2Z0d2FyZVxNaWNyb3NvZnRcV2luZG93c1xDdXJyZW50VmVyc2lvblxSdW4=";

# WMI queries
$wmiCmd = "Z2V0LXdtaW9iamVjdCAtY2xhc3Mgd2luMzJfcHJvY2Vzcw==";

# Very long encoded string (typical of malware)
$longPayload = "VGhpcyBpcyBhIHZlcnkgbG9uZyBlbmNvZGVkIHN0cmluZyB0aGF0IHNpbXVsYXRlcyBhIG1hbGljaW91cyBwYXlsb2FkLiBJdCBjb250YWlucyBtdWx0aXBsZSBsYXllcnMgb2YgZW5jb2RpbmcgYW5kIG9iZnVzY2F0aW9uIHRlY2huaXF1ZXMgdGhhdCBhcmUgY29tbW9ubHkgdXNlZCBieSBhdHRhY2tlcnMgdG8gaGlkZSB0aGVpciBtYWxpY2lvdXMgaW50ZW50LiBUaGlzIHN0cmluZyBpcyBkZXNpZ25lZCB0byB0cmlnZ2VyIGhpZ2ggZW50cm9weSBkZXRlY3Rpb24gYW5kIG90aGVyIHN0YXRpYyBhbmFseXNpcyBoZXVyaXN0aWNzLg==";

# Execution
& $a ($finalPayload)