# PowerShell Test Samples

This directory contains synthetic PowerShell test samples designed to validate the static analysis tool's detection capabilities.

## Sample Categories

### 1. Benign Scripts
- **benign_simple.ps1**: Basic system information gathering script
- **benign_moderate.ps1**: Log file analyzer with moderate complexity

### 2. Suspicious Scripts
- **suspicious_encoded.ps1**: Contains Base64 encoded strings and execution policy bypass

### 3. Malicious Scripts
- **malicious_obfuscated.ps1**: Heavily obfuscated with multiple suspicious indicators
- **malicious_extreme.ps1**: Maximum obfuscation with extremely long Base64 payloads

## Expected Detection Results

| Script | Expected Classification | Key Indicators |
|--------|------------------------|----------------|
| benign_simple.ps1 | Benign | Low entropy, no suspicious keywords |
| benign_moderate.ps1 | Benign | Moderate complexity, legitimate functions |
| suspicious_encoded.ps1 | Suspicious | Multiple Base64 strings, execution policy bypass |
| malicious_obfuscated.ps1 | Malicious | High entropy, many suspicious keywords, obfuscation |
| malicious_extreme.ps1 | Malicious | Extreme obfuscation, very long encoded payloads |

## Usage

Upload these files to your PowerShell Static Analyzer to test:

1. **Detection accuracy** - Verify correct classification
2. **Feature extraction** - Check entropy, Base64 detection, keyword counting
3. **Visualization** - Compare characteristics across categories
4. **Export functionality** - Test CSV export with known data

## Safety Note

These are synthetic test samples created for educational purposes. The "malicious" samples contain only harmless encoded strings and do not perform any actual malicious actions.