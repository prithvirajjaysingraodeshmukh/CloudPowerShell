# Test Scripts Guide

This guide provides example PowerShell scripts to test the Cloud-Aware PowerShell Security Validation system.

## Quick Test Scripts

### 1. Hardcoded Credentials Test
**File:** `test_hardcoded_credentials.ps1`

This script contains hardcoded passwords and API keys, which should trigger:
- **POL-003**: Hardcoded Credentials or Token Access (CRITICAL)
- High risk score
- BLOCK decision

**Expected Remediation:**
- Attempt 1: Replace hardcoded credentials with Azure Key Vault references
- Risk score should decrease
- Policy violations should reduce

---

### 2. Network Download Test
**File:** `test_network_download.ps1`

This script performs unrestricted network downloads, which should trigger:
- **POL-004**: Unrestricted Network Downloads (HIGH)
- Network exposure risk
- REVIEW or BLOCK decision

**Expected Remediation:**
- Attempt 1: Add `-UseBasicParsing` flag to `Invoke-WebRequest`
- Attempt 2: Add error handling to network operations
- Risk score should decrease

---

### 3. Execution Policy Bypass Test
**File:** `test_execution_policy.ps1`

This script attempts to bypass execution policies, which should trigger:
- **POL-002**: Privilege Escalation Operations (CRITICAL)
- High privilege risk
- BLOCK decision

**Expected Remediation:**
- Attempt 2: Remove execution policy bypass commands
- Add comments explaining security concerns
- Risk score should decrease

---

### 4. Mixed Issues Test
**File:** `test_mixed_issues.ps1`

This script contains multiple security issues:
- Hardcoded credentials
- Network downloads
- Execution policy bypass
- Base64 encoding

**Expected Remediation:**
- Multiple attempts addressing different issues
- Each attempt should show measurable improvement
- Best attempt should show significant risk reduction

---

### 5. Benign Simple Script
**File:** `benign_simple.ps1`

A clean, legitimate script with:
- Low risk score
- No policy violations
- ALLOW decision

**Use Case:** Baseline comparison

---

### 6. Suspicious Encoded Script
**File:** `suspicious_encoded.ps1`

Contains Base64 encoding and suspicious patterns:
- Multiple Base64 strings
- Execution policy bypass
- Medium to high risk

**Expected Remediation:**
- Attempt 3: Add security comments for Base64 content
- Improve auditability

---

### 7. Malicious Extreme Script
**File:** `malicious_extreme.ps1`

Heavily obfuscated script with:
- Maximum obfuscation
- Multiple Base64 payloads
- Critical risk score
- BLOCK decision

**Use Case:** Testing worst-case scenario

---

## How to Test AI Remediation

1. **Paste a test script** into the input panel
2. **Click "Analyze Script"** to get initial analysis
3. **Go to "Remediation" tab**
4. **Click "Generate Remediation"**
5. **Observe each attempt:**
   - Original script vs Remediated script (side-by-side)
   - Risk score changes (before → after)
   - Policy violations changes
   - Decision changes
   - Validation status (Accepted/Rejected/Needs Refinement)

## Expected Behavior

### Each Attempt Should:
- ✅ Generate a **concrete modified script** (not just advice)
- ✅ Show **different modifications** in each attempt
- ✅ Pass through **full validation pipeline**
- ✅ Display **measurable improvements** (risk score, violations, decision)

### Acceptance Criteria:
- **ACCEPTED**: Risk score improved by ≥5 points OR at least 1 violation removed
- **NEEDS REFINEMENT**: Small improvement but below threshold
- **REJECTED**: No improvement or regression

## Testing Checklist

- [ ] Test with hardcoded credentials script
- [ ] Test with network download script
- [ ] Test with execution policy bypass script
- [ ] Test with mixed issues script
- [ ] Verify each attempt shows different script modifications
- [ ] Verify risk scores change between attempts
- [ ] Verify policy violations change between attempts
- [ ] Verify original vs remediated scripts are displayed
- [ ] Verify validation status is accurate

## Notes

- AI remediation is **UNTRUSTED** - all suggestions are re-validated
- Scripts are **never executed** - only static analysis
- Each remediation attempt is **independent** and goes through full validation
- The system maintains **security guarantees** - AI cannot bypass policies

