/**
 * AI-Assisted Remediation Engine
 * 
 * Provides AI-suggested fixes for PowerShell scripts with strict validation.
 * 
 * STRICT RULES:
 * - AI can ONLY suggest fixes, never apply them automatically
 * - AI suggestions are treated as UNTRUSTED input
 * - Every AI-suggested fix MUST be re-validated using the full validation pipeline
 * - Implements a CLOSED VALIDATION FEEDBACK LOOP
 * - Loop is bounded (max attempts)
 */

import type { AnalysisResult } from '../../types/analysis';
import { runCloudSecurityValidation } from '../orchestrator';
import type { ValidationConfig } from '../orchestrator';

/**
 * Remediation suggestion from AI
 */
export interface RemediationSuggestion {
  /** The suggested fixed script content */
  suggestedScript: string;
  /** Explanation of what was changed and why */
  explanation: string;
  /** List of specific changes made */
  changes: RemediationChange[];
  /** Confidence level (0-1) */
  confidence: number;
}

/**
 * Individual change in a remediation suggestion
 */
export interface RemediationChange {
  /** Type of change */
  type: 'replace' | 'add' | 'remove' | 'refactor';
  /** Description of the change */
  description: string;
  /** Line number or location (if applicable) */
  location?: string;
  /** Original code (if applicable) */
  original?: string;
  /** New code (if applicable) */
  replacement?: string;
}

/**
 * Validation result for a remediation suggestion
 */
export interface RemediationValidationResult {
  /** Whether the suggestion was accepted */
  accepted: boolean;
  /** Validation status */
  status: 'accepted' | 'rejected' | 'needs_refinement';
  /** Reason for acceptance or rejection */
  reason: string;
  /** Analysis result of the suggested fix */
  analysisResult: AnalysisResult;
  /** Comparison with original */
  improvement: {
    riskScoreChange: number;
    policyViolationsChange: number;
    decisionChange: string;
  };
}

/**
 * Remediation attempt with feedback
 */
export interface RemediationAttempt {
  /** Attempt number (1-based) */
  attemptNumber: number;
  /** The suggestion made */
  suggestion: RemediationSuggestion;
  /** Validation result */
  validation: RemediationValidationResult;
}

/**
 * Complete remediation result
 */
export interface RemediationResult {
  /** Original analysis result */
  originalAnalysis: AnalysisResult;
  /** All remediation attempts */
  attempts: RemediationAttempt[];
  /** Final best suggestion (if any) */
  bestSuggestion?: RemediationSuggestion;
  /** Whether a valid remediation was found */
  success: boolean;
  /** Final status message */
  statusMessage: string;
}

/**
 * Configuration for AI remediation
 */
export interface RemediationConfig {
  /** Maximum number of remediation attempts */
  maxAttempts?: number;
  /** Minimum improvement in risk score to accept */
  minRiskScoreImprovement?: number;
  /** Whether to allow suggestions that still have violations */
  allowRemainingViolations?: boolean;
  /** Validation config to use for re-validation */
  validationConfig?: ValidationConfig;
}

/**
 * AI Remediation Engine
 * 
 * Provides AI-suggested fixes with strict validation feedback loop.
 */
export class AIRemediationEngine {
  private readonly maxAttempts: number;

  constructor(config: RemediationConfig = {}) {
    this.maxAttempts = config.maxAttempts ?? 3;
  }

  /**
   * Generate remediation suggestions for a script
   * 
   * @param originalScript - The original script content
   * @param originalAnalysis - The original analysis result
   * @param config - Optional remediation configuration
   * @returns Remediation result with suggestions and validation
   */
  async generateRemediation(
    originalScript: string,
    originalAnalysis: AnalysisResult,
    config?: RemediationConfig
  ): Promise<RemediationResult> {
    const maxAttempts = config?.maxAttempts ?? this.maxAttempts;
    const attempts: RemediationAttempt[] = [];
    let currentScript = originalScript;
    let previousValidation: RemediationValidationResult | null = null;
    const appliedFixes = new Set<string>(); // Track what fixes have been tried

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      // Generate AI suggestion with concrete script modifications
      const suggestion = this.generateAISuggestion(
        currentScript,
        originalAnalysis,
        previousValidation,
        attempt,
        appliedFixes
      );

      // CRITICAL: Re-validate the suggestion using the full validation pipeline
      const validation = this.validateSuggestion(
        suggestion.suggestedScript,
        originalAnalysis,
        config?.validationConfig
      );

      const attemptResult: RemediationAttempt = {
        attemptNumber: attempt,
        suggestion,
        validation
      };

      attempts.push(attemptResult);
      previousValidation = validation;

      // Track applied fixes BEFORE checking acceptance
      suggestion.changes.forEach(change => {
        if (change.description) {
          appliedFixes.add(change.description);
        }
      });

      // Check if suggestion is acceptable
      if (validation.accepted) {
        return {
          originalAnalysis,
          attempts,
          bestSuggestion: suggestion,
          success: true,
          statusMessage: `Remediation successful after ${attempt} attempt(s). Risk score improved by ${validation.improvement.riskScoreChange} points.`
        };
      }

      // Always use the suggested script as base for next attempt (even if rejected)
      // This ensures each attempt builds on the previous one
      if (attempt < maxAttempts) {
        currentScript = suggestion.suggestedScript;
      }
    }

    // No acceptable remediation found
    const bestAttempt = attempts.reduce((best, current) => {
      const currentImprovement = current.validation.improvement.riskScoreChange;
      const bestImprovement = best.validation.improvement.riskScoreChange;
      return currentImprovement > bestImprovement ? current : best;
    }, attempts[0]);

    return {
      originalAnalysis,
      attempts,
      bestSuggestion: bestAttempt?.suggestion,
      success: false,
      statusMessage: `Remediation completed after ${maxAttempts} attempts. Best improvement: ${bestAttempt.validation.improvement.riskScoreChange} points. Status: ${bestAttempt.validation.status}.`
    };
  }

  /**
   * Generate AI suggestion with CONCRETE script modifications
   * 
   * This generates actual PowerShell script modifications, not just advice.
   * Each attempt targets different issues to ensure variety.
   */
  private generateAISuggestion(
    script: string,
    originalAnalysis: AnalysisResult,
    _previousValidation: RemediationValidationResult | null,
    attemptNumber: number,
    appliedFixes: Set<string>
  ): RemediationSuggestion {
    const changes: RemediationChange[] = [];
    let suggestedScript = script;
    let explanation = '';

    const features = originalAnalysis.features;
    const scriptLower = script.toLowerCase();

    // ===== ATTEMPT 1: Address hardcoded credentials with EXECUTABLE secure code =====
    if (attemptNumber === 1 && !appliedFixes.has('hardcoded-credentials')) {
      const credentialPatterns = [
        { pattern: /\$password\s*=\s*["']([^"']+)["']/gi, varName: 'password', keyName: 'password' },
        { pattern: /\$pwd\s*=\s*["']([^"']+)["']/gi, varName: 'pwd', keyName: 'password' },
        { pattern: /\$secret\s*=\s*["']([^"']+)["']/gi, varName: 'secret', keyName: 'secret' },
        { pattern: /\$token\s*=\s*["']([^"']+)["']/gi, varName: 'token', keyName: 'token' },
        { pattern: /\$apikey\s*=\s*["']([^"']+)["']/gi, varName: 'apikey', keyName: 'apikey' },
        { pattern: /\$api_key\s*=\s*["']([^"']+)["']/gi, varName: 'api_key', keyName: 'apikey' }
      ];

      for (const { pattern, varName, keyName } of credentialPatterns) {
        if (pattern.test(script)) {
          const matches = [...script.matchAll(pattern)];
          if (matches.length > 0) {
            const firstMatch = matches[0];
            const originalLine = firstMatch[0];
            const varPart = originalLine.split('=')[0].trim();
            // Replace with Read-Host -AsSecureString (executable, secure, no policy violation)
            const replacement = `${varPart} = Read-Host -Prompt "Enter ${keyName}" -AsSecureString`;
            suggestedScript = suggestedScript.replace(originalLine, replacement);
            changes.push({
              type: 'replace',
              description: 'hardcoded-credentials',
              location: 'authentication section',
              original: originalLine,
              replacement: replacement
            });
            explanation = `Replaced hardcoded ${varName} with Read-Host -AsSecureString for secure credential input (POL-003).`;
            break;
          }
        }
      }

      // Also fix ConvertTo-SecureString -AsPlainText patterns
      if (suggestedScript.includes('ConvertTo-SecureString') && suggestedScript.includes('-AsPlainText')) {
        const plaintextPattern = /ConvertTo-SecureString\s+[^-]+-AsPlainText[^\r\n]*/gi;
        const plaintextMatches = suggestedScript.match(plaintextPattern);
        if (plaintextMatches && plaintextMatches.length > 0) {
          // Replace with Read-Host -AsSecureString (executable code)
          const originalLine = plaintextMatches[0];
          suggestedScript = suggestedScript.replace(
            plaintextPattern,
            '$securePassword = Read-Host -Prompt "Enter password" -AsSecureString'
          );
          changes.push({
            type: 'replace',
            description: 'plaintext-conversion',
            location: 'credential conversion',
            original: originalLine.trim(),
            replacement: 'Read-Host -AsSecureString'
          });
          if (!explanation) {
            explanation = 'Replaced ConvertTo-SecureString -AsPlainText with Read-Host -AsSecureString (POL-003).';
          }
        }
      }
    }

    // ===== ATTEMPT 1 (if no credentials) or ATTEMPT 2: Replace network downloads with EXECUTABLE secure code =====
    if ((attemptNumber === 1 && changes.length === 0) || attemptNumber === 2) {
      if (!appliedFixes.has('network-download-security')) {
        // Replace with EXECUTABLE PowerShell that includes allowlist validation and checksum verification
        const networkPatterns = [
          { 
            pattern: /Invoke-WebRequest\s+-Uri\s+["']([^"']+)["']([^\r\n]*)/gi, 
            cmd: 'Invoke-WebRequest',
            replacement: (url: string, rest: string) => {
              // Extract output file if present
              const outFileMatch = rest.match(/-OutFile\s+["']([^"']+)["']/i);
              const outFile = outFileMatch ? outFileMatch[1] : '$null';
              
              // Generate executable code with allowlist and checksum validation
              return `# SECURITY: Validated network download with allowlist and checksum verification
$allowedUrls = @("https://trusted-source.com", "https://trusted-api.com")  # Configure allowed URLs
$expectedHash = "SHA256_HASH_HERE"  # Configure expected file hash
$requestUrl = "${url}"
if ($allowedUrls -contains $requestUrl) {
    try {
        $response = Invoke-WebRequest -Uri $requestUrl -UseBasicParsing -ErrorAction Stop${rest}
        ${outFile !== '$null' ? `$downloadedHash = (Get-FileHash -Path "${outFile}" -Algorithm SHA256).Hash
        if ($downloadedHash -eq $expectedHash) {
            Write-Host "File verified successfully"
        } else {
            Write-Error "Hash verification failed - file may be compromised"
            Remove-Item "${outFile}" -ErrorAction SilentlyContinue
            throw "Security validation failed"
        }` : ''}
    } catch {
        Write-Error "Network operation failed: $_"
        throw
    }
} else {
    Write-Error "URL not in allowlist: $requestUrl"
    throw "Unauthorized network access attempt"
}`;
            }
          },
          { 
            pattern: /Invoke-RestMethod\s+-Uri\s+["']([^"']+)["']([^\r\n]*)/gi, 
            cmd: 'Invoke-RestMethod',
            replacement: (url: string, rest: string) => {
              return `# SECURITY: Validated API call with allowlist
$allowedUrls = @("https://trusted-api.com", "https://api.trusted-source.com")  # Configure allowed URLs
$requestUrl = "${url}"
if ($allowedUrls -contains $requestUrl) {
    try {
        $response = Invoke-RestMethod -Uri $requestUrl -ErrorAction Stop${rest}
        Write-Host "API call successful"
    } catch {
        Write-Error "API call failed: $_"
        throw
    }
} else {
    Write-Error "URL not in allowlist: $requestUrl"
    throw "Unauthorized API access attempt"
}`;
            }
          },
          { 
            pattern: /\$webClient\s*=\s*New-Object\s+System\.Net\.WebClient[^\r\n]*/gi, 
            cmd: 'WebClient',
            replacement: () => {
              return `# SECURITY: Replaced WebClient with validated download
$allowedUrls = @("https://trusted-source.com")  # Configure allowed URLs
$expectedHash = "SHA256_HASH_HERE"  # Configure expected file hash
# WebClient removed - use validated Invoke-WebRequest instead`;
            }
          },
          { 
            pattern: /\$webClient\.DownloadFile\(["']([^"']+)["']\s*,\s*["']([^"']+)["']\)/gi, 
            cmd: 'DownloadFile',
            replacement: (url: string, file: string) => {
              return `# SECURITY: Replaced DownloadFile with validated download
$allowedUrls = @("https://trusted-source.com")  # Configure allowed URLs
$expectedHash = "SHA256_HASH_HERE"  # Configure expected file hash
$requestUrl = "${url}"
$outputFile = "${file}"
if ($allowedUrls -contains $requestUrl) {
    try {
        Invoke-WebRequest -Uri $requestUrl -OutFile $outputFile -UseBasicParsing -ErrorAction Stop
        $downloadedHash = (Get-FileHash -Path $outputFile -Algorithm SHA256).Hash
        if ($downloadedHash -eq $expectedHash) {
            Write-Host "File verified successfully"
        } else {
            Write-Error "Hash verification failed - file may be compromised"
            Remove-Item $outputFile -ErrorAction SilentlyContinue
            throw "Security validation failed"
        }
    } catch {
        Write-Error "Download failed: $_"
        throw
    }
} else {
    Write-Error "URL not in allowlist: $requestUrl"
    throw "Unauthorized download attempt"
}`;
            }
          }
        ];

        for (const { pattern, cmd, replacement } of networkPatterns) {
          if (pattern.test(suggestedScript)) {
            const matches = [...suggestedScript.matchAll(pattern)];
            if (matches.length > 0) {
              const firstMatch = matches[0];
              let newCode: string;
              if (typeof replacement === 'function') {
                if (firstMatch.length > 2 && firstMatch[1] !== undefined) {
                  newCode = replacement(firstMatch[1] || '', firstMatch[2] || '');
                } else if (firstMatch.length > 3) {
                  newCode = replacement(firstMatch[1] || '', firstMatch[2] || '');
                } else {
                  newCode = (replacement as () => string)();
                }
              } else {
                newCode = replacement;
              }
              suggestedScript = suggestedScript.replace(firstMatch[0], newCode);
              changes.push({
                type: 'replace',
                description: 'network-download-security',
                location: 'network operations',
                original: firstMatch[0].trim(),
                replacement: 'Replaced with validated secure alternative'
              });
              if (!explanation) {
                explanation = `Replaced ${cmd} with validated secure alternative including allowlist and checksum verification (POL-004).`;
              }
              break;
            }
          }
        }
      }
    }

    // ===== ATTEMPT 2: Remove execution policy bypass and replace Invoke-Expression =====
    if (attemptNumber === 2 && !appliedFixes.has('execution-policy-bypass')) {
      // Remove ExecutionPolicy Bypass (executable removal)
      if (scriptLower.includes('set-executionpolicy') && scriptLower.includes('bypass')) {
        const bypassPatterns = [
          /Set-ExecutionPolicy\s+.*?Bypass.*?[\r\n]/gi,
          /Set-ExecutionPolicy\s+-ExecutionPolicy\s+Bypass[^\r\n]*/gi,
          /powershell\.exe.*-ExecutionPolicy\s+Bypass[^\r\n]*/gi
        ];

        for (const pattern of bypassPatterns) {
          if (pattern.test(suggestedScript)) {
            const matches = suggestedScript.match(pattern);
            if (matches && matches.length > 0) {
              const originalLine = matches[0].trim();
              // Remove the line entirely (executable removal)
              suggestedScript = suggestedScript.replace(pattern, '');
              changes.push({
                type: 'remove',
                description: 'execution-policy-bypass',
                location: 'execution policy section',
                original: originalLine,
                replacement: 'Removed execution policy bypass'
              });
              if (!explanation) {
                explanation = 'Removed execution policy bypass to comply with security policies (POL-002).';
              }
              break;
            }
          }
        }
      }

      // Replace Invoke-Expression with validated execution (executable code)
      if (!appliedFixes.has('invoke-expression') && (scriptLower.includes('invoke-expression') || scriptLower.includes('iex'))) {
        const iexPatterns = [
          /Invoke-Expression\s+["']([^"']+)["']/gi,
          /Invoke-Expression\s+(\$[a-zA-Z0-9_]+)/gi,
          /\$iex\s*=\s*["']([^"']+)["']/gi,
          /iex\s+["']([^"']+)["']/gi
        ];

        for (const pattern of iexPatterns) {
          if (pattern.test(suggestedScript)) {
            const matches = [...suggestedScript.matchAll(pattern)];
            if (matches.length > 0) {
              const firstMatch = matches[0];
              const codeToExecute = firstMatch[1] || firstMatch[0];
              // Replace with validated execution using script block
              const replacement = `# SECURITY: Replaced Invoke-Expression with validated script block execution
$allowedCommands = @("Get-Process", "Get-Service", "Get-ChildItem")  # Configure allowed commands
$codeToExecute = ${codeToExecute}
$scriptBlock = [scriptblock]::Create($codeToExecute)
$commandName = ($scriptBlock.Ast.FindAll({$args[0] -is [System.Management.Automation.Language.CommandAst]}, $true) | Select-Object -First 1).CommandElements[0].Value
if ($allowedCommands -contains $commandName) {
    & $scriptBlock
} else {
    Write-Error "Command not in allowlist: $commandName"
    throw "Unauthorized command execution attempt"
}`;
              suggestedScript = suggestedScript.replace(firstMatch[0], replacement);
              changes.push({
                type: 'replace',
                description: 'invoke-expression',
                location: 'code execution',
                original: firstMatch[0].trim(),
                replacement: 'Replaced with validated script block execution'
              });
              if (!explanation) {
                explanation = 'Replaced Invoke-Expression with validated script block execution using allowlist (POL-005).';
              }
              break;
            }
          }
        }
      }
    }

    // ===== ATTEMPT 2 (if no bypass found) or ATTEMPT 3: Add error handling =====
    if ((attemptNumber === 2 && changes.length === 0) || attemptNumber === 3) {
      if (!appliedFixes.has('error-handling')) {
        const networkCommands = ['Invoke-WebRequest', 'Invoke-RestMethod', 'Invoke-Expression'];
        let foundNetworkCall = false;

        for (const cmd of networkCommands) {
          if (suggestedScript.includes(cmd) && !suggestedScript.includes('try {')) {
          // Find the first occurrence and wrap it
          const cmdPattern = new RegExp(`(${cmd.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[^\\r\\n]*)`, 'i');
          const matchResult = suggestedScript.match(cmdPattern);
          if (matchResult) {
            const originalLine = matchResult[0];
              const indented = originalLine.split('\n').map((line: string) => '    ' + line).join('\n');
              const wrapped = `try {\n${indented}\n} catch {\n    Write-Error "${cmd} failed: $_"\n    throw\n}`;
              suggestedScript = suggestedScript.replace(originalLine, wrapped);
              changes.push({
                type: 'add',
                description: 'error-handling',
                location: 'network operations',
                original: originalLine,
                replacement: 'Wrapped in try-catch block'
              });
              if (!explanation) {
                explanation = `Added error handling to ${cmd} for better security and reliability.`;
              }
              foundNetworkCall = true;
              break;
            }
          }
        }

        // If no network calls, add input validation to parameters
        if (!foundNetworkCall && suggestedScript.includes('param(')) {
          const paramPattern = /param\s*\(([^)]*)\)/i;
          const paramMatch = suggestedScript.match(paramPattern);
          if (paramMatch && !suggestedScript.includes('ValidateNotNullOrEmpty')) {
            // Add validation to first parameter
            const params = paramMatch[1];
            const firstParamMatch = params.match(/(\$[a-zA-Z0-9_]+)/);
            if (firstParamMatch) {
              const paramName = firstParamMatch[1];
              const validatedParams = params.replace(
                new RegExp(`\\$${paramName.replace('$', '')}`, 'i'),
                `[Parameter(Mandatory=$true)]\n    [ValidateNotNullOrEmpty()]\n    ${paramName}`
              );
              suggestedScript = suggestedScript.replace(
                paramPattern,
                `param(\n    ${validatedParams}\n)`
              );
              changes.push({
                type: 'add',
                description: 'input-validation',
                location: 'parameter section',
                original: paramMatch[0],
                replacement: 'Added validation attributes'
              });
              if (!explanation) {
                explanation = 'Added input validation to parameters for better security.';
              }
            }
          }
        }
      }
    }

    // ===== ATTEMPT 3: Add security comments and improve auditability =====
    if (attemptNumber === 3 && !appliedFixes.has('security-comments')) {
      // Add security header if not present
      if (!suggestedScript.includes('# Security-validated script')) {
        suggestedScript = '# Security-validated script\n# Generated by AI Remediation Engine\n# Review all changes before deployment\n\n' + suggestedScript;
        changes.push({
          type: 'add',
          description: 'security-header',
          location: 'script header',
          original: '',
          replacement: 'Added security validation header'
        });
        if (!explanation) {
          explanation = 'Added security validation header comments for better auditability.';
        }
      }

      // Add comments for Base64 content
      if (features.base64Count > 0 && !appliedFixes.has('base64-comments')) {
        const base64Pattern = /(\$[a-zA-Z0-9_]+\s*=\s*["'])([A-Za-z0-9+/=]{30,})(["'])/g;
        const base64Matches = [...suggestedScript.matchAll(base64Pattern)];
        if (base64Matches.length > 0) {
          const firstMatch = base64Matches[0];
          const beforeMatch = suggestedScript.substring(0, suggestedScript.indexOf(firstMatch[0]));
          const lineNumber = beforeMatch.split('\n').length;
          suggestedScript = suggestedScript.replace(
            firstMatch[0],
            `# SECURITY REVIEW REQUIRED: Base64 encoded content detected (line ${lineNumber})\n${firstMatch[0]}`
          );
          changes.push({
            type: 'refactor',
            description: 'base64-comments',
            location: `line ${lineNumber}`,
            original: firstMatch[0].substring(0, 50) + '...',
            replacement: 'Added security comment'
          });
          if (!explanation) {
            explanation = 'Added security comments for Base64 encoded content to improve auditability.';
          }
        }
      }
    }

    // ===== FALLBACK: If no changes made, make a minimal safe improvement =====
    if (changes.length === 0) {
      // Add a comment at the top if header doesn't exist
      if (!suggestedScript.startsWith('#')) {
        suggestedScript = `# PowerShell Script\n# Reviewed by Cloud Security Validation System\n\n${suggestedScript}`;
        changes.push({
          type: 'add',
          description: 'script-header',
          location: 'script header',
          original: '',
          replacement: 'Added script header'
        });
        explanation = `Attempt ${attemptNumber}: Added script header. Review script for security improvements.`;
      } else {
        // Add a TODO comment
        const lines = suggestedScript.split('\n');
        if (lines.length > 0) {
          lines.splice(1, 0, '# TODO: Review this script for security best practices and policy compliance');
          suggestedScript = lines.join('\n');
          changes.push({
            type: 'add',
            description: 'review-comment',
            location: 'script header',
            original: '',
            replacement: 'Added review comment'
          });
          explanation = `Attempt ${attemptNumber}: Added security review comment. Manual review recommended.`;
        }
      }
    }

    return {
      suggestedScript: suggestedScript || script,
      explanation: explanation || `Attempt ${attemptNumber}: Applied security improvements based on analysis.`,
      changes,
      confidence: Math.max(0.3, 1.0 - (attemptNumber - 1) * 0.25)
    };
  }

  /**
   * Validate a remediation suggestion using the full validation pipeline
   * 
   * This is CRITICAL: Every suggestion must be re-validated.
   */
  private validateSuggestion(
    suggestedScript: string,
    originalAnalysis: AnalysisResult,
    validationConfig?: ValidationConfig
  ): RemediationValidationResult {
    // Re-run full validation pipeline on suggested script
    const suggestedAnalysis = runCloudSecurityValidation(
      suggestedScript,
      originalAnalysis.filename,
      validationConfig
    );

    const originalRiskScore = originalAnalysis.riskScore?.overallScore || 0;
    const suggestedRiskScore = suggestedAnalysis.riskScore?.overallScore || 0;
    const riskScoreChange = originalRiskScore - suggestedRiskScore; // Positive = improvement

    const originalViolations = originalAnalysis.policyValidation?.violations.length || 0;
    const suggestedViolations = suggestedAnalysis.policyValidation?.violations.length || 0;
    const violationsChange = originalViolations - suggestedViolations; // Positive = improvement

    const originalDecision = originalAnalysis.decision?.decision || 'block';
    const suggestedDecision = suggestedAnalysis.decision?.decision || 'block';

    // Determine if suggestion is acceptable
    // ACCEPT if: risk score decreases OR severity of at least one violation is reduced
    let accepted = false;
    let status: 'accepted' | 'rejected' | 'needs_refinement' = 'rejected';
    let reason = '';

    // Check for severity reduction in violations
    const originalViolationsBySeverity = this.groupViolationsBySeverity(originalAnalysis.policyValidation?.violations || []);
    const suggestedViolationsBySeverity = this.groupViolationsBySeverity(suggestedAnalysis.policyValidation?.violations || []);
    const severityReduced = this.hasSeverityReduction(originalViolationsBySeverity, suggestedViolationsBySeverity);

    // ACCEPTANCE CRITERIA: Accept if risk score decreases OR severity is reduced
    if (riskScoreChange > 0 || severityReduced) {
      // Accept if risk improved by any amount OR severity was reduced
      if (riskScoreChange > 0 || severityReduced) {
        accepted = true;
        status = 'accepted';
        const parts: string[] = [];
        if (riskScoreChange > 0) {
          parts.push(`Risk score improved by ${riskScoreChange} points`);
        }
        if (violationsChange > 0) {
          parts.push(`Policy violations reduced by ${violationsChange}`);
        }
        if (severityReduced) {
          parts.push('Severity of violations reduced');
        }
        reason = parts.join('. ') + '.';
      }
    } else if (riskScoreChange === 0 && violationsChange === 0 && !severityReduced) {
      // Check if script actually changed
      const scriptChanged = suggestedScript !== originalAnalysis.scriptContent;
      if (!scriptChanged) {
        status = 'rejected';
        reason = 'Suggestion did not modify the script. No changes detected.';
      } else {
        status = 'rejected';
        reason = 'Suggestion modified the script but did not change risk score, policy violations, or severity. Changes may not address security issues.';
      }
    } else {
      status = 'rejected';
      reason = `Suggestion did not improve risk score or reduce severity. Risk ${riskScoreChange < 0 ? 'increased' : 'unchanged'} by ${Math.abs(riskScoreChange)} points.`;
    }

    // Additional check: if decision improved from BLOCK to ALLOW or REVIEW
    if (!accepted && originalDecision === 'block' && (suggestedDecision === 'allow' || suggestedDecision === 'review')) {
      if (status === 'rejected') {
        status = 'needs_refinement';
      }
      reason += ` Decision improved from BLOCK to ${suggestedDecision.toUpperCase()}.`;
    }

    return {
      accepted,
      status,
      reason,
      analysisResult: suggestedAnalysis,
      improvement: {
        riskScoreChange,
        policyViolationsChange: violationsChange,
        decisionChange: `${originalDecision} → ${suggestedDecision}`
      }
    };
  }

  /**
   * Group violations by severity
   */
  private groupViolationsBySeverity(violations: any[]): { [key: string]: number } {
    const grouped: { [key: string]: number } = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    };
    violations.forEach(v => {
      const severity = v.severity?.toLowerCase() || 'low';
      if (grouped[severity] !== undefined) {
        grouped[severity]++;
      }
    });
    return grouped;
  }

  /**
   * Check if severity was reduced (e.g., CRITICAL -> HIGH, HIGH -> MEDIUM, etc.)
   */
  private hasSeverityReduction(original: { [key: string]: number }, suggested: { [key: string]: number }): boolean {
    // Check if any higher severity violations were reduced
    if (suggested.critical < original.critical) return true;
    if (suggested.high < original.high && suggested.critical <= original.critical) return true;
    if (suggested.medium < original.medium && suggested.critical <= original.critical && suggested.high <= original.high) return true;
    return false;
  }
}
