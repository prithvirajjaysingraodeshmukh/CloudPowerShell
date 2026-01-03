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
  private readonly minRiskScoreImprovement: number;
  private readonly allowRemainingViolations: boolean;

  constructor(config: RemediationConfig = {}) {
    this.maxAttempts = config.maxAttempts ?? 3;
    this.minRiskScoreImprovement = config.minRiskScoreImprovement ?? 10;
    this.allowRemainingViolations = config.allowRemainingViolations ?? false;
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

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      // Generate AI suggestion (simulated - in real implementation, this would call an AI service)
      const suggestion = this.generateAISuggestion(
        currentScript,
        originalAnalysis,
        previousValidation,
        attempt
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

      // If not accepted and not the last attempt, refine for next iteration
      if (attempt < maxAttempts && validation.status === 'needs_refinement') {
        currentScript = suggestion.suggestedScript; // Use current suggestion as base for refinement
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
   * Generate AI suggestion (simulated - replace with actual AI service call)
   * 
   * This is a SIMULATION. In production, this would call an AI service.
   * The simulation demonstrates the pattern without external dependencies.
   */
  private generateAISuggestion(
    script: string,
    originalAnalysis: AnalysisResult,
    previousValidation: RemediationValidationResult | null,
    attemptNumber: number
  ): RemediationSuggestion {
    const changes: RemediationChange[] = [];
    let suggestedScript = script;
    let explanation = '';

    // Use feedback from previous validation to refine suggestions
    if (previousValidation) {
      const violations = previousValidation.analysisResult.policyValidation?.violations || [];

      // Focus on critical violations first
      const criticalViolations = violations.filter((v: { severity: string }) => v.severity === 'critical');
      if (criticalViolations.length > 0 && attemptNumber === 1) {
        // First attempt: address critical violations
        const violation = criticalViolations[0];
        if (violation.policyId === 'POL-003' && violation.evidence.includes('password')) {
          // Suggest using Key Vault instead of hardcoded passwords
          suggestedScript = this.suggestKeyVaultUsage(suggestedScript);
          changes.push({
            type: 'replace',
            description: 'Replace hardcoded password with Azure Key Vault reference',
            location: 'authentication section',
            original: 'password = "..."',
            replacement: '$password = Get-AzKeyVaultSecret -VaultName "vault" -Name "password"'
          });
          explanation = 'Replaced hardcoded password with secure Key Vault reference to comply with authentication policy.';
        }
      }
    } else {
      // First attempt: analyze original issues
      const riskScore = originalAnalysis.riskScore?.overallScore || 0;

      if (riskScore > 50) {
        // High risk - suggest general improvements
        if (script.includes('Invoke-WebRequest') && !script.includes('UseBasicParsing')) {
          suggestedScript = script.replace(
            /Invoke-WebRequest/g,
            'Invoke-WebRequest -UseBasicParsing'
          );
          changes.push({
            type: 'add',
            description: 'Add -UseBasicParsing flag to Invoke-WebRequest for better security',
            location: 'network operations'
          });
          explanation = 'Added -UseBasicParsing flag to reduce attack surface.';
        }
      }
    }

    // If no changes were made, provide a generic suggestion
    if (changes.length === 0) {
      explanation = `Attempt ${attemptNumber}: Analyzing script for security improvements. Review policy violations and risk factors.`;
      changes.push({
        type: 'refactor',
        description: 'Review and refactor based on policy violations',
        location: 'entire script'
      });
    }

    return {
      suggestedScript: suggestedScript || script,
      explanation,
      changes,
      confidence: Math.max(0.5, 1.0 - (attemptNumber - 1) * 0.2) // Decrease confidence with attempts
    };
  }

  /**
   * Suggest Key Vault usage (helper method)
   */
  private suggestKeyVaultUsage(script: string): string {
    // Simple pattern replacement - in production, use more sophisticated parsing
    const patterns = [
      /password\s*=\s*["']([^"']+)["']/gi,
      /pwd\s*=\s*["']([^"']+)["']/gi,
      /secret\s*=\s*["']([^"']+)["']/gi
    ];

    let modified = script;
    patterns.forEach(pattern => {
      modified = modified.replace(pattern, () => {
        return `$password = Get-AzKeyVaultSecret -VaultName "your-keyvault" -Name "password" -AsPlainText`;
      });
    });

    return modified;
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
    let accepted = false;
    let status: 'accepted' | 'rejected' | 'needs_refinement' = 'rejected';
    let reason = '';

    if (riskScoreChange >= this.minRiskScoreImprovement) {
      if (suggestedViolations === 0 || this.allowRemainingViolations) {
        accepted = true;
        status = 'accepted';
        reason = `Risk score improved by ${riskScoreChange} points. Policy violations reduced by ${violationsChange}.`;
      } else {
        status = 'needs_refinement';
        reason = `Risk score improved by ${riskScoreChange} points, but ${suggestedViolations} policy violations remain. Refinement needed.`;
      }
    } else if (riskScoreChange > 0) {
      status = 'needs_refinement';
      reason = `Risk score improved by ${riskScoreChange} points, but improvement is below threshold (${this.minRiskScoreImprovement}). Refinement needed.`;
    } else {
      status = 'rejected';
      reason = `Suggestion did not improve risk score. Risk increased by ${-riskScoreChange} points.`;
    }

    // Additional check: if decision improved from BLOCK to ALLOW or REVIEW
    if (!accepted && originalDecision === 'block' && (suggestedDecision === 'allow' || suggestedDecision === 'review')) {
      status = 'needs_refinement';
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
}

