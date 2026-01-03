/**
 * Cloud Security Validation Orchestrator
 * 
 * Single entry point for cloud-aware PowerShell security validation.
 * Coordinates all engines and returns comprehensive validation results.
 */

import type { AnalysisResult } from '../types/analysis';
import {
  StaticAnalysisEngine,
  CloudExecutionContextEngine,
  CloudSecurityPolicyEngine,
  CloudRiskScoringEngine,
  DevSecOpsDecisionEngine,
  ReportingEngine
} from './index';

// Initialize engines
const staticAnalysisEngine = new StaticAnalysisEngine();
const cloudExecutionContextEngine = new CloudExecutionContextEngine();
const cloudSecurityPolicyEngine = new CloudSecurityPolicyEngine();
const cloudRiskScoringEngine = new CloudRiskScoringEngine();
const devsecopsDecisionEngine = new DevSecOpsDecisionEngine();
const reportingEngine = new ReportingEngine();

/**
 * Configuration options for cloud security validation
 */
export interface ValidationConfig {
  /** Optional cloud context overrides */
  cloudContext?: {
    privilegeLevel?: 'user' | 'admin' | 'managed_identity';
    environmentType?: 'cloud_vm' | 'ci_cd_pipeline' | 'admin_automation';
  };
  /** Optional list of enabled policy IDs (if not provided, all enabled policies are used) */
  enabledPolicies?: string[];
}

/**
 * Run cloud security validation on a PowerShell script
 * 
 * This is the SINGLE entry point for analysis. All UI should call this function.
 * 
 * @param scriptContent - The PowerShell script content to validate
 * @param filename - Optional filename (defaults to 'script.ps1')
 * @param config - Optional validation configuration (context overrides, enabled policies)
 * @returns Complete analysis result with cloud security validation
 */
export function runCloudSecurityValidation(
  scriptContent: string,
  filename: string = 'script.ps1',
  config?: ValidationConfig
): AnalysisResult {
  // Step 1: Static Analysis
  const staticAnalysisResult = staticAnalysisEngine.analyze(scriptContent);
  const features = staticAnalysisResult.features;
  
  // Step 2: Cloud Execution Context Analysis (with optional overrides)
  const contextOverrides = config?.cloudContext ? {
    privilegeLevel: config.cloudContext.privilegeLevel as any,
    environmentType: config.cloudContext.environmentType as any
  } : undefined;
  const cloudContext = cloudExecutionContextEngine.analyze(scriptContent, features, contextOverrides);
  
  // Step 3: Cloud Security Policy Validation (with optional policy filtering)
  if (config?.enabledPolicies && config.enabledPolicies.length > 0) {
    // Filter policies based on enabled list
    cloudSecurityPolicyEngine.setEnabledPolicies(config.enabledPolicies);
  } else {
    // Reset to all default policies if no config provided or empty array
    try {
      const allPolicies = cloudSecurityPolicyEngine.getAllPolicies();
      cloudSecurityPolicyEngine.loadPolicies(allPolicies);
    } catch (error) {
      console.error('Error loading default policies:', error);
      // Continue with whatever policies are already loaded
    }
  }
  const policyValidation = cloudSecurityPolicyEngine.validate(scriptContent, features, cloudContext);
  
  // Step 4: Cloud Risk Scoring
  const riskScore = cloudRiskScoringEngine.calculateRiskScore(features, cloudContext, policyValidation);
  
  // Step 5: DevSecOps Decision
  const decision = devsecopsDecisionEngine.makeDecision(features, cloudContext, policyValidation, riskScore);
  
  // Determine classification based on static analysis (preserving existing behavior)
  let classification: 'benign' | 'suspicious' | 'malicious';
  let confidence: number;
  
  if (features.obfuscationScore >= 75) {
    classification = 'malicious';
    confidence = Math.min(features.obfuscationScore / 100 * 0.95, 0.95);
  } else if (features.obfuscationScore >= 45) {
    classification = 'suspicious';
    confidence = features.obfuscationScore / 100 * 0.8;
  } else {
    classification = 'benign';
    confidence = (100 - features.obfuscationScore) / 100 * 0.9;
  }
  
  // Build complete analysis result
  const result: AnalysisResult = {
    filename,
    features,
    classification,
    confidence,
    timestamp: new Date(),
    scriptContent,
    threatCategories: staticAnalysisResult.threatCategories,
    riskFactors: staticAnalysisResult.riskFactors,
    recommendations: staticAnalysisResult.recommendations,
    yara: staticAnalysisResult.yara,
    behaviorAnalysis: staticAnalysisResult.behaviorAnalysis,
    timeline: staticAnalysisResult.timeline,
    // Cloud-aware analysis results
    cloudContext,
    policyValidation,
    riskScore,
    decision
  };
  
  return result;
}

/**
 * Generate security report from analysis result
 * 
 * @param analysisResult - Complete analysis result
 * @param reportType - Type of report to generate
 * @returns Security report (JSON or text format)
 */
export function generateSecurityReport(
  analysisResult: AnalysisResult,
  reportType: 'summary' | 'detailed' | 'executive' = 'summary',
  format: 'json' | 'text' = 'json'
): string {
  const report = reportingEngine.generateReport(analysisResult, reportType);
  
  if (format === 'json') {
    return reportingEngine.generateJsonReport(report);
  } else {
    return reportingEngine.generateTextReport(report);
  }
}
