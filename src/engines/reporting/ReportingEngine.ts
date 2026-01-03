/**
 * Reporting & Explainability Engine
 * 
 * Generates explainable security reports from analysis results.
 * This engine aggregates outputs from all analysis engines and creates
 * comprehensive, human-readable reports focused on cloud security.
 * 
 * This engine does NOT:
 * - Execute scripts
 * - Perform detection or scoring
 * - Make decisions
 */

import type { AnalysisResult } from '../../types/analysis';
import type { CloudExecutionContext } from '../cloudExecutionContext/CloudExecutionContextEngine';
import type { PolicyValidationReport } from '../cloudSecurityPolicy/CloudSecurityPolicyEngine';
import type { RiskScore } from '../cloudRiskScoring/CloudRiskScoringEngine';
import type { DevSecOpsDecision } from '../devsecopsDecision/DevSecOpsDecisionEngine';

/**
 * Comprehensive security report
 */
export interface SecurityReport {
  /** Report metadata */
  metadata: ReportMetadata;
  /** Executive summary */
  summary: ReportSummary;
  /** Script metadata summary */
  scriptMetadata: ScriptMetadataSummary;
  /** Cloud execution context summary */
  cloudContext: CloudContextSummary;
  /** Static analysis results */
  staticAnalysis: StaticAnalysisSummary;
  /** Policy validation results */
  policyValidation: PolicyValidationSummary;
  /** Risk assessment results */
  riskAssessment: RiskAssessmentSummary;
  /** DevSecOps decision */
  decision: DecisionSummary;
  /** Security recommendations */
  recommendations: Recommendation[];
}

/**
 * Report metadata
 */
export interface ReportMetadata {
  /** When the report was generated */
  generatedAt: Date;
  /** Report type */
  reportType: 'summary' | 'detailed' | 'executive';
  /** Analysis engine version */
  analysisEngine: string;
  /** Script filename */
  scriptFilename: string;
  /** Script hash (if available) */
  scriptHash?: string;
}

/**
 * Executive summary
 */
export interface ReportSummary {
  /** Overall classification */
  classification: string;
  /** Overall risk score (0-100) */
  overallRiskScore: number;
  /** Risk level category */
  riskLevel: string;
  /** Final DevSecOps decision */
  decision: 'allow' | 'review' | 'block';
  /** Decision confidence (0-1) */
  decisionConfidence: number;
  /** Key findings */
  keyFindings: string[];
}

/**
 * Script metadata summary
 */
export interface ScriptMetadataSummary {
  /** Script filename */
  filename: string;
  /** Script size in characters */
  size: number;
  /** Number of lines */
  lineCount: number;
  /** Average line length */
  averageLineLength: number;
  /** Number of functions */
  functionCount: number;
  /** Comment ratio percentage */
  commentRatio: number;
}

/**
 * Cloud execution context summary
 */
export interface CloudContextSummary {
  /** Execution environment type */
  environmentType: string;
  /** Privilege level */
  privilegeLevel: string;
  /** Network exposure level */
  networkExposure: string;
  /** Cloud platform */
  platform: string;
  /** Cloud services detected */
  cloudServices: string[];
  /** Cloud APIs detected */
  cloudApis: CloudApiSummary[];
  /** Cloud resources detected */
  cloudResources: CloudResourceSummary[];
  /** Context assumptions */
  assumptions: string[];
  /** Context confidence */
  confidence: number;
}

/**
 * Cloud API summary
 */
export interface CloudApiSummary {
  /** Service name */
  service: string;
  /** API name */
  apiName: string;
  /** Operation type */
  operation: string;
}

/**
 * Cloud resource summary
 */
export interface CloudResourceSummary {
  /** Resource type */
  type: string;
  /** Resource identifier (if available) */
  identifier?: string;
}

/**
 * Static analysis summary
 */
export interface StaticAnalysisSummary {
  /** Obfuscation score (0-100) */
  obfuscationScore: number;
  /** Entropy score */
  entropy: number;
  /** Code structure metrics */
  codeStructure: CodeStructureMetrics;
  /** Detected patterns */
  detectedPatterns: DetectedPattern[];
  /** Threat categories */
  threatCategories: string[];
}

/**
 * Code structure metrics
 */
export interface CodeStructureMetrics {
  /** Number of functions */
  functionCount: number;
  /** Maximum nesting depth */
  maxNestingDepth: number;
  /** Comment ratio */
  commentRatio: number;
  /** Variable obfuscation score */
  variableObfuscationScore: number;
}

/**
 * Detected pattern
 */
export interface DetectedPattern {
  /** Pattern name */
  name: string;
  /** Pattern description */
  description: string;
  /** Severity */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Evidence */
  evidence: string[];
}

/**
 * Policy validation summary
 */
export interface PolicyValidationSummary {
  /** Overall compliance score (0-100) */
  complianceScore: number;
  /** Total violations */
  totalViolations: number;
  /** Violations by severity */
  violationsBySeverity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  /** Detailed violations */
  violations: PolicyViolationDetail[];
}

/**
 * Policy violation detail
 */
export interface PolicyViolationDetail {
  /** Policy ID */
  policyId: string;
  /** Policy name */
  policyName: string;
  /** Severity */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Description */
  description: string;
  /** Explanation */
  explanation: string;
  /** Evidence */
  evidence: string;
  /** Line number (if available) */
  lineNumber?: number;
}

/**
 * Risk assessment summary
 */
export interface RiskAssessmentSummary {
  /** Overall risk score (0-100) */
  overallScore: number;
  /** Risk level */
  riskLevel: string;
  /** Confidence in score (0-1) */
  confidence: number;
  /** Component risk scores */
  componentScores: ComponentRiskScores;
  /** Risk breakdown by category */
  riskBreakdown: RiskBreakdownSummary;
  /** Contributing factors */
  contributingFactors: ContributingFactorSummary[];
  /** Explanation */
  explanation: string[];
}

/**
 * Component risk scores
 */
export interface ComponentRiskScores {
  /** Policy violation risk */
  policyViolationRisk: number;
  /** Privilege level risk */
  privilegeLevelRisk: number;
  /** Obfuscation risk */
  obfuscationRisk: number;
  /** Network exposure risk */
  networkExposureRisk: number;
}

/**
 * Risk breakdown summary
 */
export interface RiskBreakdownSummary {
  /** Obfuscation risk */
  obfuscation: number;
  /** Network access risk */
  networkAccess: number;
  /** Resource access risk */
  resourceAccess: number;
  /** Authentication risk */
  authentication: number;
  /** Data exposure risk */
  dataExposure: number;
  /** Compliance risk */
  compliance: number;
}

/**
 * Contributing factor summary
 */
export interface ContributingFactorSummary {
  /** Factor name */
  factor: string;
  /** Contribution to score */
  contribution: number;
  /** Description */
  description: string;
}

/**
 * Decision summary
 */
export interface DecisionSummary {
  /** Final decision */
  decision: 'allow' | 'review' | 'block';
  /** Decision confidence (0-1) */
  confidence: number;
  /** Rationale */
  rationale: string;
  /** Key factors */
  keyFactors: DecisionFactorSummary[];
  /** Required actions */
  requiredActions: RequiredActionSummary[];
}

/**
 * Decision factor summary
 */
export interface DecisionFactorSummary {
  /** Factor name */
  factor: string;
  /** Impact on decision */
  impact: 'positive' | 'negative' | 'neutral';
  /** Description */
  description: string;
  /** Weight */
  weight: number;
}

/**
 * Required action summary
 */
export interface RequiredActionSummary {
  /** Action description */
  action: string;
  /** Priority */
  priority: 'low' | 'medium' | 'high' | 'critical';
  /** Description */
  description: string;
}

/**
 * Security recommendation
 */
export interface Recommendation {
  /** Recommendation text */
  text: string;
  /** Priority */
  priority: 'low' | 'medium' | 'high' | 'critical';
  /** Category */
  category: string;
}

/**
 * Reporting & Explainability Engine
 * 
 * Aggregates outputs from all analysis engines and generates
 * comprehensive, explainable security reports.
 */
export class ReportingEngine {
  /**
   * Generate comprehensive security report
   * 
   * @param analysisResult - Complete analysis result from all engines
   * @param reportType - Type of report to generate
   * @returns Structured security report
   */
  generateReport(
    analysisResult: AnalysisResult,
    reportType: 'summary' | 'detailed' | 'executive' = 'summary'
  ): SecurityReport {
    const cloudContext = analysisResult.cloudContext as CloudExecutionContext | undefined;
    const policyValidation = analysisResult.policyValidation as PolicyValidationReport | undefined;
    const riskScore = analysisResult.riskScore as RiskScore | undefined;
    const decision = analysisResult.decision as DevSecOpsDecision | undefined;

    const report: SecurityReport = {
      metadata: this.generateMetadata(analysisResult, reportType),
      summary: this.generateSummary(analysisResult, riskScore, decision),
      scriptMetadata: this.generateScriptMetadata(analysisResult),
      cloudContext: this.generateCloudContextSummary(cloudContext),
      staticAnalysis: this.generateStaticAnalysisSummary(analysisResult),
      policyValidation: this.generatePolicyValidationSummary(policyValidation),
      riskAssessment: this.generateRiskAssessmentSummary(riskScore),
      decision: this.generateDecisionSummary(decision),
      recommendations: this.generateRecommendations(analysisResult, policyValidation, riskScore, decision)
    };

    return report;
  }

  /**
   * Generate JSON report (machine-readable)
   * 
   * @param report - Security report object
   * @returns JSON string
   */
  generateJsonReport(report: SecurityReport): string {
    try {
      // Convert Date objects to ISO strings for JSON serialization
      const jsonReport = {
        ...report,
        metadata: {
          ...report.metadata,
          generatedAt: report.metadata.generatedAt instanceof Date 
            ? report.metadata.generatedAt.toISOString() 
            : new Date().toISOString()
        }
      };
      
      // Use a replacer function to handle any problematic values
      return JSON.stringify(jsonReport, (key, value) => {
        // Handle undefined values
        if (value === undefined) {
          return null;
        }
        // Handle Date objects
        if (value instanceof Date) {
          return value.toISOString();
        }
        // Handle functions (shouldn't happen, but just in case)
        if (typeof value === 'function') {
          return '[Function]';
        }
        // Handle circular references and other edge cases
        try {
          return value;
        } catch (e) {
          return '[Error serializing value]';
        }
      }, 2);
    } catch (error) {
      console.error('Error generating JSON report:', error);
      // Return a minimal error report
      return JSON.stringify({
        error: 'Failed to generate full report',
        message: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString()
      }, null, 2);
    }
  }

  /**
   * Generate text report (human-readable)
   * 
   * @param report - Security report object
   * @returns Formatted text report
   */
  generateTextReport(report: SecurityReport): string {
    const lines: string[] = [];
    
    // Header
    lines.push('='.repeat(80));
    lines.push('CLOUD-AWARE POWERSHELL SECURITY VALIDATION REPORT');
    lines.push('='.repeat(80));
    lines.push('');
    
    // Metadata
    lines.push('REPORT METADATA');
    lines.push('-'.repeat(80));
    lines.push(`Generated: ${report.metadata.generatedAt.toLocaleString()}`);
    lines.push(`Script: ${report.metadata.scriptFilename}`);
    lines.push(`Report Type: ${report.metadata.reportType.toUpperCase()}`);
    lines.push(`Analysis Engine: ${report.metadata.analysisEngine}`);
    lines.push('');
    
    // Executive Summary
    lines.push('EXECUTIVE SUMMARY');
    lines.push('-'.repeat(80));
    lines.push(`Classification: ${report.summary.classification.toUpperCase()}`);
    lines.push(`Overall Risk Score: ${report.summary.overallRiskScore}/100 (${report.summary.riskLevel.toUpperCase()})`);
    lines.push(`Decision: ${report.summary.decision.toUpperCase()} (Confidence: ${(report.summary.decisionConfidence * 100).toFixed(1)}%)`);
    lines.push('');
    lines.push('Key Findings:');
    report.summary.keyFindings.forEach((finding, idx) => {
      lines.push(`  ${idx + 1}. ${finding}`);
    });
    lines.push('');
    
    // Script Metadata
    lines.push('SCRIPT METADATA');
    lines.push('-'.repeat(80));
    lines.push(`Filename: ${report.scriptMetadata.filename}`);
    lines.push(`Size: ${report.scriptMetadata.size.toLocaleString()} characters`);
    lines.push(`Lines: ${report.scriptMetadata.lineCount}`);
    lines.push(`Average Line Length: ${report.scriptMetadata.averageLineLength.toFixed(1)} characters`);
    lines.push(`Functions: ${report.scriptMetadata.functionCount}`);
    lines.push(`Comment Ratio: ${report.scriptMetadata.commentRatio.toFixed(1)}%`);
    lines.push('');
    
    // Cloud Execution Context
    lines.push('CLOUD EXECUTION CONTEXT');
    lines.push('-'.repeat(80));
    lines.push(`Environment Type: ${report.cloudContext.environmentType}`);
    lines.push(`Privilege Level: ${report.cloudContext.privilegeLevel}`);
    lines.push(`Network Exposure: ${report.cloudContext.networkExposure}`);
    lines.push(`Cloud Platform: ${report.cloudContext.platform.toUpperCase()}`);
    lines.push(`Context Confidence: ${(report.cloudContext.confidence * 100).toFixed(1)}%`);
    lines.push('');
    
    if (report.cloudContext.cloudServices.length > 0) {
      lines.push('Cloud Services:');
      report.cloudContext.cloudServices.forEach(service => {
        lines.push(`  - ${service}`);
      });
      lines.push('');
    }
    
    if (report.cloudContext.cloudApis.length > 0) {
      lines.push('Cloud APIs:');
      report.cloudContext.cloudApis.forEach(api => {
        lines.push(`  - ${api.service}: ${api.apiName} (${api.operation})`);
      });
      lines.push('');
    }
    
    if (report.cloudContext.assumptions.length > 0) {
      lines.push('Context Assumptions:');
      report.cloudContext.assumptions.forEach(assumption => {
        lines.push(`  - ${assumption}`);
      });
      lines.push('');
    }
    
    // Static Analysis
    lines.push('STATIC ANALYSIS RESULTS');
    lines.push('-'.repeat(80));
    lines.push(`Obfuscation Score: ${report.staticAnalysis.obfuscationScore}/100`);
    lines.push(`Entropy: ${report.staticAnalysis.entropy.toFixed(2)}`);
    lines.push(`Functions: ${report.staticAnalysis.codeStructure.functionCount}`);
    lines.push(`Max Nesting Depth: ${report.staticAnalysis.codeStructure.maxNestingDepth}`);
    lines.push(`Variable Obfuscation: ${report.staticAnalysis.codeStructure.variableObfuscationScore.toFixed(1)}%`);
    lines.push('');
    
    if (report.staticAnalysis.detectedPatterns.length > 0) {
      lines.push('Detected Patterns:');
      report.staticAnalysis.detectedPatterns.forEach(pattern => {
        lines.push(`  [${pattern.severity.toUpperCase()}] ${pattern.name}: ${pattern.description}`);
      });
      lines.push('');
    }
    
    if (report.staticAnalysis.threatCategories.length > 0) {
      lines.push('Threat Categories:');
      report.staticAnalysis.threatCategories.forEach(category => {
        lines.push(`  - ${category}`);
      });
      lines.push('');
    }
    
    // Policy Validation
    lines.push('POLICY VALIDATION');
    lines.push('-'.repeat(80));
    lines.push(`Compliance Score: ${report.policyValidation.complianceScore}%`);
    lines.push(`Total Violations: ${report.policyValidation.totalViolations}`);
    lines.push(`  - Critical: ${report.policyValidation.violationsBySeverity.critical}`);
    lines.push(`  - High: ${report.policyValidation.violationsBySeverity.high}`);
    lines.push(`  - Medium: ${report.policyValidation.violationsBySeverity.medium}`);
    lines.push(`  - Low: ${report.policyValidation.violationsBySeverity.low}`);
    lines.push('');
    
    if (report.policyValidation.violations.length > 0) {
      lines.push('Policy Violations:');
      report.policyValidation.violations.forEach((violation, idx) => {
        lines.push(`  ${idx + 1}. [${violation.policyId}] ${violation.policyName} (${violation.severity.toUpperCase()})`);
        lines.push(`     ${violation.description}`);
        lines.push(`     Explanation: ${violation.explanation}`);
        if (violation.lineNumber) {
          lines.push(`     Line: ${violation.lineNumber}`);
        }
        lines.push(`     Evidence: ${violation.evidence}`);
        lines.push('');
      });
    }
    
    // Risk Assessment
    lines.push('RISK ASSESSMENT');
    lines.push('-'.repeat(80));
    lines.push(`Overall Risk Score: ${report.riskAssessment.overallScore}/100`);
    lines.push(`Risk Level: ${report.riskAssessment.riskLevel.toUpperCase()}`);
    lines.push(`Confidence: ${(report.riskAssessment.confidence * 100).toFixed(1)}%`);
    lines.push('');
    lines.push('Component Risk Scores:');
    lines.push(`  - Policy Violation Risk: ${report.riskAssessment.componentScores.policyViolationRisk.toFixed(1)}/100`);
    lines.push(`  - Privilege Level Risk: ${report.riskAssessment.componentScores.privilegeLevelRisk.toFixed(1)}/100`);
    lines.push(`  - Obfuscation Risk: ${report.riskAssessment.componentScores.obfuscationRisk.toFixed(1)}/100`);
    lines.push(`  - Network Exposure Risk: ${report.riskAssessment.componentScores.networkExposureRisk.toFixed(1)}/100`);
    lines.push('');
    lines.push('Risk Breakdown by Category:');
    lines.push(`  - Obfuscation: ${report.riskAssessment.riskBreakdown.obfuscation.toFixed(1)}/100`);
    lines.push(`  - Network Access: ${report.riskAssessment.riskBreakdown.networkAccess.toFixed(1)}/100`);
    lines.push(`  - Resource Access: ${report.riskAssessment.riskBreakdown.resourceAccess.toFixed(1)}/100`);
    lines.push(`  - Authentication: ${report.riskAssessment.riskBreakdown.authentication.toFixed(1)}/100`);
    lines.push(`  - Data Exposure: ${report.riskAssessment.riskBreakdown.dataExposure.toFixed(1)}/100`);
    lines.push(`  - Compliance: ${report.riskAssessment.riskBreakdown.compliance.toFixed(1)}/100`);
    lines.push('');
    
    if (report.riskAssessment.contributingFactors.length > 0) {
      lines.push('Contributing Factors:');
      report.riskAssessment.contributingFactors.forEach(factor => {
        lines.push(`  - ${factor.factor}: ${factor.contribution} points - ${factor.description}`);
      });
      lines.push('');
    }
    
    if (report.riskAssessment.explanation.length > 0) {
      lines.push('Risk Score Explanation:');
      report.riskAssessment.explanation.forEach(explanation => {
        lines.push(`  - ${explanation}`);
      });
      lines.push('');
    }
    
    // DevSecOps Decision
    lines.push('DEVSECOPS DECISION');
    lines.push('-'.repeat(80));
    lines.push(`Decision: ${report.decision.decision.toUpperCase()}`);
    lines.push(`Confidence: ${(report.decision.confidence * 100).toFixed(1)}%`);
    lines.push('');
    lines.push('Rationale:');
    lines.push(`  ${report.decision.rationale}`);
    lines.push('');
    
    if (report.decision.keyFactors.length > 0) {
      lines.push('Key Decision Factors:');
      report.decision.keyFactors.forEach(factor => {
        const impactIcon = factor.impact === 'positive' ? '+' : factor.impact === 'negative' ? '-' : '=';
        lines.push(`  ${impactIcon} ${factor.factor} (Weight: ${factor.weight}): ${factor.description}`);
      });
      lines.push('');
    }
    
    if (report.decision.requiredActions.length > 0) {
      lines.push('Required Actions:');
      report.decision.requiredActions.forEach(action => {
        lines.push(`  [${action.priority.toUpperCase()}] ${action.action}`);
        lines.push(`    ${action.description}`);
      });
      lines.push('');
    }
    
    // Recommendations
    lines.push('SECURITY RECOMMENDATIONS');
    lines.push('-'.repeat(80));
    report.recommendations.forEach((rec, idx) => {
      lines.push(`${idx + 1}. [${rec.priority.toUpperCase()}] ${rec.text}`);
    });
    lines.push('');
    
    // Footer
    lines.push('='.repeat(80));
    lines.push('End of Report');
    lines.push('='.repeat(80));
    
    return lines.join('\n');
  }

  /**
   * Generate report metadata
   */
  private generateMetadata(
    analysisResult: AnalysisResult,
    reportType: 'summary' | 'detailed' | 'executive'
  ): ReportMetadata {
    return {
      generatedAt: new Date(),
      reportType,
      analysisEngine: 'Cloud-Aware Static Security Validation v1.0',
      scriptFilename: analysisResult.filename
    };
  }

  /**
   * Generate executive summary
   */
  private generateSummary(
    analysisResult: AnalysisResult,
    riskScore: RiskScore | undefined,
    decision: DevSecOpsDecision | undefined
  ): ReportSummary {
    const keyFindings: string[] = [];
    
    // Risk score findings
    if (riskScore) {
      if (riskScore.riskLevel === 'critical' || riskScore.riskLevel === 'high') {
        keyFindings.push(`High risk level detected: ${riskScore.riskLevel.toUpperCase()} (Score: ${riskScore.overallScore}/100)`);
      }
    }
    
    // Policy violation findings
    const policyValidation = analysisResult.policyValidation as PolicyValidationReport | undefined;
    if (policyValidation) {
      if (policyValidation.criticalViolations.length > 0) {
        keyFindings.push(`${policyValidation.criticalViolations.length} CRITICAL policy violation(s) detected`);
      }
      if (policyValidation.highViolations.length > 0) {
        keyFindings.push(`${policyValidation.highViolations.length} HIGH severity policy violation(s) detected`);
      }
    }
    
    // Cloud context findings
    const cloudContext = analysisResult.cloudContext as CloudExecutionContext | undefined;
    if (cloudContext) {
      if (cloudContext.privilegeLevel === 'admin') {
        keyFindings.push('Script runs with administrative privileges');
      }
      if (cloudContext.networkExposure === 'internet_facing') {
        keyFindings.push('Script has internet-facing network exposure');
      }
    }
    
    // Static analysis findings
    if (analysisResult.features.obfuscationScore > 50) {
      keyFindings.push(`High obfuscation score: ${analysisResult.features.obfuscationScore}/100`);
    }
    
    if (keyFindings.length === 0) {
      keyFindings.push('No significant security concerns detected');
    }
    
    return {
      classification: analysisResult.classification,
      overallRiskScore: riskScore?.overallScore || 0,
      riskLevel: riskScore?.riskLevel || 'unknown',
      decision: decision?.decision || 'review',
      decisionConfidence: decision?.confidence || 0,
      keyFindings
    };
  }

  /**
   * Generate script metadata summary
   */
  private generateScriptMetadata(analysisResult: AnalysisResult): ScriptMetadataSummary {
    return {
      filename: analysisResult.filename,
      size: analysisResult.features.totalLength,
      lineCount: analysisResult.features.lineCount,
      averageLineLength: analysisResult.features.averageLineLength,
      functionCount: analysisResult.features.functionCount,
      commentRatio: analysisResult.features.commentRatio
    };
  }

  /**
   * Generate cloud context summary
   */
  private generateCloudContextSummary(
    cloudContext: CloudExecutionContext | undefined
  ): CloudContextSummary {
    if (!cloudContext) {
      return {
        environmentType: 'unknown',
        privilegeLevel: 'unknown',
        networkExposure: 'unknown',
        platform: 'unknown',
        cloudServices: [],
        cloudApis: [],
        cloudResources: [],
        assumptions: ['Cloud execution context not available'],
        confidence: 0
      };
    }
    
    return {
      environmentType: cloudContext.environmentType,
      privilegeLevel: cloudContext.privilegeLevel,
      networkExposure: cloudContext.networkExposure,
      platform: cloudContext.platform,
      cloudServices: cloudContext.cloudServices,
      cloudApis: cloudContext.cloudApis.map(api => ({
        service: api.service,
        apiName: api.apiName,
        operation: api.operation
      })),
      cloudResources: cloudContext.cloudResources.map(resource => ({
        type: resource.type,
        identifier: resource.identifier
      })),
      assumptions: cloudContext.metadata.assumptions,
      confidence: cloudContext.metadata.confidence
    };
  }

  /**
   * Generate static analysis summary
   */
  private generateStaticAnalysisSummary(analysisResult: AnalysisResult): StaticAnalysisSummary {
    const detectedPatterns: DetectedPattern[] = [];
    
    // Base64 encoding pattern
    if (analysisResult.features.base64Count > 0) {
      detectedPatterns.push({
        name: 'Base64 Encoding',
        description: `${analysisResult.features.base64Count} Base64 encoded string(s) detected`,
        severity: analysisResult.features.base64Count > 5 ? 'high' : 'medium',
        evidence: analysisResult.features.base64Strings.slice(0, 3).map(s => s.substring(0, 50) + '...')
      });
    }
    
    // Network activity pattern
    if (analysisResult.features.urlCount > 0 || analysisResult.features.ipCount > 0) {
      detectedPatterns.push({
        name: 'Network Activity',
        description: `Network indicators detected: ${analysisResult.features.urlCount} URL(s), ${analysisResult.features.ipCount} IP address(es)`,
        severity: 'medium',
        evidence: [
          ...analysisResult.features.urlsFound.slice(0, 3),
          ...analysisResult.features.ipAddresses.slice(0, 3)
        ]
      });
    }
    
    // Obfuscation pattern
    if (analysisResult.features.obfuscationScore > 50) {
      detectedPatterns.push({
        name: 'Code Obfuscation',
        description: `High obfuscation score: ${analysisResult.features.obfuscationScore}/100`,
        severity: analysisResult.features.obfuscationScore > 70 ? 'high' : 'medium',
        evidence: [
          `Obfuscation score: ${analysisResult.features.obfuscationScore}`,
          `Variable obfuscation: ${analysisResult.features.variableObfuscationScore.toFixed(1)}%`,
          `Encoding methods: ${analysisResult.features.encodingMethodCount}`
        ]
      });
    }
    
    return {
      obfuscationScore: analysisResult.features.obfuscationScore,
      entropy: analysisResult.features.entropy,
      codeStructure: {
        functionCount: analysisResult.features.functionCount,
        maxNestingDepth: analysisResult.features.nestedBlockDepth,
        commentRatio: analysisResult.features.commentRatio,
        variableObfuscationScore: analysisResult.features.variableObfuscationScore
      },
      detectedPatterns,
      threatCategories: analysisResult.threatCategories
    };
  }

  /**
   * Generate policy validation summary
   */
  private generatePolicyValidationSummary(
    policyValidation: PolicyValidationReport | undefined
  ): PolicyValidationSummary {
    if (!policyValidation) {
      return {
        complianceScore: 100,
        totalViolations: 0,
        violationsBySeverity: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0
        },
        violations: []
      };
    }
    
    const violations: PolicyViolationDetail[] = policyValidation.violations.map(violation => ({
      policyId: violation.policyId,
      policyName: violation.description.split(':')[0] || 'Unknown Policy',
      severity: violation.severity,
      description: violation.description,
      explanation: violation.explanation,
      evidence: violation.evidence,
      lineNumber: violation.lineNumber
    }));
    
    return {
      complianceScore: policyValidation.overallCompliance,
      totalViolations: policyValidation.violations.length,
      violationsBySeverity: {
        critical: policyValidation.criticalViolations.length,
        high: policyValidation.highViolations.length,
        medium: policyValidation.mediumViolations.length,
        low: policyValidation.lowViolations.length
      },
      violations
    };
  }

  /**
   * Generate risk assessment summary
   */
  private generateRiskAssessmentSummary(
    riskScore: RiskScore | undefined
  ): RiskAssessmentSummary {
    if (!riskScore) {
      return {
        overallScore: 0,
        riskLevel: 'unknown',
        confidence: 0,
        componentScores: {
          policyViolationRisk: 0,
          privilegeLevelRisk: 0,
          obfuscationRisk: 0,
          networkExposureRisk: 0
        },
        riskBreakdown: {
          obfuscation: 0,
          networkAccess: 0,
          resourceAccess: 0,
          authentication: 0,
          dataExposure: 0,
          compliance: 0
        },
        contributingFactors: [],
        explanation: ['Risk assessment not available']
      };
    }
    
    return {
      overallScore: riskScore.overallScore,
      riskLevel: riskScore.riskLevel,
      confidence: riskScore.confidence,
      componentScores: {
        policyViolationRisk: riskScore.policyViolationRisk,
        privilegeLevelRisk: riskScore.privilegeLevelRisk,
        obfuscationRisk: riskScore.obfuscationRisk,
        networkExposureRisk: riskScore.networkExposureRisk
      },
      riskBreakdown: {
        obfuscation: riskScore.riskBreakdown.obfuscation,
        networkAccess: riskScore.riskBreakdown.networkAccess,
        resourceAccess: riskScore.riskBreakdown.resourceAccess,
        authentication: riskScore.riskBreakdown.authentication,
        dataExposure: riskScore.riskBreakdown.dataExposure,
        compliance: riskScore.riskBreakdown.compliance
      },
      contributingFactors: riskScore.contributingFactors.map(factor => ({
        factor: factor.factor,
        contribution: factor.contribution,
        description: factor.description
      })),
      explanation: riskScore.explanation
    };
  }

  /**
   * Generate decision summary
   */
  private generateDecisionSummary(
    decision: DevSecOpsDecision | undefined
  ): DecisionSummary {
    if (!decision) {
      return {
        decision: 'review',
        confidence: 0,
        rationale: 'Decision not available',
        keyFactors: [],
        requiredActions: []
      };
    }
    
    return {
      decision: decision.decision,
      confidence: decision.confidence,
      rationale: decision.rationale,
      keyFactors: decision.keyFactors.map(factor => ({
        factor: factor.factor,
        impact: factor.impact,
        description: factor.description,
        weight: factor.weight
      })),
      requiredActions: decision.requiredActions.map(action => ({
        action: action.action,
        priority: action.priority,
        description: action.description
      }))
    };
  }

  /**
   * Generate security recommendations
   */
  private generateRecommendations(
    analysisResult: AnalysisResult,
    policyValidation: PolicyValidationReport | undefined,
    riskScore: RiskScore | undefined,
    decision: DevSecOpsDecision | undefined
  ): Recommendation[] {
    const recommendations: Recommendation[] = [];
    
    // Decision-based recommendations
    if (decision) {
      decision.recommendations.forEach(rec => {
        const priority = rec.includes('🚨') || rec.includes('CRITICAL') ? 'critical' :
                        rec.includes('⚠️') || rec.includes('HIGH') ? 'high' :
                        rec.includes('⚠') ? 'medium' : 'low';
        recommendations.push({
          text: rec.replace(/[🚨⚠️✅👀📋🔍🔐🌐📊🔄]/g, '').trim(),
          priority,
          category: 'Decision Guidance'
        });
      });
    }
    
    // Policy violation recommendations
    if (policyValidation && policyValidation.violations.length > 0) {
      if (policyValidation.criticalViolations.length > 0) {
        recommendations.push({
          text: `Resolve ${policyValidation.criticalViolations.length} CRITICAL policy violation(s) before execution`,
          priority: 'critical',
          category: 'Policy Compliance'
        });
      }
      
      if (policyValidation.highViolations.length > 0) {
        recommendations.push({
          text: `Address ${policyValidation.highViolations.length} HIGH severity policy violation(s)`,
          priority: 'high',
          category: 'Policy Compliance'
        });
      }
    }
    
    // Risk-based recommendations
    if (riskScore) {
      if (riskScore.riskLevel === 'critical' || riskScore.riskLevel === 'high') {
        recommendations.push({
          text: `High risk level (${riskScore.riskLevel.toUpperCase()}) - conduct thorough security review`,
          priority: 'high',
          category: 'Risk Management'
        });
      }
      
      if (riskScore.obfuscationRisk > 50) {
        recommendations.push({
          text: 'Reduce code obfuscation for better auditability and security review',
          priority: 'medium',
          category: 'Code Quality'
        });
      }
    }
    
    // Cloud context recommendations
    const cloudContext = analysisResult.cloudContext as CloudExecutionContext | undefined;
    if (cloudContext) {
      if (cloudContext.privilegeLevel === 'admin') {
        recommendations.push({
          text: 'Consider using managed identity or least-privilege access instead of admin privileges',
          priority: 'high',
          category: 'Access Control'
        });
      }
      
      if (cloudContext.networkExposure === 'internet_facing') {
        recommendations.push({
          text: 'Implement network security controls and validate all external connections',
          priority: 'medium',
          category: 'Network Security'
        });
      }
    }
    
    // Static analysis recommendations
    if (analysisResult.features.base64Count > 0) {
      recommendations.push({
        text: 'Review and validate Base64 encoded content to ensure legitimate use',
        priority: 'medium',
        category: 'Code Quality'
      });
    }
    
    // Default recommendation if none generated
    if (recommendations.length === 0) {
      recommendations.push({
        text: 'Script appears compliant with cloud security policies. Continue monitoring in production.',
        priority: 'low',
        category: 'General'
      });
    }
    
    return recommendations;
  }
}
