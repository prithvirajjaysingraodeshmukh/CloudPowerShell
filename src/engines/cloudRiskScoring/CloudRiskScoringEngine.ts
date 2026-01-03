/**
 * Cloud Risk Scoring Engine
 * 
 * Calculates cloud-specific risk scores for PowerShell scripts.
 * This engine combines static analysis features, cloud execution context,
 * and policy violations to produce a comprehensive cloud risk score.
 * 
 * This engine does NOT:
 * - Execute scripts
 * - Make allow/block decisions
 * - Perform policy detection itself
 */

import type { CloudExecutionContext } from '../cloudExecutionContext/CloudExecutionContextEngine';
import { PrivilegeLevel, NetworkExposure } from '../cloudExecutionContext/CloudExecutionContextEngine';
import type { PolicyValidationReport } from '../cloudSecurityPolicy/CloudSecurityPolicyEngine';
import { PolicySeverity } from '../cloudSecurityPolicy/CloudSecurityPolicyEngine';

/**
 * Risk level categories
 */
export enum RiskLevel {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

/**
 * Risk score configuration with weightings
 */
interface RiskScoreWeights {
  /** Weight for policy violation risk (0-1) */
  policyViolationWeight: number;
  /** Weight for privilege level risk (0-1) */
  privilegeLevelWeight: number;
  /** Weight for obfuscation risk (0-1) */
  obfuscationWeight: number;
  /** Weight for network exposure risk (0-1) */
  networkExposureWeight: number;
}

/**
 * Default risk score weightings
 * 
 * These weightings determine how much each factor contributes to the overall risk score.
 * Total should ideally sum to 1.0 for normalized scoring, but can be adjusted for emphasis.
 */
const DEFAULT_WEIGHTS: RiskScoreWeights = {
  policyViolationWeight: 0.40,  // 40% - Policy violations are primary risk indicator
  privilegeLevelWeight: 0.25,   // 25% - Privilege level significantly impacts risk
  obfuscationWeight: 0.20,      // 20% - Obfuscation indicates potential malicious intent
  networkExposureWeight: 0.15   // 15% - Network exposure adds attack surface
};

/**
 * Risk score result
 */
export interface RiskScore {
  /** Overall risk score (0-100, higher = more risk) */
  overallScore: number;
  /** Confidence in the score (0-1) */
  confidence: number;
  /** Risk level category */
  riskLevel: RiskLevel;
  
  // Component scores (0-100 each)
  /** Risk from policy violations */
  policyViolationRisk: number;
  /** Risk from privilege level */
  privilegeLevelRisk: number;
  /** Risk from obfuscation/suspicious indicators */
  obfuscationRisk: number;
  /** Risk from network exposure */
  networkExposureRisk: number;
  
  // Risk breakdown by category
  riskBreakdown: RiskBreakdown;
  
  // Explanation of the score
  explanation: string[];
  
  // Contributing factors
  contributingFactors: ContributingFactor[];
}

/**
 * Risk breakdown by category
 */
export interface RiskBreakdown {
  /** Obfuscation-related risk (0-100) */
  obfuscation: number;
  /** Network access risk (0-100) */
  networkAccess: number;
  /** Resource access risk (0-100) */
  resourceAccess: number;
  /** Authentication risk (0-100) */
  authentication: number;
  /** Data exposure risk (0-100) */
  dataExposure: number;
  /** Compliance risk (0-100) */
  compliance: number;
}

/**
 * Contributing factor to the risk score
 */
export interface ContributingFactor {
  /** Factor name */
  factor: string;
  /** Contribution to overall score (0-100) */
  contribution: number;
  /** Description of the factor */
  description: string;
  /** Evidence supporting this factor */
  evidence: string[];
}

/**
 * Risk factors with detailed information
 */
export interface RiskFactors {
  /** Individual risk factors */
  factors: RiskFactor[];
  /** Total impact score */
  totalImpact: number;
}

/**
 * Individual risk factor
 */
export interface RiskFactor {
  /** Category of the risk factor */
  category: string;
  /** Severity level */
  severity: 'low' | 'medium' | 'high' | 'critical';
  /** Impact score (0-100) */
  impact: number;
  /** Description of the risk factor */
  description: string;
  /** Evidence supporting this risk factor */
  evidence: string[];
}

/**
 * Cloud Risk Scoring Engine
 * 
 * Calculates deterministic, reproducible risk scores for PowerShell scripts
 * based on static analysis, cloud context, and policy violations.
 */
export class CloudRiskScoringEngine {
  private weights: RiskScoreWeights;

  /**
   * Constructor
   * 
   * @param weights - Optional custom weightings (uses defaults if not provided)
   */
  constructor(weights?: Partial<RiskScoreWeights>) {
    this.weights = { ...DEFAULT_WEIGHTS, ...weights };
  }

  /**
   * Calculate comprehensive cloud risk score
   * 
   * @param staticAnalysisFeatures - Features extracted by static analysis
   * @param cloudExecutionContext - Cloud execution context information
   * @param policyValidationReport - Policy validation results
   * @returns Risk score and breakdown
   */
  calculateRiskScore(
    staticAnalysisFeatures: any,
    cloudExecutionContext: CloudExecutionContext,
    policyValidationReport: PolicyValidationReport
  ): RiskScore {
    // Calculate component scores
    const policyViolationRisk = this.calculatePolicyViolationRisk(policyValidationReport);
    const privilegeLevelRisk = this.calculatePrivilegeLevelRisk(cloudExecutionContext);
    const obfuscationRisk = this.calculateObfuscationRisk(staticAnalysisFeatures);
    const networkExposureRisk = this.calculateNetworkExposureRisk(
      cloudExecutionContext,
      staticAnalysisFeatures
    );

    // Calculate weighted overall score
    const overallScore = Math.min(100, Math.round(
      (policyViolationRisk * this.weights.policyViolationWeight) +
      (privilegeLevelRisk * this.weights.privilegeLevelWeight) +
      (obfuscationRisk * this.weights.obfuscationWeight) +
      (networkExposureRisk * this.weights.networkExposureWeight)
    ));

    // Determine risk level
    const riskLevel = this.determineRiskLevel(overallScore);

    // Calculate risk breakdown by category
    const riskBreakdown = this.calculateRiskBreakdown(
      staticAnalysisFeatures,
      cloudExecutionContext,
      policyValidationReport
    );

    // Generate explanation
    const explanation = this.generateExplanation(
      overallScore,
      riskLevel,
      policyViolationRisk,
      privilegeLevelRisk,
      obfuscationRisk,
      networkExposureRisk,
      policyValidationReport,
      cloudExecutionContext
    );

    // Identify contributing factors
    const contributingFactors = this.identifyContributingFactors(
      policyViolationRisk,
      privilegeLevelRisk,
      obfuscationRisk,
      networkExposureRisk,
      policyValidationReport,
      cloudExecutionContext,
      staticAnalysisFeatures
    );

    // Calculate confidence based on data quality
    const confidence = this.calculateConfidence(
      staticAnalysisFeatures,
      cloudExecutionContext,
      policyValidationReport
    );

    return {
      overallScore,
      confidence,
      riskLevel,
      policyViolationRisk,
      privilegeLevelRisk,
      obfuscationRisk,
      networkExposureRisk,
      riskBreakdown,
      explanation,
      contributingFactors
    };
  }

  /**
   * Calculate risk from policy violations
   */
  private calculatePolicyViolationRisk(report: PolicyValidationReport): number {
    if (report.violations.length === 0) {
      return 0;
    }

    // Calculate weighted violation score
    let violationScore = 0;
    let totalWeight = 0;

    // Severity weights
    const severityWeights = {
      [PolicySeverity.CRITICAL]: 100,
      [PolicySeverity.HIGH]: 70,
      [PolicySeverity.MEDIUM]: 40,
      [PolicySeverity.LOW]: 15
    };

    // Count violations by severity
    const criticalCount = report.criticalViolations.length;
    const highCount = report.highViolations.length;
    const mediumCount = report.mediumViolations.length;
    const lowCount = report.lowViolations.length;

    // Calculate weighted average
    violationScore = (
      (criticalCount * severityWeights[PolicySeverity.CRITICAL]) +
      (highCount * severityWeights[PolicySeverity.HIGH]) +
      (mediumCount * severityWeights[PolicySeverity.MEDIUM]) +
      (lowCount * severityWeights[PolicySeverity.LOW])
    );

    // Normalize based on total violations (cap at 100)
    // Multiple violations increase risk, but with diminishing returns
    const totalViolations = report.violations.length;
    const normalizedScore = Math.min(100, violationScore / Math.max(1, totalViolations * 0.5));

    // Apply compliance penalty
    const compliancePenalty = (100 - report.overallCompliance) * 0.5;
    return Math.min(100, normalizedScore + compliancePenalty);
  }

  /**
   * Calculate risk from privilege level
   */
  private calculatePrivilegeLevelRisk(context: CloudExecutionContext): number {
    const privilegeRiskScores = {
      [PrivilegeLevel.USER]: 10,
      [PrivilegeLevel.MANAGED_IDENTITY]: 30,  // Managed identity is safer but still elevated
      [PrivilegeLevel.ADMIN]: 80
    };

    let baseRisk = privilegeRiskScores[context.privilegeLevel] || 50;

    // Adjust based on environment type
    // Admin automation with admin privileges is higher risk
    if (context.environmentType === 'admin_automation' && 
        context.privilegeLevel === PrivilegeLevel.ADMIN) {
      baseRisk = Math.min(100, baseRisk + 15);
    }

    return baseRisk;
  }

  /**
   * Calculate risk from obfuscation and suspicious indicators
   */
  private calculateObfuscationRisk(features: any): number {
    if (!features) {
      return 0;
    }

    let risk = 0;

    // Obfuscation score (0-100) contributes directly
    const obfuscationScore = features.obfuscationScore || 0;
    risk += obfuscationScore * 0.6; // 60% weight

    // Base64 encoding increases risk
    if (features.base64Count > 0) {
      risk += Math.min(30, features.base64Count * 5);
    }

    // Suspicious keywords increase risk
    if (features.suspiciousKeywordCount > 0) {
      risk += Math.min(20, features.suspiciousKeywordCount * 2);
    }

    // High entropy indicates obfuscation
    if (features.entropy > 6) {
      risk += 15;
    } else if (features.entropy > 5) {
      risk += 10;
    }

    // Variable obfuscation
    if (features.variableObfuscationScore > 50) {
      risk += 10;
    }

    return Math.min(100, risk);
  }

  /**
   * Calculate risk from network exposure
   */
  private calculateNetworkExposureRisk(
    context: CloudExecutionContext,
    features: any
  ): number {
    let risk = 0;

    // Base risk from network exposure level
    if (context.networkExposure === NetworkExposure.INTERNET_FACING) {
      risk = 40; // Base risk for internet exposure
    } else {
      risk = 10; // Lower risk for internal-only
    }

    // Increase risk based on network activity indicators
    if (features) {
      if (features.urlCount > 0) {
        risk += Math.min(30, features.urlCount * 5);
      }

      if (features.ipCount > 0) {
        risk += Math.min(20, features.ipCount * 4);
      }
    }

    // Higher risk if internet-facing with network activity
    if (context.networkExposure === NetworkExposure.INTERNET_FACING && 
        features?.urlCount > 0) {
      risk += 10;
    }

    return Math.min(100, risk);
  }

  /**
   * Determine risk level category from score
   */
  private determineRiskLevel(score: number): RiskLevel {
    if (score >= 75) {
      return RiskLevel.CRITICAL;
    } else if (score >= 50) {
      return RiskLevel.HIGH;
    } else if (score >= 25) {
      return RiskLevel.MEDIUM;
    } else {
      return RiskLevel.LOW;
    }
  }

  /**
   * Calculate risk breakdown by category
   */
  private calculateRiskBreakdown(
    features: any,
    context: CloudExecutionContext,
    report: PolicyValidationReport
  ): RiskBreakdown {
    // Obfuscation risk
    const obfuscation = this.calculateObfuscationRisk(features);

    // Network access risk
    const networkAccess = this.calculateNetworkExposureRisk(context, features);

    // Resource access risk (based on privilege level and cloud resources)
    let resourceAccess = 0;
    if (context.privilegeLevel === PrivilegeLevel.ADMIN) {
      resourceAccess = 70;
    } else if (context.privilegeLevel === PrivilegeLevel.MANAGED_IDENTITY) {
      resourceAccess = 40;
    } else {
      resourceAccess = 20;
    }
    if (context.cloudResources.length > 0) {
      resourceAccess = Math.min(100, resourceAccess + (context.cloudResources.length * 5));
    }

    // Authentication risk (from policy violations related to auth)
    const authViolations = report.violations.filter(v => 
      v.policyId === 'POL-003' || v.policyId === 'POL-007'
    );
    const authentication = authViolations.length > 0 ? 80 : 20;

    // Data exposure risk (from policy violations and network exposure)
    const dataExposureViolations = report.violations.filter(v => 
      v.policyId === 'POL-003' || v.policyId === 'POL-007'
    );
    let dataExposure = dataExposureViolations.length * 30;
    if (context.networkExposure === NetworkExposure.INTERNET_FACING) {
      dataExposure = Math.min(100, dataExposure + 20);
    }

    // Compliance risk (inverse of compliance score)
    const compliance = 100 - report.overallCompliance;

    return {
      obfuscation,
      networkAccess,
      resourceAccess,
      authentication,
      dataExposure,
      compliance
    };
  }

  /**
   * Generate explanation of the risk score
   */
  private generateExplanation(
    overallScore: number,
    riskLevel: RiskLevel,
    policyRisk: number,
    privilegeRisk: number,
    obfuscationRisk: number,
    networkRisk: number,
    report: PolicyValidationReport,
    context: CloudExecutionContext
  ): string[] {
    const explanation: string[] = [];

    explanation.push(`Overall Risk Score: ${overallScore}/100 (${riskLevel.toUpperCase()})`);

    // Policy violations
    if (report.violations.length > 0) {
      explanation.push(
        `Policy Violations: ${report.violations.length} violation(s) detected ` +
        `(${report.criticalViolations.length} critical, ${report.highViolations.length} high, ` +
        `${report.mediumViolations.length} medium, ${report.lowViolations.length} low)`
      );
      explanation.push(`Policy Violation Risk: ${policyRisk.toFixed(1)}/100`);
    } else {
      explanation.push('Policy Violations: No violations detected');
    }

    // Privilege level
    explanation.push(
      `Privilege Level: ${context.privilegeLevel} (Risk: ${privilegeRisk.toFixed(1)}/100)`
    );

    // Obfuscation
    if (obfuscationRisk > 30) {
      explanation.push(
        `Obfuscation: High obfuscation indicators detected (Risk: ${obfuscationRisk.toFixed(1)}/100)`
      );
    } else {
      explanation.push(`Obfuscation: Low obfuscation risk (Risk: ${obfuscationRisk.toFixed(1)}/100)`);
    }

    // Network exposure
    explanation.push(
      `Network Exposure: ${context.networkExposure} (Risk: ${networkRisk.toFixed(1)}/100)`
    );

    // Contributing factors
    const topContributor = Math.max(policyRisk, privilegeRisk, obfuscationRisk, networkRisk);
    if (topContributor === policyRisk && report.violations.length > 0) {
      explanation.push('Primary Risk Factor: Policy violations');
    } else if (topContributor === privilegeRisk) {
      explanation.push('Primary Risk Factor: Elevated privilege level');
    } else if (topContributor === obfuscationRisk) {
      explanation.push('Primary Risk Factor: Code obfuscation');
    } else if (topContributor === networkRisk) {
      explanation.push('Primary Risk Factor: Network exposure');
    }

    return explanation;
  }

  /**
   * Identify contributing factors to the risk score
   */
  private identifyContributingFactors(
    policyRisk: number,
    privilegeRisk: number,
    obfuscationRisk: number,
    networkRisk: number,
    report: PolicyValidationReport,
    context: CloudExecutionContext,
    features: any
  ): ContributingFactor[] {
    const factors: ContributingFactor[] = [];

    // Policy violation factor
    if (report.violations.length > 0) {
      const contribution = policyRisk * this.weights.policyViolationWeight;
      factors.push({
        factor: 'Policy Violations',
        contribution: Math.round(contribution),
        description: `${report.violations.length} policy violation(s) detected`,
        evidence: [
          `${report.criticalViolations.length} critical violation(s)`,
          `${report.highViolations.length} high severity violation(s)`,
          `Compliance score: ${report.overallCompliance}%`
        ]
      });
    }

    // Privilege level factor
    const privilegeContribution = privilegeRisk * this.weights.privilegeLevelWeight;
    factors.push({
      factor: 'Privilege Level',
      contribution: Math.round(privilegeContribution),
      description: `Script runs with ${context.privilegeLevel} privileges`,
      evidence: [
        `Privilege level: ${context.privilegeLevel}`,
        `Environment: ${context.environmentType}`
      ]
    });

    // Obfuscation factor
    if (obfuscationRisk > 20) {
      const obfuscationContribution = obfuscationRisk * this.weights.obfuscationWeight;
      factors.push({
        factor: 'Code Obfuscation',
        contribution: Math.round(obfuscationContribution),
        description: 'Obfuscation and suspicious indicators detected',
        evidence: [
          `Obfuscation score: ${features?.obfuscationScore || 0}/100`,
          `Base64 strings: ${features?.base64Count || 0}`,
          `Suspicious keywords: ${features?.suspiciousKeywordCount || 0}`
        ]
      });
    }

    // Network exposure factor
    if (networkRisk > 20) {
      const networkContribution = networkRisk * this.weights.networkExposureWeight;
      factors.push({
        factor: 'Network Exposure',
        contribution: Math.round(networkContribution),
        description: `Network exposure: ${context.networkExposure}`,
        evidence: [
          `Network exposure: ${context.networkExposure}`,
          `URLs detected: ${features?.urlCount || 0}`,
          `IP addresses detected: ${features?.ipCount || 0}`
        ]
      });
    }

    return factors;
  }

  /**
   * Calculate confidence in the risk score
   */
  private calculateConfidence(
    features: any,
    context: CloudExecutionContext,
    report: PolicyValidationReport
  ): number {
    let confidence = 0.5; // Base confidence

    // Higher confidence if we have good static analysis data
    if (features && features.totalLength > 100) {
      confidence += 0.2;
    }

    // Higher confidence if cloud context is well-defined
    if (context.platform !== 'unknown') {
      confidence += 0.15;
    }

    // Higher confidence if we have policy evaluation results
    if (report.validationResults.length > 0) {
      confidence += 0.15;
    }

    return Math.min(1.0, confidence);
  }

  /**
   * Identify specific risk factors
   * 
   * @param staticAnalysisFeatures - Features extracted by static analysis
   * @param cloudExecutionContext - Cloud execution context information
   * @param policyValidationReport - Policy validation results
   * @returns Detailed risk factors
   */
  identifyRiskFactors(
    staticAnalysisFeatures: any,
    cloudExecutionContext: CloudExecutionContext,
    policyValidationReport: PolicyValidationReport
  ): RiskFactors {
    const factors: RiskFactor[] = [];

    // Policy violation factors
    if (policyValidationReport.criticalViolations.length > 0) {
      factors.push({
        category: 'Policy Compliance',
        severity: 'critical',
        impact: 90,
        description: `${policyValidationReport.criticalViolations.length} critical policy violation(s)`,
        evidence: policyValidationReport.criticalViolations.map(v => v.description)
      });
    }

    if (policyValidationReport.highViolations.length > 0) {
      factors.push({
        category: 'Policy Compliance',
        severity: 'high',
        impact: 70,
        description: `${policyValidationReport.highViolations.length} high severity policy violation(s)`,
        evidence: policyValidationReport.highViolations.map(v => v.description)
      });
    }

    // Privilege level factor
    if (cloudExecutionContext.privilegeLevel === PrivilegeLevel.ADMIN) {
      factors.push({
        category: 'Authorization',
        severity: 'high',
        impact: 80,
        description: 'Script runs with administrative privileges',
        evidence: [`Privilege level: ${cloudExecutionContext.privilegeLevel}`]
      });
    }

    // Obfuscation factor
    if (staticAnalysisFeatures?.obfuscationScore > 50) {
      factors.push({
        category: 'Code Quality',
        severity: 'medium',
        impact: staticAnalysisFeatures.obfuscationScore,
        description: 'High obfuscation score detected',
        evidence: [
          `Obfuscation score: ${staticAnalysisFeatures.obfuscationScore}/100`,
          `Base64 strings: ${staticAnalysisFeatures.base64Count || 0}`
        ]
      });
    }

    // Network exposure factor
    if (cloudExecutionContext.networkExposure === NetworkExposure.INTERNET_FACING) {
      factors.push({
        category: 'Network Security',
        severity: 'medium',
        impact: 50,
        description: 'Script has internet-facing network exposure',
        evidence: [
          `Network exposure: ${cloudExecutionContext.networkExposure}`,
          `URLs: ${staticAnalysisFeatures?.urlCount || 0}`
        ]
      });
    }

    // Calculate total impact
    const totalImpact = factors.reduce((sum, factor) => sum + factor.impact, 0) / Math.max(1, factors.length);

    return {
      factors,
      totalImpact: Math.min(100, totalImpact)
    };
  }

  /**
   * Update risk score weightings
   * 
   * @param weights - Partial weightings to update
   */
  updateWeights(weights: Partial<RiskScoreWeights>): void {
    this.weights = { ...this.weights, ...weights };
  }

  /**
   * Get current weightings
   * 
   * @returns Current risk score weightings
   */
  getWeights(): RiskScoreWeights {
    return { ...this.weights };
  }
}
