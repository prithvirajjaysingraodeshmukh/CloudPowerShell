/**
 * DevSecOps Decision Engine
 * 
 * Makes allow/review/block decisions based on comprehensive analysis.
 * This engine combines risk scoring, policy validation, and cloud execution context
 * to provide actionable DevSecOps decisions.
 * 
 * This engine does NOT:
 * - Execute scripts
 * - Perform analysis or scoring
 * - Modify policies
 */

import type { CloudExecutionContext } from '../cloudExecutionContext/CloudExecutionContextEngine';
import { PrivilegeLevel, ExecutionEnvironmentType } from '../cloudExecutionContext/CloudExecutionContextEngine';
import type { PolicyValidationReport, PolicyViolation } from '../cloudSecurityPolicy/CloudSecurityPolicyEngine';
import { PolicySeverity } from '../cloudSecurityPolicy/CloudSecurityPolicyEngine';
import type { RiskScore } from '../cloudRiskScoring/CloudRiskScoringEngine';
import { RiskLevel } from '../cloudRiskScoring/CloudRiskScoringEngine';

/**
 * Decision outcomes
 */
export enum Decision {
  /** Script is safe to execute */
  ALLOW = 'allow',
  /** Script requires manual review before execution */
  REVIEW = 'review',
  /** Script should be blocked from execution */
  BLOCK = 'block'
}

/**
 * Decision thresholds configuration
 */
interface DecisionThresholds {
  /** Maximum risk score for ALLOW decision */
  allowMaxRiskScore: number;
  /** Maximum risk score for REVIEW decision */
  reviewMaxRiskScore: number;
  /** Risk score threshold for BLOCK decision */
  blockMinRiskScore: number;
  /** Allow critical policy violations (false = block on critical) */
  allowCriticalViolations: boolean;
  /** Allow high severity violations in ALLOW decision */
  allowHighViolations: boolean;
}

/**
 * Default decision thresholds
 */
const DEFAULT_THRESHOLDS: DecisionThresholds = {
  allowMaxRiskScore: 30,
  reviewMaxRiskScore: 70,
  blockMinRiskScore: 75,
  allowCriticalViolations: false,
  allowHighViolations: false
};

/**
 * DevSecOps decision result
 */
export interface DevSecOpsDecision {
  /** Final decision outcome */
  decision: Decision;
  /** Confidence in the decision (0-1) */
  confidence: number;
  
  /** Decision rationale explaining why this decision was made */
  rationale: string;
  /** Key factors that influenced the decision */
  keyFactors: DecisionFactor[];
  
  /** Recommendations for next steps */
  recommendations: string[];
  /** Required actions based on the decision */
  requiredActions: RequiredAction[];
  
  /** References to contributing risk factors */
  riskFactorReferences: string[];
  /** References to violated policies */
  policyReferences: string[];
}

/**
 * Decision factor that influenced the decision
 */
export interface DecisionFactor {
  /** Factor name */
  factor: string;
  /** Impact on decision (positive = favors allow, negative = favors block) */
  impact: 'positive' | 'negative' | 'neutral';
  /** Description of the factor */
  description: string;
  /** Weight/importance of this factor */
  weight: number;
}

/**
 * Required action based on the decision
 */
export interface RequiredAction {
  /** Action description */
  action: string;
  /** Priority level */
  priority: 'low' | 'medium' | 'high' | 'critical';
  /** Detailed description */
  description: string;
}

/**
 * DevSecOps Decision Engine
 * 
 * Makes deterministic, explainable decisions based on risk scores,
 * policy violations, and cloud execution context.
 */
export class DevSecOpsDecisionEngine {
  private thresholds: DecisionThresholds;

  /**
   * Constructor
   * 
   * @param thresholds - Optional custom decision thresholds (uses defaults if not provided)
   */
  constructor(thresholds?: Partial<DecisionThresholds>) {
    this.thresholds = { ...DEFAULT_THRESHOLDS, ...thresholds };
  }

  /**
   * Make DevSecOps decision based on comprehensive analysis
   * 
   * @param staticAnalysisFeatures - Features extracted by static analysis (for context)
   * @param cloudExecutionContext - Cloud execution context information
   * @param policyValidationReport - Policy validation results
   * @param riskScore - Risk scoring results
   * @returns DevSecOps decision with rationale
   */
  makeDecision(
    staticAnalysisFeatures: any,
    cloudExecutionContext: CloudExecutionContext,
    policyValidationReport: PolicyValidationReport,
    riskScore: RiskScore
  ): DevSecOpsDecision {
    // Determine decision based on deterministic rules
    const decision = this.determineDecision(riskScore, policyValidationReport, cloudExecutionContext);
    
    // Calculate confidence
    const confidence = this.calculateConfidence(riskScore, policyValidationReport);
    
    // Generate rationale
    const rationale = this.generateRationale(
      decision,
      riskScore,
      policyValidationReport,
      cloudExecutionContext
    );
    
    // Identify key factors
    const keyFactors = this.identifyKeyFactors(
      riskScore,
      policyValidationReport,
      cloudExecutionContext
    );
    
    // Generate recommendations
    const recommendations = this.generateRecommendations(
      decision,
      riskScore,
      policyValidationReport,
      cloudExecutionContext
    );
    
    // Generate required actions
    const requiredActions = this.generateRequiredActions(
      decision,
      riskScore,
      policyValidationReport,
      cloudExecutionContext
    );
    
    // Collect references
    const riskFactorReferences = this.collectRiskFactorReferences(riskScore);
    const policyReferences = this.collectPolicyReferences(policyValidationReport);
    
    return {
      decision,
      confidence,
      rationale,
      keyFactors,
      recommendations,
      requiredActions,
      riskFactorReferences,
      policyReferences
    };
  }

  /**
   * Determine decision based on deterministic rules
   * 
   * Rules (in priority order):
   * 1. CRITICAL risk level → BLOCK
   * 2. CRITICAL policy violation → BLOCK (unless allowCriticalViolations is true)
   * 3. Risk score ≥ blockMinRiskScore → BLOCK
   * 4. HIGH risk level → REVIEW
   * 5. Risk score > reviewMaxRiskScore → REVIEW
   * 6. HIGH severity policy violations → REVIEW (unless allowHighViolations is true)
   * 7. Risk score ≤ allowMaxRiskScore with no critical/high violations → ALLOW
   * 8. Default → REVIEW
   */
  private determineDecision(
    riskScore: RiskScore,
    policyReport: PolicyValidationReport,
    context: CloudExecutionContext
  ): Decision {
    // Rule 1: CRITICAL risk level → BLOCK
    if (riskScore.riskLevel === RiskLevel.CRITICAL) {
      return Decision.BLOCK;
    }
    
    // Rule 2: CRITICAL policy violation → BLOCK (unless explicitly allowed)
    if (policyReport.criticalViolations.length > 0 && !this.thresholds.allowCriticalViolations) {
      return Decision.BLOCK;
    }
    
    // Rule 3: Risk score ≥ blockMinRiskScore → BLOCK
    if (riskScore.overallScore >= this.thresholds.blockMinRiskScore) {
      return Decision.BLOCK;
    }
    
    // Rule 4: HIGH risk level → REVIEW
    if (riskScore.riskLevel === RiskLevel.HIGH) {
      return Decision.REVIEW;
    }
    
    // Rule 5: Risk score > reviewMaxRiskScore → REVIEW
    if (riskScore.overallScore > this.thresholds.reviewMaxRiskScore) {
      return Decision.REVIEW;
    }
    
    // Rule 6: HIGH severity policy violations → REVIEW (unless explicitly allowed)
    if (policyReport.highViolations.length > 0 && !this.thresholds.allowHighViolations) {
      return Decision.REVIEW;
    }
    
    // Rule 7: Risk score ≤ allowMaxRiskScore with no critical/high violations → ALLOW
    if (riskScore.overallScore <= this.thresholds.allowMaxRiskScore) {
      const hasCriticalOrHighViolations = 
        policyReport.criticalViolations.length > 0 || 
        policyReport.highViolations.length > 0;
      
      if (!hasCriticalOrHighViolations) {
        return Decision.ALLOW;
      }
    }
    
    // Rule 8: Default → REVIEW (conservative approach)
    return Decision.REVIEW;
  }

  /**
   * Calculate confidence in the decision
   */
  private calculateConfidence(
    riskScore: RiskScore,
    policyReport: PolicyValidationReport
  ): number {
    // Base confidence from risk score confidence
    let confidence = riskScore.confidence || 0.5;
    
    // Higher confidence if we have clear policy violations
    if (policyReport.violations.length > 0) {
      confidence = Math.min(1.0, confidence + 0.2);
    }
    
    // Higher confidence if risk level is clear (CRITICAL or LOW)
    if (riskScore.riskLevel === RiskLevel.CRITICAL || riskScore.riskLevel === RiskLevel.LOW) {
      confidence = Math.min(1.0, confidence + 0.15);
    }
    
    // Lower confidence if risk score is near threshold boundaries
    const distanceFromThreshold = Math.min(
      Math.abs(riskScore.overallScore - this.thresholds.allowMaxRiskScore),
      Math.abs(riskScore.overallScore - this.thresholds.reviewMaxRiskScore),
      Math.abs(riskScore.overallScore - this.thresholds.blockMinRiskScore)
    );
    
    if (distanceFromThreshold < 5) {
      confidence = Math.max(0.5, confidence - 0.1);
    }
    
    return Math.min(1.0, Math.max(0.0, confidence));
  }

  /**
   * Generate decision rationale
   */
  private generateRationale(
    decision: Decision,
    riskScore: RiskScore,
    policyReport: PolicyValidationReport,
    context: CloudExecutionContext
  ): string {
    const parts: string[] = [];
    
    parts.push(`Decision: ${decision.toUpperCase()}`);
    parts.push(`Risk Score: ${riskScore.overallScore}/100 (${riskScore.riskLevel.toUpperCase()})`);
    
    // Policy violations summary
    if (policyReport.violations.length > 0) {
      parts.push(
        `Policy Violations: ${policyReport.violations.length} total ` +
        `(${policyReport.criticalViolations.length} critical, ` +
        `${policyReport.highViolations.length} high, ` +
        `${policyReport.mediumViolations.length} medium, ` +
        `${policyReport.lowViolations.length} low)`
      );
    } else {
      parts.push('Policy Violations: None detected');
    }
    
    // Decision reason
    if (decision === Decision.BLOCK) {
      if (riskScore.riskLevel === RiskLevel.CRITICAL) {
        parts.push('Reason: CRITICAL risk level detected');
      } else if (policyReport.criticalViolations.length > 0) {
        parts.push(`Reason: ${policyReport.criticalViolations.length} CRITICAL policy violation(s) detected`);
      } else if (riskScore.overallScore >= this.thresholds.blockMinRiskScore) {
        parts.push(`Reason: Risk score (${riskScore.overallScore}) exceeds block threshold (${this.thresholds.blockMinRiskScore})`);
      }
    } else if (decision === Decision.REVIEW) {
      if (riskScore.riskLevel === RiskLevel.HIGH) {
        parts.push('Reason: HIGH risk level requires manual review');
      } else if (policyReport.highViolations.length > 0) {
        parts.push(`Reason: ${policyReport.highViolations.length} HIGH severity policy violation(s) require review`);
      } else if (riskScore.overallScore > this.thresholds.reviewMaxRiskScore) {
        parts.push(`Reason: Risk score (${riskScore.overallScore}) exceeds review threshold (${this.thresholds.reviewMaxRiskScore})`);
      } else {
        parts.push('Reason: Risk assessment indicates manual review is recommended');
      }
    } else { // ALLOW
      parts.push('Reason: Risk score and policy violations are within acceptable thresholds');
      if (riskScore.overallScore <= this.thresholds.allowMaxRiskScore) {
        parts.push(`Risk score (${riskScore.overallScore}) is within allow threshold (${this.thresholds.allowMaxRiskScore})`);
      }
    }
    
    // Context information
    parts.push(`Execution Context: ${context.environmentType} with ${context.privilegeLevel} privileges`);
    
    return parts.join('. ');
  }

  /**
   * Identify key factors that influenced the decision
   */
  private identifyKeyFactors(
    riskScore: RiskScore,
    policyReport: PolicyValidationReport,
    context: CloudExecutionContext
  ): DecisionFactor[] {
    const factors: DecisionFactor[] = [];
    
    // Risk level factor
    const riskLevelImpact = riskScore.riskLevel === RiskLevel.CRITICAL || riskScore.riskLevel === RiskLevel.HIGH
      ? 'negative'
      : riskScore.riskLevel === RiskLevel.LOW
      ? 'positive'
      : 'neutral';
    
    factors.push({
      factor: 'Risk Level',
      impact: riskLevelImpact,
      description: `Overall risk level: ${riskScore.riskLevel.toUpperCase()} (Score: ${riskScore.overallScore}/100)`,
      weight: 0.4
    });
    
    // Policy violations factor
    if (policyReport.criticalViolations.length > 0) {
      factors.push({
        factor: 'Critical Policy Violations',
        impact: 'negative',
        description: `${policyReport.criticalViolations.length} CRITICAL policy violation(s) detected`,
        weight: 0.35
      });
    } else if (policyReport.highViolations.length > 0) {
      factors.push({
        factor: 'High Policy Violations',
        impact: 'negative',
        description: `${policyReport.highViolations.length} HIGH severity policy violation(s) detected`,
        weight: 0.25
      });
    } else if (policyReport.violations.length === 0) {
      factors.push({
        factor: 'Policy Compliance',
        impact: 'positive',
        description: 'No policy violations detected',
        weight: 0.2
      });
    }
    
    // Privilege level factor
    const privilegeImpact = context.privilegeLevel === PrivilegeLevel.ADMIN
      ? 'negative'
      : context.privilegeLevel === PrivilegeLevel.USER
      ? 'positive'
      : 'neutral';
    
    factors.push({
      factor: 'Privilege Level',
      impact: privilegeImpact,
      description: `Script runs with ${context.privilegeLevel} privileges`,
      weight: 0.15
    });
    
    // Obfuscation factor
    if (riskScore.obfuscationRisk > 50) {
      factors.push({
        factor: 'Code Obfuscation',
        impact: 'negative',
        description: `High obfuscation risk: ${riskScore.obfuscationRisk.toFixed(1)}/100`,
        weight: 0.1
      });
    }
    
    return factors;
  }

  /**
   * Generate recommendations based on decision
   */
  private generateRecommendations(
    decision: Decision,
    riskScore: RiskScore,
    policyReport: PolicyValidationReport,
    context: CloudExecutionContext
  ): string[] {
    const recommendations: string[] = [];
    
    if (decision === Decision.BLOCK) {
      recommendations.push('🚫 Script execution is BLOCKED due to security concerns');
      
      if (riskScore.riskLevel === RiskLevel.CRITICAL) {
        recommendations.push('⚠️ CRITICAL risk level detected - immediate security review required');
      }
      
      if (policyReport.criticalViolations.length > 0) {
        recommendations.push(
          `🔴 ${policyReport.criticalViolations.length} CRITICAL policy violation(s) must be resolved before execution`
        );
      }
      
      recommendations.push('📋 Review all policy violations and risk factors before considering execution');
      recommendations.push('🔍 Consider manual code review or security team consultation');
      
    } else if (decision === Decision.REVIEW) {
      recommendations.push('👀 Script requires MANUAL REVIEW before execution');
      
      if (riskScore.riskLevel === RiskLevel.HIGH) {
        recommendations.push('⚠️ HIGH risk level - thorough review recommended');
      }
      
      if (policyReport.highViolations.length > 0) {
        recommendations.push(
          `⚠️ ${policyReport.highViolations.length} HIGH severity policy violation(s) should be addressed`
        );
      }
      
      recommendations.push('📊 Review risk score breakdown and contributing factors');
      recommendations.push('✅ Verify script legitimacy and intended functionality');
      recommendations.push('🔒 Consider additional security controls if execution is necessary');
      
    } else { // ALLOW
      recommendations.push('✅ Script appears safe for execution based on current analysis');
      recommendations.push('📝 Monitor execution in production environments');
      recommendations.push('🔄 Re-evaluate if script behavior changes or new risks are identified');
    }
    
    // Context-specific recommendations
    if (context.privilegeLevel === PrivilegeLevel.ADMIN) {
      recommendations.push('🔐 Script runs with admin privileges - ensure proper authorization');
    }
    
    if (context.networkExposure === 'internet_facing') {
      recommendations.push('🌐 Script has internet exposure - monitor network activity');
    }
    
    return recommendations;
  }

  /**
   * Generate required actions based on decision
   */
  private generateRequiredActions(
    decision: Decision,
    riskScore: RiskScore,
    policyReport: PolicyValidationReport,
    context: CloudExecutionContext
  ): RequiredAction[] {
    const actions: RequiredAction[] = [];
    
    if (decision === Decision.BLOCK) {
      actions.push({
        action: 'Block Script Execution',
        priority: 'critical',
        description: 'Prevent script from executing due to security concerns'
      });
      
      if (policyReport.criticalViolations.length > 0) {
        actions.push({
          action: 'Resolve Critical Policy Violations',
          priority: 'critical',
          description: `Address ${policyReport.criticalViolations.length} CRITICAL policy violation(s)`
        });
      }
      
      actions.push({
        action: 'Security Team Review',
        priority: 'high',
        description: 'Engage security team for detailed analysis'
      });
      
    } else if (decision === Decision.REVIEW) {
      actions.push({
        action: 'Manual Code Review',
        priority: 'high',
        description: 'Conduct thorough manual review of script before execution'
      });
      
      if (policyReport.highViolations.length > 0) {
        actions.push({
          action: 'Address High Severity Violations',
          priority: 'high',
          description: `Review and resolve ${policyReport.highViolations.length} HIGH severity policy violation(s)`
        });
      }
      
      actions.push({
        action: 'Verify Script Legitimacy',
        priority: 'medium',
        description: 'Confirm script source and intended functionality'
      });
      
      if (riskScore.overallScore > 50) {
        actions.push({
          action: 'Risk Assessment',
          priority: 'medium',
          description: 'Perform additional risk assessment before execution'
        });
      }
      
    } else { // ALLOW
      actions.push({
        action: 'Proceed with Execution',
        priority: 'low',
        description: 'Script can proceed with execution based on current analysis'
      });
      
      actions.push({
        action: 'Monitor Execution',
        priority: 'low',
        description: 'Monitor script execution for unexpected behavior'
      });
    }
    
    return actions;
  }

  /**
   * Collect references to risk factors
   */
  private collectRiskFactorReferences(riskScore: RiskScore): string[] {
    const references: string[] = [];
    
    riskScore.contributingFactors.forEach(factor => {
      references.push(
        `${factor.factor}: ${factor.contribution} points (${factor.description})`
      );
    });
    
    return references;
  }

  /**
   * Collect references to violated policies
   */
  private collectPolicyReferences(policyReport: PolicyValidationReport): string[] {
    const references: string[] = [];
    
    // Group by policy ID
    const policyMap = new Map<string, PolicyViolation[]>();
    policyReport.violations.forEach(violation => {
      if (!policyMap.has(violation.policyId)) {
        policyMap.set(violation.policyId, []);
      }
      policyMap.get(violation.policyId)!.push(violation);
    });
    
    policyMap.forEach((violations, policyId) => {
      const severity = violations[0].severity;
      references.push(
        `Policy ${policyId}: ${violations.length} ${severity.toUpperCase()} violation(s) - ${violations[0].explanation}`
      );
    });
    
    return references;
  }

  /**
   * Update decision thresholds
   * 
   * @param thresholds - Partial thresholds to update
   */
  updateThresholds(thresholds: Partial<DecisionThresholds>): void {
    this.thresholds = { ...this.thresholds, ...thresholds };
  }

  /**
   * Get current decision thresholds
   * 
   * @returns Current decision thresholds
   */
  getThresholds(): DecisionThresholds {
    return { ...this.thresholds };
  }
}

// Export Decision type for backward compatibility
export type { Decision as DecisionType };
