/**
 * Engine exports
 * 
 * Centralized exports for all analysis engines
 */

export { StaticAnalysisEngine } from './staticAnalysis/StaticAnalysisEngine';
export { CloudExecutionContextEngine } from './cloudExecutionContext/CloudExecutionContextEngine';
export type { 
  CloudExecutionContext, 
  CloudApi, 
  CloudResource, 
  ExecutionEnvironment,
  ContextMetadata
} from './cloudExecutionContext/CloudExecutionContextEngine';
export {
  ExecutionEnvironmentType,
  PrivilegeLevel,
  NetworkExposure,
  CloudPlatform,
  DEFAULT_CONTEXT
} from './cloudExecutionContext/CloudExecutionContextEngine';

export { CloudSecurityPolicyEngine, PolicySeverity } from './cloudSecurityPolicy/CloudSecurityPolicyEngine';
export type { 
  SecurityPolicy, 
  PolicyValidationResult, 
  PolicyValidationReport, 
  PolicyViolation, 
  PolicyCategory,
  PolicyDetector,
  PolicyDetectionResult
} from './cloudSecurityPolicy/CloudSecurityPolicyEngine';

export { CloudRiskScoringEngine, RiskLevel } from './cloudRiskScoring/CloudRiskScoringEngine';
export type { 
  RiskScore, 
  RiskBreakdown, 
  RiskFactors, 
  RiskFactor,
  ContributingFactor
} from './cloudRiskScoring/CloudRiskScoringEngine';

export { DevSecOpsDecisionEngine, Decision } from './devsecopsDecision/DevSecOpsDecisionEngine';
export type { 
  DevSecOpsDecision, 
  DecisionFactor, 
  RequiredAction,
  DecisionType
} from './devsecopsDecision/DevSecOpsDecisionEngine';

export { ReportingEngine } from './reporting/ReportingEngine';

// Orchestrator - Single entry point for cloud security validation
export { runCloudSecurityValidation, generateSecurityReport } from './orchestrator';
export type { ValidationConfig } from './orchestrator';

// AI Remediation Engine
export { AIRemediationEngine } from './aiRemediation/AIRemediationEngine';
export type {
  RemediationSuggestion,
  RemediationChange,
  RemediationValidationResult,
  RemediationAttempt,
  RemediationResult,
  RemediationConfig
} from './aiRemediation/AIRemediationEngine';
export type { 
  SecurityReport, 
  ReportMetadata, 
  ReportSummary,
  ScriptMetadataSummary,
  CloudContextSummary,
  CloudApiSummary,
  CloudResourceSummary,
  StaticAnalysisSummary,
  CodeStructureMetrics,
  DetectedPattern,
  PolicyValidationSummary,
  PolicyViolationDetail,
  RiskAssessmentSummary,
  ComponentRiskScores,
  RiskBreakdownSummary,
  ContributingFactorSummary,
  DecisionSummary,
  DecisionFactorSummary,
  RequiredActionSummary,
  Recommendation
} from './reporting/ReportingEngine';

