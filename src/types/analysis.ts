export interface AnalysisFeatures {
  entropy: number;
  base64Strings: string[];
  base64Count: number;
  maxStringLength: number;
  suspiciousKeywords: string[];
  suspiciousKeywordCount: number;
  totalLength: number;
  lineCount: number;
  averageLineLength: number;
  obfuscationScore: number;
  // New features
  urlsFound: string[];
  urlCount: number;
  ipAddresses: string[];
  ipCount: number;
  fileExtensions: string[];
  fileExtensionCount: number;
  powershellCommands: string[];
  powershellCommandCount: number;
  encodingMethods: string[];
  encodingMethodCount: number;
  stringObfuscationTechniques: string[];
  variableObfuscationScore: number;
  commentRatio: number;
  functionCount: number;
  nestedBlockDepth: number;
}

export interface AnalysisResult {
  filename: string;
  features: AnalysisFeatures;
  classification: 'benign' | 'suspicious' | 'malicious';
  confidence: number;
  timestamp: Date;
  scriptContent: string;
  threatCategories: string[];
  riskFactors: RiskFactor[];
  recommendations: string[];
  yara: YaraMatch[];
  behaviorAnalysis: BehaviorAnalysis;
  timeline: TimelineEvent[];
  // Cloud-aware analysis results (optional, added by respective engines)
  cloudContext?: any; // CloudExecutionContext from CloudExecutionContextEngine
  policyValidation?: any; // PolicyValidationReport from CloudSecurityPolicyEngine
  riskScore?: any; // RiskScore from CloudRiskScoringEngine
  decision?: any; // DevSecOpsDecision from DevSecOpsDecisionEngine
}

export interface YaraMatch {
  ruleName: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  tags: string[];
  matches: string[];
}

export interface BehaviorAnalysis {
  fileOperations: string[];
  registryOperations: string[];
  networkConnections: string[];
  processCreation: string[];
  serviceManipulation: string[];
  scheduledTasks: string[];
  persistenceMechanisms: string[];
  antiAnalysis: string[];
  dataExfiltration: string[];
  privilegeEscalation: string[];
}

export interface TimelineEvent {
  timestamp: string;
  action: string;
  description: string;
  severity: 'info' | 'warning' | 'critical';
  lineNumber?: number;
}

// Note: Sandbox-related interfaces removed as sandboxing is out of scope
// These may be kept for backward compatibility but are not used in cloud-aware analysis
export interface RiskFactor {
  category: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  evidence: string[];
}

export interface DatasetEntry {
  filename: string;
  label: 'benign' | 'malicious';
  features: AnalysisFeatures;
}

// Re-export engine types for convenience
export type {
  CloudExecutionContext,
  CloudApi,
  CloudResource,
  ExecutionEnvironment
} from '../engines/cloudExecutionContext/CloudExecutionContextEngine';

export type {
  SecurityPolicy,
  PolicyValidationResult,
  PolicyCategory
} from '../engines/cloudSecurityPolicy/CloudSecurityPolicyEngine';

export type {
  RiskScore,
  RiskBreakdown,
  RiskFactors,
  RiskFactor as EngineRiskFactor
} from '../engines/cloudRiskScoring/CloudRiskScoringEngine';

export type {
  DevSecOpsDecision,
  Decision,
  DecisionFactor,
  RequiredAction
} from '../engines/devsecopsDecision/DevSecOpsDecisionEngine';