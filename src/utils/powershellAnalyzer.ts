/**
 * PowerShell Analyzer
 * 
 * Main entry point for PowerShell script analysis using the modular engine architecture.
 * Coordinates analysis across all engines: static analysis, cloud context, policy validation,
 * risk scoring, decision making, and reporting.
 */

import { AnalysisResult, AnalysisFeatures } from '../types/analysis';
import {
  StaticAnalysisEngine,
  CloudExecutionContextEngine,
  CloudSecurityPolicyEngine,
  CloudRiskScoringEngine,
  DevSecOpsDecisionEngine
  // ReportingEngine - available for future use
} from '../engines';

// Initialize engines
const staticAnalysisEngine = new StaticAnalysisEngine();
const cloudExecutionContextEngine = new CloudExecutionContextEngine();
const cloudSecurityPolicyEngine = new CloudSecurityPolicyEngine();
const cloudRiskScoringEngine = new CloudRiskScoringEngine();
const devsecopsDecisionEngine = new DevSecOpsDecisionEngine();
// ReportingEngine available for future use
// const reportingEngine = new ReportingEngine();

/**
 * Main analysis function
 * 
 * Analyzes a PowerShell script using all available engines and returns
 * comprehensive analysis results.
 * 
 * @param scriptContent - The PowerShell script content to analyze
 * @param filename - The filename of the script
 * @returns Complete analysis result
 */
export function analyzeScript(scriptContent: string, filename: string = 'script.ps1'): AnalysisResult {
  // Step 1: Static Analysis (core functionality - implemented)
  const staticAnalysisResult = staticAnalysisEngine.analyze(scriptContent);
  
  const features: AnalysisFeatures = staticAnalysisResult.features;
  
  // Step 2: Cloud Execution Context Analysis (implemented)
  const cloudContext = cloudExecutionContextEngine.analyze(scriptContent, features);
  
  // Step 3: Cloud Security Policy Validation (implemented)
  const policyValidation = cloudSecurityPolicyEngine.validate(scriptContent, features, cloudContext);
  
  // Step 4: Cloud Risk Scoring (implemented)
  const riskScore = cloudRiskScoringEngine.calculateRiskScore(features, cloudContext, policyValidation);
  
  // Step 5: DevSecOps Decision (implemented)
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
  
  // Build analysis result
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
    // Cloud-aware analysis results (optional, added by respective engines)
    cloudContext,
    policyValidation,
    riskScore,
    decision
  };
  
  return result;
}

/**
 * Export analysis results to CSV
 * 
 * @param results - Array of analysis results to export
 * @returns CSV string
 */
export function exportToCSV(results: AnalysisResult[]): string {
  const headers = [
    'Filename',
    'Classification',
    'Confidence',
    'Entropy',
    'Base64 Count',
    'Max String Length',
    'Suspicious Keywords Count',
    'Total Length',
    'Line Count',
    'Average Line Length',
    'Obfuscation Score',
    'URL Count',
    'IP Count',
    'File Extensions Count',
    'PowerShell Commands Count',
    'Encoding Methods Count',
    'Variable Obfuscation Score',
    'Comment Ratio',
    'Function Count',
    'Nested Block Depth',
    'Threat Categories',
    'Timestamp'
  ];
  
  const rows = results.map(result => [
    result.filename,
    result.classification,
    result.confidence.toFixed(3),
    result.features.entropy.toFixed(3),
    result.features.base64Count,
    result.features.maxStringLength,
    result.features.suspiciousKeywordCount,
    result.features.totalLength,
    result.features.lineCount,
    result.features.averageLineLength.toFixed(2),
    result.features.obfuscationScore,
    result.features.urlCount,
    result.features.ipCount,
    result.features.fileExtensionCount,
    result.features.powershellCommandCount,
    result.features.encodingMethodCount,
    result.features.variableObfuscationScore.toFixed(2),
    result.features.commentRatio.toFixed(2),
    result.features.functionCount,
    result.features.nestedBlockDepth,
    result.threatCategories.join('; '),
    result.timestamp.toISOString()
  ]);
  
  return [headers, ...rows].map(row => row.join(',')).join('\n');
}

// Re-export utility functions from StaticAnalysisEngine for backward compatibility
export const calculateEntropy = (text: string) => staticAnalysisEngine.calculateEntropy(text);
export const detectBase64Strings = (text: string) => staticAnalysisEngine.detectBase64Strings(text);
export const extractUrls = (text: string) => staticAnalysisEngine.extractUrls(text);
export const extractIpAddresses = (text: string) => staticAnalysisEngine.extractIpAddresses(text);
export const detectFileExtensions = (text: string) => staticAnalysisEngine.detectFileExtensions(text);
export const findPowershellCommands = (text: string) => staticAnalysisEngine.findPowershellCommands(text);
export const detectEncodingMethods = (text: string) => staticAnalysisEngine.detectEncodingMethods(text);
export const analyzeStringObfuscation = (text: string) => staticAnalysisEngine.analyzeStringObfuscation(text);
export const calculateVariableObfuscationScore = (text: string) => staticAnalysisEngine.calculateVariableObfuscationScore(text);
export const calculateCommentRatio = (text: string) => staticAnalysisEngine.calculateCommentRatio(text);
export const countFunctions = (text: string) => staticAnalysisEngine.countFunctions(text);
export const calculateNestedBlockDepth = (text: string) => staticAnalysisEngine.calculateNestedBlockDepth(text);
export const findSuspiciousKeywords = (text: string) => staticAnalysisEngine.findSuspiciousKeywords(text);
export const getMaxStringLength = (text: string) => staticAnalysisEngine.getMaxStringLength(text);
export const calculateObfuscationScore = (features: AnalysisFeatures) => staticAnalysisEngine.calculateObfuscationScore(features);
export const generateThreatCategories = (features: AnalysisFeatures) => staticAnalysisEngine.generateThreatCategories(features);
export const generateRiskFactors = (features: AnalysisFeatures, scriptContent: string) => staticAnalysisEngine.generateRiskFactors(features, scriptContent);
export const generateRecommendations = (features: AnalysisFeatures, classification: string) => staticAnalysisEngine.generateRecommendations(features, classification);
export const performYaraAnalysis = (scriptContent: string) => staticAnalysisEngine.performYaraAnalysis(scriptContent);
export const analyzeBehavior = (scriptContent: string) => staticAnalysisEngine.analyzeBehavior(scriptContent);
export const generateTimeline = (scriptContent: string) => staticAnalysisEngine.generateTimeline(scriptContent);
