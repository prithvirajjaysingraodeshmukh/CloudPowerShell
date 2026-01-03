import { useState, useCallback, useEffect } from 'react';
import { 
  Shield, FileText, Download, CheckCircle, XCircle, AlertTriangle, 
  Settings, GitBranch, GitCompare, Bot, ChevronRight, Lock,
  RefreshCw
} from 'lucide-react';
import { 
  runCloudSecurityValidation, 
  generateSecurityReport,
  type ValidationConfig,
  CloudSecurityPolicyEngine,
  AIRemediationEngine,
  type RemediationResult
} from './engines';
import type { AnalysisResult } from './types/analysis';
import type { CloudExecutionContext } from './engines/cloudExecutionContext/CloudExecutionContextEngine';
import type { PolicyValidationReport } from './engines/cloudSecurityPolicy/CloudSecurityPolicyEngine';
import type { RiskScore } from './engines/cloudRiskScoring/CloudRiskScoringEngine';
import type { DevSecOpsDecision } from './engines/devsecopsDecision/DevSecOpsDecisionEngine';
import type { SecurityPolicy } from './engines/cloudSecurityPolicy/CloudSecurityPolicyEngine';

type ViewMode = 'single' | 'compare';

function App() {
  // Script input
  const [scriptContent, setScriptContent] = useState('');
  const [scriptContent2, setScriptContent2] = useState(''); // For comparison mode
  
  // Analysis results
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [result2, setResult2] = useState<AnalysisResult | null>(null); // For comparison
  
  // Cloud context configuration
  const [privilegeLevel, setPrivilegeLevel] = useState<'user' | 'admin' | 'managed_identity'>('user');
  const [environmentType, setEnvironmentType] = useState<'cloud_vm' | 'ci_cd_pipeline' | 'admin_automation'>('cloud_vm');
  
  // Policy configuration
  const [policyEngine] = useState(() => new CloudSecurityPolicyEngine());
  const [enabledPolicies, setEnabledPolicies] = useState<Set<string>>(new Set());
  const [policies, setPolicies] = useState<SecurityPolicy[]>([]);
  
  // UI state
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [viewMode, setViewMode] = useState<ViewMode>('single');
  const [activeTab, setActiveTab] = useState<'analysis' | 'policies' | 'remediation' | 'explainability'>('analysis');
  const [showContextPanel, setShowContextPanel] = useState(true);
  const [remediationResult, setRemediationResult] = useState<RemediationResult | null>(null);
  const [isGeneratingRemediation, setIsGeneratingRemediation] = useState(false);

  // Initialize policies on mount
  useEffect(() => {
    try {
      const allPolicies = policyEngine.getAllPolicies();
      setPolicies(allPolicies);
      setEnabledPolicies(new Set(allPolicies.map((p: SecurityPolicy) => p.id)));
    } catch (error) {
      console.error('Error initializing policies:', error);
      // Set empty policies on error to prevent crash
      setPolicies([]);
      setEnabledPolicies(new Set());
    }
  }, [policyEngine]);

  const handleAnalyze = useCallback((script: string, isSecond: boolean = false) => {
    if (!script.trim()) {
      alert('Please enter a script to analyze.');
      return;
    }

    setIsAnalyzing(true);
    try {
      // Ensure we have policies loaded before analyzing
      if (policies.length === 0) {
        console.warn('Policies not loaded yet, using default policies');
      }

      const config: ValidationConfig = {
        cloudContext: {
          privilegeLevel,
          environmentType
        },
        // Only pass enabledPolicies if we have policies loaded and enabled
        enabledPolicies: enabledPolicies.size > 0 ? Array.from(enabledPolicies) : undefined
      };

      const analysisResult = runCloudSecurityValidation(script, `script${isSecond ? '2' : ''}.ps1`, config);
      
      if (isSecond) {
        setResult2(analysisResult);
      } else {
        setResult(analysisResult);
      }
    } catch (error) {
      console.error('Analysis error:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
      alert(`Error during analysis: ${errorMessage}\n\nPlease check the browser console for more details.`);
      // Set result to null to clear any previous results
      if (isSecond) {
        setResult2(null);
      } else {
        setResult(null);
      }
    } finally {
      setIsAnalyzing(false);
    }
  }, [privilegeLevel, environmentType, enabledPolicies, policies.length]);

  const handleAnalyzeBoth = useCallback(() => {
    if (viewMode === 'compare') {
      if (scriptContent.trim()) {
        handleAnalyze(scriptContent, false);
      }
      if (scriptContent2.trim()) {
        handleAnalyze(scriptContent2, true);
      }
    } else {
      if (scriptContent.trim()) {
        handleAnalyze(scriptContent, false);
      }
    }
  }, [viewMode, scriptContent, scriptContent2, handleAnalyze]);

  const handleTogglePolicy = (policyId: string) => {
    const newEnabled = new Set(enabledPolicies);
    if (newEnabled.has(policyId)) {
      newEnabled.delete(policyId);
    } else {
      newEnabled.add(policyId);
    }
    setEnabledPolicies(newEnabled);
    
    // Re-analyze if we have results
    if (result && scriptContent.trim()) {
      handleAnalyze(scriptContent, false);
    }
  };

  const handleGenerateRemediation = async () => {
    if (!result || !scriptContent.trim()) return;

    setIsGeneratingRemediation(true);
    try {
      const remediationEngine = new AIRemediationEngine({
        maxAttempts: 3,
        minRiskScoreImprovement: 10
      });

      const config: ValidationConfig = {
        cloudContext: {
          privilegeLevel,
          environmentType
        },
        enabledPolicies: Array.from(enabledPolicies)
      };

      const remediation = await remediationEngine.generateRemediation(
        scriptContent,
        result,
        { validationConfig: config }
      );

      setRemediationResult(remediation);
      setActiveTab('remediation');
    } catch (error) {
      console.error('Remediation error:', error);
      alert('Error generating remediation. Please check the console for details.');
    } finally {
      setIsGeneratingRemediation(false);
    }
  };

  const getDecisionColor = (decision: string) => {
    switch (decision) {
      case 'allow':
        return 'text-green-600 bg-green-100 border-green-200 dark:text-green-400 dark:bg-green-950 dark:border-green-800';
      case 'review':
        return 'text-amber-600 bg-amber-100 border-amber-200 dark:text-amber-400 dark:bg-amber-950 dark:border-amber-800';
      case 'block':
        return 'text-red-600 bg-red-100 border-red-200 dark:text-red-400 dark:bg-red-950 dark:border-red-800';
      default:
        return 'text-gray-600 bg-gray-100 border-gray-200';
    }
  };

  const getDecisionIcon = (decision: string) => {
    switch (decision) {
      case 'allow':
        return <CheckCircle className="h-6 w-6" />;
      case 'review':
        return <AlertTriangle className="h-6 w-6" />;
      case 'block':
        return <XCircle className="h-6 w-6" />;
      default:
        return <Shield className="h-6 w-6" />;
    }
  };

  const getRiskColor = (riskLevel: string) => {
    switch (riskLevel.toLowerCase()) {
      case 'critical':
        return 'text-red-600 bg-red-100 dark:text-red-400 dark:bg-red-950';
      case 'high':
        return 'text-orange-600 bg-orange-100 dark:text-orange-400 dark:bg-orange-950';
      case 'medium':
        return 'text-yellow-600 bg-yellow-100 dark:text-yellow-400 dark:bg-yellow-950';
      case 'low':
        return 'text-green-600 bg-green-100 dark:text-green-400 dark:bg-green-950';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const cloudContext = result?.cloudContext as CloudExecutionContext | undefined;
  const policyValidation = result?.policyValidation as PolicyValidationReport | undefined;
  const riskScore = result?.riskScore as RiskScore | undefined;
  const decision = result?.decision as DevSecOpsDecision | undefined;

  const riskScore2 = result2?.riskScore as RiskScore | undefined;
  const decision2 = result2?.decision as DevSecOpsDecision | undefined;

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 transition-colors">
      {/* Header */}
      <header className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 sticky top-0 z-50">
        <div className="max-w-[1920px] mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-blue-600" />
              <div>
                <h1 className="text-xl font-bold text-gray-900 dark:text-gray-100">
                  Cloud-Aware PowerShell Security Validation
                </h1>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  Static security validation for PowerShell automation
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setViewMode(viewMode === 'single' ? 'compare' : 'single')}
                className={`px-4 py-2 text-sm rounded-lg transition-colors flex items-center gap-2 ${
                  viewMode === 'compare'
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
                }`}
              >
                <GitCompare className="h-4 w-4" />
                {viewMode === 'compare' ? 'Comparison Mode' : 'Single Mode'}
              </button>
              <button
                onClick={() => setShowContextPanel(!showContextPanel)}
                className="px-4 py-2 text-sm bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors flex items-center gap-2"
              >
                <Settings className="h-4 w-4" />
                {showContextPanel ? 'Hide' : 'Show'} Context
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-[1920px] mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <div className="grid grid-cols-1 xl:grid-cols-4 gap-6">
          {/* Left Sidebar - Script Input & Context */}
          <div className="xl:col-span-1 space-y-4">
            {/* Script Input Panel */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-3 flex items-center gap-2">
                <FileText className="h-5 w-5" />
                PowerShell Script Input
              </h2>
              <textarea
                value={scriptContent}
                onChange={(e) => setScriptContent(e.target.value)}
                placeholder="Paste your PowerShell script here..."
                className="w-full h-64 p-3 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 font-mono text-xs focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none"
              />
              {viewMode === 'compare' && (
                <div className="mt-3">
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Script 2 (for comparison)
                  </label>
                  <textarea
                    value={scriptContent2}
                    onChange={(e) => setScriptContent2(e.target.value)}
                    placeholder="Paste second script for comparison..."
                    className="w-full h-64 p-3 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 font-mono text-xs focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none"
                  />
                </div>
              )}
              <button
                onClick={handleAnalyzeBoth}
                disabled={!scriptContent.trim() || isAnalyzing}
                className="mt-3 w-full px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
              >
                {isAnalyzing ? (
                  <>
                    <RefreshCw className="h-4 w-4 animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Shield className="h-4 w-4" />
                    Analyze Script{viewMode === 'compare' ? 's' : ''}
                  </>
                )}
              </button>
            </div>

            {/* Configurable Cloud Context Panel */}
            {showContextPanel && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
                <h3 className="text-md font-semibold text-gray-900 dark:text-gray-100 mb-3 flex items-center gap-2">
                  <Settings className="h-4 w-4" />
                  Cloud Execution Context
                </h3>
                <div className="space-y-3">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Privilege Level
                    </label>
                    <select
                      value={privilegeLevel}
                      onChange={(e) => setPrivilegeLevel(e.target.value as any)}
                      className="w-full p-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 text-sm"
                    >
                      <option value="user">User</option>
                      <option value="admin">Admin</option>
                      <option value="managed_identity">Service Principal</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Environment
                    </label>
                    <select
                      value={environmentType}
                      onChange={(e) => setEnvironmentType(e.target.value as any)}
                      className="w-full p-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 text-sm"
                    >
                      <option value="cloud_vm">Dev</option>
                      <option value="ci_cd_pipeline">Staging</option>
                      <option value="admin_automation">Production</option>
                    </select>
                  </div>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    Risk score and decision will update based on selected context.
                  </p>
                </div>
              </div>
            )}

            {/* Policy Control Panel */}
            {showContextPanel && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
                <h3 className="text-md font-semibold text-gray-900 dark:text-gray-100 mb-3 flex items-center gap-2">
                  <Lock className="h-4 w-4" />
                  Security Policies
                </h3>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {policies.length > 0 ? (
                    policies.map((policy: SecurityPolicy) => (
                      <label
                        key={policy.id}
                        className="flex items-start gap-2 p-2 rounded hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer"
                      >
                        <input
                          type="checkbox"
                          checked={enabledPolicies.has(policy.id)}
                          onChange={() => handleTogglePolicy(policy.id)}
                          className="mt-1"
                        />
                        <div className="flex-1">
                          <div className="text-xs font-medium text-gray-900 dark:text-gray-100">
                            {policy.id}: {policy.name}
                          </div>
                          <div className="text-xs text-gray-500 dark:text-gray-400">
                            {policy.category} • {policy.severity}
                          </div>
                        </div>
                      </label>
                    ))
                  ) : (
                    <p className="text-xs text-gray-500 dark:text-gray-400 p-2">Loading policies...</p>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Main Content Area */}
          <div className="xl:col-span-3 space-y-4">
            {/* Tabs */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
              <div className="flex border-b border-gray-200 dark:border-gray-700">
                {(['analysis', 'policies', 'remediation', 'explainability'] as const).map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`px-6 py-3 text-sm font-medium transition-colors capitalize ${
                      activeTab === tab
                        ? 'text-blue-600 border-b-2 border-blue-600 dark:text-blue-400'
                        : 'text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'
                    }`}
                  >
                    {tab}
                  </button>
                ))}
              </div>
            </div>

            {/* Analysis Tab */}
            {activeTab === 'analysis' && (
              <div className="space-y-4">
                {!result ? (
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-12">
                    <div className="text-center text-gray-500 dark:text-gray-400">
                      <FileText className="h-16 w-16 mx-auto mb-4 opacity-50" />
                      <p className="text-lg">Enter a PowerShell script and click "Analyze Script" to begin validation</p>
                    </div>
                  </div>
                ) : (
                  <>
                    {/* DevSecOps Decision Banner */}
                    {decision && decision.decision && (
                      <div className={`p-6 rounded-lg border-2 ${getDecisionColor(decision.decision)}`}>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-4">
                            {getDecisionIcon(decision.decision)}
                            <div>
                              <h3 className="text-2xl font-bold capitalize">
                                Decision: {decision.decision.toUpperCase()}
                              </h3>
                              <p className="text-sm opacity-90 mt-1">
                                Confidence: {decision.confidence ? (decision.confidence * 100).toFixed(1) : '0'}%
                              </p>
                            </div>
                          </div>
                          {/* CI/CD Gate Simulation */}
                          <div className="text-right">
                            <div className="flex items-center gap-2 mb-2">
                              <GitBranch className="h-5 w-5" />
                              <span className="font-semibold">CI/CD Gate</span>
                            </div>
                            {decision.decision === 'block' ? (
                              <div className="flex items-center gap-2 text-red-600 dark:text-red-400">
                                <XCircle className="h-5 w-5" />
                                <span className="font-bold">BLOCKED</span>
                              </div>
                            ) : decision.decision === 'review' ? (
                              <div className="flex items-center gap-2 text-amber-600 dark:text-amber-400">
                                <AlertTriangle className="h-5 w-5" />
                                <span className="font-bold">REVIEW REQUIRED</span>
                              </div>
                            ) : (
                              <div className="flex items-center gap-2 text-green-600 dark:text-green-400">
                                <CheckCircle className="h-5 w-5" />
                                <span className="font-bold">ALLOWED</span>
                              </div>
                            )}
                            {decision.decision === 'block' && decision.rationale && (
                              <p className="text-xs mt-2 opacity-90">
                                Blocking reason: {decision.rationale.substring(0, 100)}...
                              </p>
                            )}
                          </div>
                        </div>
                        {decision.rationale && (
                          <div className="mt-4 pt-4 border-t border-current opacity-20">
                            <p className="text-sm font-medium mb-2">Rationale:</p>
                            <p className="text-sm opacity-90">{decision.rationale}</p>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Risk Score Visualization */}
                    {riskScore && riskScore.overallScore !== undefined && (
                      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
                          Cloud Risk Assessment
                        </h3>
                        <div className="space-y-4">
                          <div>
                            <div className="flex justify-between mb-2">
                              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                                Overall Risk Score
                              </span>
                              <span className={`text-lg font-bold px-3 py-1 rounded ${getRiskColor(riskScore.riskLevel || 'low')}`}>
                                {riskScore.overallScore}/100 ({(riskScore.riskLevel || 'low').toUpperCase()})
                              </span>
                            </div>
                            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-4">
                              <div
                                className={`h-4 rounded-full transition-all ${
                                  riskScore.riskLevel === 'critical' ? 'bg-red-500' :
                                  riskScore.riskLevel === 'high' ? 'bg-orange-500' :
                                  riskScore.riskLevel === 'medium' ? 'bg-yellow-500' : 'bg-green-500'
                                }`}
                                style={{ width: `${Math.min(riskScore.overallScore || 0, 100)}%` }}
                              />
                            </div>
                          </div>
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                            <div className="p-3 bg-gray-50 dark:bg-gray-700 rounded">
                              <div className="text-xs text-gray-500 dark:text-gray-400">Policy Risk</div>
                              <div className="text-lg font-bold">{(riskScore.policyViolationRisk || 0).toFixed(1)}</div>
                            </div>
                            <div className="p-3 bg-gray-50 dark:bg-gray-700 rounded">
                              <div className="text-xs text-gray-500 dark:text-gray-400">Privilege Risk</div>
                              <div className="text-lg font-bold">{(riskScore.privilegeLevelRisk || 0).toFixed(1)}</div>
                            </div>
                            <div className="p-3 bg-gray-50 dark:bg-gray-700 rounded">
                              <div className="text-xs text-gray-500 dark:text-gray-400">Obfuscation Risk</div>
                              <div className="text-lg font-bold">{(riskScore.obfuscationRisk || 0).toFixed(1)}</div>
                            </div>
                            <div className="p-3 bg-gray-50 dark:bg-gray-700 rounded">
                              <div className="text-xs text-gray-500 dark:text-gray-400">Network Risk</div>
                              <div className="text-lg font-bold">{(riskScore.networkExposureRisk || 0).toFixed(1)}</div>
                            </div>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Comparison View */}
                    {viewMode === 'compare' && result2 && (
                      <div className="grid grid-cols-2 gap-4">
                        <div className="bg-blue-50 dark:bg-blue-950 rounded-lg border-2 border-blue-200 dark:border-blue-800 p-4">
                          <h4 className="font-semibold mb-2">Script 1</h4>
                          {riskScore && (
                            <div className="text-2xl font-bold">{riskScore.overallScore}/100</div>
                          )}
                          {decision && (
                            <div className="text-sm mt-1 capitalize">{decision.decision}</div>
                          )}
                        </div>
                        <div className="bg-purple-50 dark:bg-purple-950 rounded-lg border-2 border-purple-200 dark:border-purple-800 p-4">
                          <h4 className="font-semibold mb-2">Script 2</h4>
                          {riskScore2 && (
                            <div className="text-2xl font-bold">{riskScore2.overallScore}/100</div>
                          )}
                          {decision2 && (
                            <div className="text-sm mt-1 capitalize">{decision2.decision}</div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Policy Violations Panel */}
                    {policyValidation && (
                      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
                          Policy Violations
                        </h3>
                        <div className="space-y-4">
                          <div className="flex justify-between items-center">
                            <span className="text-sm text-gray-600 dark:text-gray-400">Compliance Score:</span>
                            <span className="text-2xl font-bold">{policyValidation.overallCompliance}%</span>
                          </div>
                          <div className="grid grid-cols-4 gap-3">
                            <div className="text-center p-3 bg-red-50 dark:bg-red-950 rounded">
                              <div className="text-2xl font-bold text-red-600">{policyValidation.criticalViolations.length}</div>
                              <div className="text-xs text-gray-600 dark:text-gray-400">Critical</div>
                            </div>
                            <div className="text-center p-3 bg-orange-50 dark:bg-orange-950 rounded">
                              <div className="text-2xl font-bold text-orange-600">{policyValidation.highViolations.length}</div>
                              <div className="text-xs text-gray-600 dark:text-gray-400">High</div>
                            </div>
                            <div className="text-center p-3 bg-yellow-50 dark:bg-yellow-950 rounded">
                              <div className="text-2xl font-bold text-yellow-600">{policyValidation.mediumViolations.length}</div>
                              <div className="text-xs text-gray-600 dark:text-gray-400">Medium</div>
                            </div>
                            <div className="text-center p-3 bg-blue-50 dark:bg-blue-950 rounded">
                              <div className="text-2xl font-bold text-blue-600">{policyValidation.lowViolations.length}</div>
                              <div className="text-xs text-gray-600 dark:text-gray-400">Low</div>
                            </div>
                          </div>
                          {policyValidation.violations.length > 0 && (
                            <div className="mt-4 space-y-2 max-h-64 overflow-y-auto">
                              {policyValidation.violations.map((violation, idx) => (
                                <div key={idx} className="text-sm p-3 bg-red-50 dark:bg-red-950 rounded border border-red-200 dark:border-red-800">
                                  <div className="flex justify-between items-start">
                                    <div>
                                      <span className="font-medium">{violation.policyId}</span>
                                      <span className="ml-2 text-xs px-2 py-1 rounded bg-red-200 dark:bg-red-900">
                                        {violation.severity}
                                      </span>
                                    </div>
                                    {violation.lineNumber && (
                                      <span className="text-xs text-gray-500">Line {violation.lineNumber}</span>
                                    )}
                                  </div>
                                  <p className="mt-1 text-xs">{violation.description}</p>
                                  <p className="mt-1 text-xs text-gray-600 dark:text-gray-400">{violation.explanation}</p>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Cloud Execution Context */}
                    {cloudContext && (
                      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
                          Cloud Execution Context
                        </h3>
                        <div className="grid grid-cols-2 gap-4 text-sm">
                          <div>
                            <span className="text-gray-600 dark:text-gray-400">Environment:</span>
                            <span className="ml-2 font-medium">{cloudContext.environmentType}</span>
                          </div>
                          <div>
                            <span className="text-gray-600 dark:text-gray-400">Privilege Level:</span>
                            <span className="ml-2 font-medium">{cloudContext.privilegeLevel}</span>
                          </div>
                          <div>
                            <span className="text-gray-600 dark:text-gray-400">Network Exposure:</span>
                            <span className="ml-2 font-medium">{cloudContext.networkExposure}</span>
                          </div>
                          <div>
                            <span className="text-gray-600 dark:text-gray-400">Platform:</span>
                            <span className="ml-2 font-medium">{cloudContext.platform.toUpperCase()}</span>
                          </div>
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

            {/* Policies Tab */}
            {activeTab === 'policies' && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
                  Security Policy Governance
                </h3>
                <div className="space-y-3">
                  {policies && policies.length > 0 ? (
                    policies.map((policy: SecurityPolicy) => (
                      <div
                        key={policy.id}
                        className={`p-4 rounded-lg border ${
                          enabledPolicies.has(policy.id)
                            ? 'border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-950'
                            : 'border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700'
                        }`}
                      >
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-2">
                              <input
                                type="checkbox"
                                checked={enabledPolicies.has(policy.id)}
                                onChange={() => handleTogglePolicy(policy.id)}
                                className="mt-1"
                              />
                              <span className="font-semibold">{policy.id}: {policy.name}</span>
                              <span className={`text-xs px-2 py-1 rounded ${
                                policy.severity === 'critical' ? 'bg-red-200 dark:bg-red-900' :
                                policy.severity === 'high' ? 'bg-orange-200 dark:bg-orange-900' :
                                policy.severity === 'medium' ? 'bg-yellow-200 dark:bg-yellow-900' :
                                'bg-blue-200 dark:bg-blue-900'
                              }`}>
                                {policy.severity}
                              </span>
                            </div>
                            <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">{policy.description}</p>
                            <p className="text-xs text-gray-500 dark:text-gray-500">{policy.explanation}</p>
                          </div>
                        </div>
                      </div>
                    ))
                  ) : (
                    <p className="text-sm text-gray-500 dark:text-gray-400 p-4">Loading policies...</p>
                  )}
                </div>
              </div>
            )}

            {/* Remediation Tab */}
            {activeTab === 'remediation' && (
              <div className="space-y-4">
                {!result ? (
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-12">
                    <div className="text-center text-gray-500 dark:text-gray-400">
                      <Bot className="h-16 w-16 mx-auto mb-4 opacity-50" />
                      <p className="text-lg">Analyze a script first to generate AI-assisted remediation suggestions</p>
                    </div>
                  </div>
                ) : (
                  <>
                    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                      <div className="flex items-center justify-between mb-4">
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                          AI-Assisted Remediation
                        </h3>
                        <button
                          onClick={handleGenerateRemediation}
                          disabled={isGeneratingRemediation}
                          className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
                        >
                          <Bot className="h-4 w-4" />
                          {isGeneratingRemediation ? 'Generating...' : 'Generate Remediation'}
                        </button>
                      </div>
                      <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                        AI suggestions are UNTRUSTED and must be re-validated. Every suggestion goes through the full validation pipeline.
                      </p>
                    </div>

                    {remediationResult && (
                      <div className="space-y-4">
                        {remediationResult.attempts.map((attempt, idx) => (
                          <div
                            key={idx}
                            className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6"
                          >
                            <div className="flex items-center justify-between mb-4">
                              <h4 className="font-semibold">Attempt {attempt.attemptNumber}</h4>
                              <span className={`px-3 py-1 rounded text-sm font-medium ${
                                attempt.validation.status === 'accepted' ? 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300' :
                                attempt.validation.status === 'rejected' ? 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300' :
                                'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300'
                              }`}>
                                {attempt.validation.status.toUpperCase().replace('_', ' ')}
                              </span>
                            </div>
                            <div className="space-y-3">
                              <div>
                                <p className="text-sm font-medium mb-1">Suggestion:</p>
                                <p className="text-sm text-gray-600 dark:text-gray-400">{attempt.suggestion.explanation}</p>
                              </div>
                              <div>
                                <p className="text-sm font-medium mb-1">Validation Status:</p>
                                <p className="text-sm">{attempt.validation.reason}</p>
                              </div>
                              <div className="grid grid-cols-3 gap-3 text-sm">
                                <div>
                                  <div className="text-xs text-gray-500">Risk Score Change</div>
                                  <div className={`font-bold ${
                                    attempt.validation.improvement.riskScoreChange > 0 ? 'text-green-600' : 'text-red-600'
                                  }`}>
                                    {attempt.validation.improvement.riskScoreChange > 0 ? '+' : ''}
                                    {attempt.validation.improvement.riskScoreChange}
                                  </div>
                                </div>
                                <div>
                                  <div className="text-xs text-gray-500">Violations Change</div>
                                  <div className={`font-bold ${
                                    attempt.validation.improvement.policyViolationsChange > 0 ? 'text-green-600' : 'text-red-600'
                                  }`}>
                                    {attempt.validation.improvement.policyViolationsChange > 0 ? '+' : ''}
                                    {attempt.validation.improvement.policyViolationsChange}
                                  </div>
                                </div>
                                <div>
                                  <div className="text-xs text-gray-500">Decision Change</div>
                                  <div className="font-bold">{attempt.validation.improvement.decisionChange}</div>
                                </div>
                              </div>
                            </div>
                          </div>
                        ))}
                        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                          <p className="text-sm font-medium mb-2">Status:</p>
                          <p className="text-sm">{remediationResult.statusMessage}</p>
                        </div>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}

            {/* Explainability Tab */}
            {activeTab === 'explainability' && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
                  Analysis Flow & Explainability
                </h3>
                {!result ? (
                  <p className="text-gray-500 dark:text-gray-400">Analyze a script to see the step-by-step analysis flow.</p>
                ) : (
                  <div className="space-y-4">
                    <div className="flex items-start gap-4 p-4 bg-blue-50 dark:bg-blue-950 rounded-lg">
                      <div className="flex-shrink-0 w-8 h-8 bg-blue-600 text-white rounded-full flex items-center justify-center font-bold">1</div>
                      <div className="flex-1">
                        <h4 className="font-semibold mb-1">Static Analysis</h4>
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                          Analyzed script structure, detected obfuscation patterns, extracted features.
                          Obfuscation score: {result.features.obfuscationScore.toFixed(1)}/100
                        </p>
                      </div>
                    </div>
                    <ChevronRight className="h-6 w-6 text-gray-400 mx-auto" />
                    <div className="flex items-start gap-4 p-4 bg-green-50 dark:bg-green-950 rounded-lg">
                      <div className="flex-shrink-0 w-8 h-8 bg-green-600 text-white rounded-full flex items-center justify-center font-bold">2</div>
                      <div className="flex-1">
                        <h4 className="font-semibold mb-1">Cloud Execution Context</h4>
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                          Determined execution environment: {cloudContext?.environmentType}, 
                          privilege level: {cloudContext?.privilegeLevel}, 
                          network exposure: {cloudContext?.networkExposure}
                        </p>
                      </div>
                    </div>
                    <ChevronRight className="h-6 w-6 text-gray-400 mx-auto" />
                    <div className="flex items-start gap-4 p-4 bg-yellow-50 dark:bg-yellow-950 rounded-lg">
                      <div className="flex-shrink-0 w-8 h-8 bg-yellow-600 text-white rounded-full flex items-center justify-center font-bold">3</div>
                      <div className="flex-1">
                        <h4 className="font-semibold mb-1">Policy Validation</h4>
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                          Validated against {policyValidation?.validationResults.length || 0} security policies.
                          Compliance: {policyValidation?.overallCompliance}%
                        </p>
                      </div>
                    </div>
                    <ChevronRight className="h-6 w-6 text-gray-400 mx-auto" />
                    <div className="flex items-start gap-4 p-4 bg-orange-50 dark:bg-orange-950 rounded-lg">
                      <div className="flex-shrink-0 w-8 h-8 bg-orange-600 text-white rounded-full flex items-center justify-center font-bold">4</div>
                      <div className="flex-1">
                        <h4 className="font-semibold mb-1">Risk Scoring</h4>
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                          Calculated overall risk score: {riskScore?.overallScore}/100 ({riskScore?.riskLevel}).
                          Factored in policy violations, privilege level, obfuscation, and network exposure.
                        </p>
                      </div>
                    </div>
                    <ChevronRight className="h-6 w-6 text-gray-400 mx-auto" />
                    <div className="flex items-start gap-4 p-4 bg-purple-50 dark:bg-purple-950 rounded-lg">
                      <div className="flex-shrink-0 w-8 h-8 bg-purple-600 text-white rounded-full flex items-center justify-center font-bold">5</div>
                      <div className="flex-1">
                        <h4 className="font-semibold mb-1">DevSecOps Decision</h4>
                        <p className="text-sm text-gray-600 dark:text-gray-400">
                          Decision: {decision?.decision.toUpperCase()} (confidence: {(decision?.confidence || 0) * 100}%).
                          {decision?.rationale}
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Report Export Section */}
            {result && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                    Export Security Report
                  </h3>
                  <div className="flex gap-2">
                    <button
                      onClick={() => {
                        try {
                          const jsonReport = generateSecurityReport(result, 'detailed', 'json');
                          const blob = new Blob([jsonReport], { type: 'application/json;charset=utf-8' });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url;
                          // Sanitize filename to prevent URI errors
                          const sanitizedFilename = (result.filename || 'script').replace(/[^a-zA-Z0-9.-]/g, '_');
                          a.download = `security-report-${sanitizedFilename}-${Date.now()}.json`;
                          document.body.appendChild(a);
                          a.click();
                          document.body.removeChild(a);
                          URL.revokeObjectURL(url);
                        } catch (error) {
                          console.error('Error exporting JSON report:', error);
                          alert(`Error exporting JSON report: ${error instanceof Error ? error.message : 'Unknown error'}`);
                        }
                      }}
                      className="px-4 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors flex items-center gap-2"
                    >
                      <Download className="h-4 w-4" />
                      Download JSON
                    </button>
                    <button
                      onClick={() => {
                        try {
                          const textReport = generateSecurityReport(result, 'detailed', 'text');
                          const blob = new Blob([textReport], { type: 'text/plain;charset=utf-8' });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url;
                          // Sanitize filename to prevent URI errors
                          const sanitizedFilename = (result.filename || 'script').replace(/[^a-zA-Z0-9.-]/g, '_');
                          a.download = `security-report-${sanitizedFilename}-${Date.now()}.txt`;
                          document.body.appendChild(a);
                          a.click();
                          document.body.removeChild(a);
                          URL.revokeObjectURL(url);
                        } catch (error) {
                          console.error('Error exporting text report:', error);
                          alert(`Error exporting text report: ${error instanceof Error ? error.message : 'Unknown error'}`);
                        }
                      }}
                      className="px-4 py-2 text-sm bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors flex items-center gap-2"
                    >
                      <Download className="h-4 w-4" />
                      Download Summary
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="mt-16 bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700">
        <div className="max-w-[1920px] mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="text-center text-sm text-gray-500 dark:text-gray-400">
            <p>Cloud-Aware Static Security Validation for PowerShell Automation</p>
            <p className="mt-1">
              Features: Static Analysis • Cloud Context Evaluation • Policy Validation • Risk Scoring • DevSecOps Decision • AI Remediation • Reporting
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
