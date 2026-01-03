import React, { useState } from 'react';
import { AnalysisResult } from '../types/analysis';
import { FileText, Download, Calendar, Filter, CheckCircle } from 'lucide-react';

interface ReportGeneratorProps {
  results: AnalysisResult[];
}

export default function ReportGenerator({ results }: ReportGeneratorProps) {
  const [reportType, setReportType] = useState<'summary' | 'detailed' | 'executive'>('summary');
  const [dateRange, setDateRange] = useState<'all' | '7d' | '30d'>('all');
  const [includeCharts, setIncludeCharts] = useState(true);
  const [includeRecommendations, setIncludeRecommendations] = useState(true);
  const [selectedClassifications, setSelectedClassifications] = useState<string[]>(['malicious', 'suspicious', 'benign']);

  const filteredResults = results.filter(result => {
    // Filter by classification
    if (!selectedClassifications.includes(result.classification)) return false;
    
    // Filter by date range
    if (dateRange !== 'all') {
      const days = dateRange === '7d' ? 7 : 30;
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - days);
      if (new Date(result.timestamp) < cutoff) return false;
    }
    
    return true;
  });

  const generateReport = () => {
    const reportData = {
      metadata: {
        generatedAt: new Date().toISOString(),
        reportType,
        dateRange,
        totalScripts: filteredResults.length,
        analysisEngine: 'PowerShell Static Analyzer v1.0'
      },
      summary: {
        totalAnalyzed: filteredResults.length,
        maliciousCount: filteredResults.filter(r => r.classification === 'malicious').length,
        suspiciousCount: filteredResults.filter(r => r.classification === 'suspicious').length,
        benignCount: filteredResults.filter(r => r.classification === 'benign').length,
        averageObfuscationScore: filteredResults.reduce((sum, r) => sum + r.features.obfuscationScore, 0) / filteredResults.length || 0,
        totalNetworkIndicators: filteredResults.reduce((sum, r) => sum + r.features.urlCount + r.features.ipCount, 0),
        totalBase64Strings: filteredResults.reduce((sum, r) => sum + r.features.base64Count, 0)
      },
      threatCategories: {},
      networkIndicators: {
        urls: [...new Set(filteredResults.flatMap(r => r.features.urlsFound || []))],
        ips: [...new Set(filteredResults.flatMap(r => r.features.ipAddresses || []))]
      },
      highRiskScripts: filteredResults
        .filter(r => r.features.obfuscationScore > 70)
        .sort((a, b) => b.features.obfuscationScore - a.features.obfuscationScore)
        .slice(0, 10),
      recommendations: includeRecommendations ? generateGlobalRecommendations(filteredResults) : [],
      detailedResults: reportType === 'detailed' ? filteredResults : []
    };

    // Calculate threat categories
    const allCategories = filteredResults.flatMap(r => r.threatCategories || []);
    reportData.threatCategories = allCategories.reduce((acc, category) => {
      acc[category] = (acc[category] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return reportData;
  };

  const generateGlobalRecommendations = (results: AnalysisResult[]): string[] => {
    const recommendations = [];
    const maliciousCount = results.filter(r => r.classification === 'malicious').length;
    const suspiciousCount = results.filter(r => r.classification === 'suspicious').length;
    const networkIndicators = results.reduce((sum, r) => sum + r.features.urlCount + r.features.ipCount, 0);
    
    if (maliciousCount > 0) {
      recommendations.push(`🚨 CRITICAL: ${maliciousCount} malicious script(s) detected - immediate action required`);
      recommendations.push('🔒 Implement strict execution policies and sandboxing for PowerShell scripts');
    }
    
    if (suspiciousCount > 0) {
      recommendations.push(`⚠️ WARNING: ${suspiciousCount} suspicious script(s) require further investigation`);
    }
    
    if (networkIndicators > 0) {
      recommendations.push('🌐 Monitor network traffic for connections to detected URLs and IP addresses');
      recommendations.push('🛡️ Consider implementing network-level blocking for suspicious indicators');
    }
    
    recommendations.push('📊 Regular monitoring and analysis of PowerShell activity is recommended');
    recommendations.push('🎓 Provide security awareness training on PowerShell-based threats');
    
    return recommendations;
  };

  const downloadReport = () => {
    const reportData = generateReport();
    let content = '';

    if (reportType === 'executive') {
      content = generateExecutiveReport(reportData);
    } else if (reportType === 'detailed') {
      content = generateDetailedReport(reportData);
    } else {
      content = generateSummaryReport(reportData);
    }

    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `powershell-analysis-report-${reportType}-${new Date().toISOString().split('T')[0]}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const generateExecutiveReport = (data: any) => {
    return `
EXECUTIVE SUMMARY - POWERSHELL SECURITY ANALYSIS
Generated: ${new Date(data.metadata.generatedAt).toLocaleString()}
Analysis Period: ${data.metadata.dateRange === 'all' ? 'All Time' : data.metadata.dateRange}

THREAT OVERVIEW
===============
Total Scripts Analyzed: ${data.summary.totalAnalyzed}
Malicious Scripts: ${data.summary.maliciousCount} (${((data.summary.maliciousCount / data.summary.totalAnalyzed) * 100).toFixed(1)}%)
Suspicious Scripts: ${data.summary.suspiciousCount} (${((data.summary.suspiciousCount / data.summary.totalAnalyzed) * 100).toFixed(1)}%)
Benign Scripts: ${data.summary.benignCount} (${((data.summary.benignCount / data.summary.totalAnalyzed) * 100).toFixed(1)}%)

RISK ASSESSMENT
===============
Average Obfuscation Score: ${data.summary.averageObfuscationScore.toFixed(1)}/100
Network Indicators Found: ${data.summary.totalNetworkIndicators}
Encoded Payloads Detected: ${data.summary.totalBase64Strings}

KEY RECOMMENDATIONS
==================
${data.recommendations.map(rec => `• ${rec}`).join('\n')}

HIGH-RISK SCRIPTS
=================
${data.highRiskScripts.map((script: any, idx: number) => 
  `${idx + 1}. ${script.filename} (Score: ${script.features.obfuscationScore})`
).join('\n')}
`;
  };

  const generateSummaryReport = (data: any) => {
    return `
POWERSHELL STATIC ANALYSIS REPORT - SUMMARY
Generated: ${new Date(data.metadata.generatedAt).toLocaleString()}
Report Type: ${data.metadata.reportType.toUpperCase()}
Analysis Engine: ${data.metadata.analysisEngine}

ANALYSIS SUMMARY
================
Total Scripts Analyzed: ${data.summary.totalAnalyzed}
Analysis Period: ${data.metadata.dateRange === 'all' ? 'All Time' : data.metadata.dateRange}

CLASSIFICATION BREAKDOWN
========================
• Malicious: ${data.summary.maliciousCount} scripts (${((data.summary.maliciousCount / data.summary.totalAnalyzed) * 100).toFixed(1)}%)
• Suspicious: ${data.summary.suspiciousCount} scripts (${((data.summary.suspiciousCount / data.summary.totalAnalyzed) * 100).toFixed(1)}%)
• Benign: ${data.summary.benignCount} scripts (${((data.summary.benignCount / data.summary.totalAnalyzed) * 100).toFixed(1)}%)

THREAT INDICATORS
=================
Average Obfuscation Score: ${data.summary.averageObfuscationScore.toFixed(1)}/100
Total Network Indicators: ${data.summary.totalNetworkIndicators}
Total Base64 Encoded Strings: ${data.summary.totalBase64Strings}

THREAT CATEGORIES
=================
${Object.entries(data.threatCategories).map(([category, count]) => 
  `• ${category}: ${count} occurrence(s)`
).join('\n')}

${data.recommendations.length > 0 ? `
RECOMMENDATIONS
===============
${data.recommendations.map(rec => `• ${rec}`).join('\n')}
` : ''}
`;
  };

  const generateDetailedReport = (data: any) => {
    let report = generateSummaryReport(data);
    
    report += `

DETAILED ANALYSIS RESULTS
=========================
`;

    data.detailedResults.forEach((result: AnalysisResult, idx: number) => {
      report += `
${idx + 1}. ${result.filename}
   Classification: ${result.classification.toUpperCase()}
   Confidence: ${(result.confidence * 100).toFixed(1)}%
   Obfuscation Score: ${result.features.obfuscationScore}/100
   Entropy: ${result.features.entropy.toFixed(2)}
   Base64 Strings: ${result.features.base64Count}
   Suspicious Keywords: ${result.features.suspiciousKeywordCount}
   Network Indicators: ${result.features.urlCount + result.features.ipCount}
   Script Length: ${result.features.totalLength.toLocaleString()} characters
   Analysis Date: ${new Date(result.timestamp).toLocaleString()}
   ${result.threatCategories && result.threatCategories.length > 0 ? 
     `Threat Categories: ${result.threatCategories.join(', ')}` : ''}
`;
    });

    return report;
  };

  const handleClassificationToggle = (classification: string) => {
    setSelectedClassifications(prev => 
      prev.includes(classification)
        ? prev.filter(c => c !== classification)
        : [...prev, classification]
    );
  };

  return (
    <div className="space-y-6">
      <div className="text-center">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">
          Security Report Generator
        </h2>
        <p className="text-gray-600 dark:text-gray-400">
          Generate comprehensive security reports from your analysis results
        </p>
      </div>

      {/* Report Configuration */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3">
            <FileText className="h-5 w-5 text-blue-500" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
              Report Configuration
            </h3>
          </div>
        </div>
        <div className="p-6 space-y-6">
          {/* Report Type */}
          <div>
            <label className="block text-sm font-medium text-gray-900 dark:text-gray-100 mb-3">
              Report Type
            </label>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {[
                { value: 'executive', label: 'Executive Summary', desc: 'High-level overview for management' },
                { value: 'summary', label: 'Summary Report', desc: 'Balanced overview with key metrics' },
                { value: 'detailed', label: 'Detailed Analysis', desc: 'Complete technical analysis' }
              ].map(type => (
                <div
                  key={type.value}
                  onClick={() => setReportType(type.value as any)}
                  className={`p-4 rounded-lg border cursor-pointer transition-all ${
                    reportType === type.value
                      ? 'border-blue-500 bg-blue-50 dark:bg-blue-950'
                      : 'border-gray-200 dark:border-gray-700 hover:border-gray-300'
                  }`}
                >
                  <div className="flex items-center space-x-2 mb-2">
                    <input
                      type="radio"
                      checked={reportType === type.value}
                      onChange={() => {}}
                      className="h-4 w-4 text-blue-600"
                    />
                    <span className="font-medium text-gray-900 dark:text-gray-100">
                      {type.label}
                    </span>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    {type.desc}
                  </p>
                </div>
              ))}
            </div>
          </div>

          {/* Date Range */}
          <div>
            <label className="block text-sm font-medium text-gray-900 dark:text-gray-100 mb-3">
              <Calendar className="inline h-4 w-4 mr-2" />
              Date Range
            </label>
            <select
              value={dateRange}
              onChange={(e) => setDateRange(e.target.value as any)}
              className="w-full md:w-auto px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
            >
              <option value="all">All Time</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>
          </div>

          {/* Classification Filter */}
          <div>
            <label className="block text-sm font-medium text-gray-900 dark:text-gray-100 mb-3">
              <Filter className="inline h-4 w-4 mr-2" />
              Include Classifications
            </label>
            <div className="flex flex-wrap gap-4">
              {['malicious', 'suspicious', 'benign'].map(classification => (
                <label key={classification} className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={selectedClassifications.includes(classification)}
                    onChange={() => handleClassificationToggle(classification)}
                    className="h-4 w-4 text-blue-600 rounded"
                  />
                  <span className="text-sm text-gray-900 dark:text-gray-100 capitalize">
                    {classification}
                  </span>
                </label>
              ))}
            </div>
          </div>

          {/* Additional Options */}
          <div>
            <label className="block text-sm font-medium text-gray-900 dark:text-gray-100 mb-3">
              Additional Options
            </label>
            <div className="space-y-2">
              <label className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  checked={includeRecommendations}
                  onChange={(e) => setIncludeRecommendations(e.target.checked)}
                  className="h-4 w-4 text-blue-600 rounded"
                />
                <span className="text-sm text-gray-900 dark:text-gray-100">
                  Include Security Recommendations
                </span>
              </label>
            </div>
          </div>
        </div>
      </div>

      {/* Report Preview */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
            Report Preview
          </h3>
        </div>
        <div className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
            <div className="text-center">
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
                {filteredResults.length}
              </p>
              <p className="text-sm text-gray-600 dark:text-gray-400">Total Scripts</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-red-600">
                {filteredResults.filter(r => r.classification === 'malicious').length}
              </p>
              <p className="text-sm text-gray-600 dark:text-gray-400">Malicious</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-amber-600">
                {filteredResults.filter(r => r.classification === 'suspicious').length}
              </p>
              <p className="text-sm text-gray-600 dark:text-gray-400">Suspicious</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-green-600">
                {filteredResults.filter(r => r.classification === 'benign').length}
              </p>
              <p className="text-sm text-gray-600 dark:text-gray-400">Benign</p>
            </div>
          </div>

          <div className="flex justify-center">
            <button
              onClick={downloadReport}
              disabled={filteredResults.length === 0}
              className="flex items-center space-x-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <Download className="h-5 w-5" />
              <span>Generate & Download Report</span>
            </button>
          </div>

          {filteredResults.length === 0 && (
            <p className="text-center text-gray-500 dark:text-gray-400 mt-4">
              No scripts match the current filter criteria
            </p>
          )}
        </div>
      </div>
    </div>
  );
}