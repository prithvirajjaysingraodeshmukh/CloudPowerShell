import React from 'react';
import { AnalysisResult } from '../types/analysis';
import { Shield, AlertTriangle, AlertCircle, FileText, Hash, Key, Eye, Globe, Server, Code, Zap, MessageSquare } from 'lucide-react';

interface AnalysisResultsProps {
  result: AnalysisResult;
}

export default function AnalysisResults({ result }: AnalysisResultsProps) {
  const getClassificationColor = (classification: string) => {
    switch (classification) {
      case 'benign':
        return 'text-green-600 bg-green-100 border-green-200 dark:text-green-400 dark:bg-green-950 dark:border-green-800';
      case 'suspicious':
        return 'text-amber-600 bg-amber-100 border-amber-200 dark:text-amber-400 dark:bg-amber-950 dark:border-amber-800';
      case 'malicious':
        return 'text-red-600 bg-red-100 border-red-200 dark:text-red-400 dark:bg-red-950 dark:border-red-800';
      default:
        return 'text-gray-600 bg-gray-100 border-gray-200';
    }
  };

  const getClassificationIcon = (classification: string) => {
    switch (classification) {
      case 'benign':
        return <Shield className="h-5 w-5" />;
      case 'suspicious':
        return <AlertTriangle className="h-5 w-5" />;
      case 'malicious':
        return <AlertCircle className="h-5 w-5" />;
      default:
        return <FileText className="h-5 w-5" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'text-red-700 bg-red-100 border-red-300 dark:text-red-300 dark:bg-red-950 dark:border-red-700';
      case 'high':
        return 'text-orange-700 bg-orange-100 border-orange-300 dark:text-orange-300 dark:bg-orange-950 dark:border-orange-700';
      case 'medium':
        return 'text-yellow-700 bg-yellow-100 border-yellow-300 dark:text-yellow-300 dark:bg-yellow-950 dark:border-yellow-700';
      case 'low':
        return 'text-blue-700 bg-blue-100 border-blue-300 dark:text-blue-300 dark:bg-blue-950 dark:border-blue-700';
      default:
        return 'text-gray-700 bg-gray-100 border-gray-300';
    }
  };

  return (
    <div className="space-y-6">
      {/* Classification Header */}
      <div className={`p-6 rounded-lg border ${getClassificationColor(result.classification)}`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            {getClassificationIcon(result.classification)}
            <div>
              <h2 className="text-xl font-bold capitalize">
                {result.classification}
              </h2>
              <p className="text-sm opacity-90">
                Confidence: {(result.confidence * 100).toFixed(1)}%
              </p>
            </div>
          </div>
          <div className="text-right">
            <p className="font-medium">{result.filename}</p>
            <p className="text-sm opacity-75">
              {result.timestamp.toLocaleString()}
            </p>
          </div>
        </div>
      </div>

      {/* Threat Categories */}
      {result.threatCategories.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
              Threat Categories
            </h3>
          </div>
          <div className="p-6">
            <div className="flex flex-wrap gap-2">
              {result.threatCategories.map((category, idx) => (
                <span
                  key={idx}
                  className="px-3 py-1 bg-red-100 dark:bg-red-950 text-red-800 dark:text-red-200 text-sm rounded-full font-medium"
                >
                  {category}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Risk Factors */}
      {result.riskFactors.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
              Risk Factors
            </h3>
          </div>
          <div className="p-6 space-y-4">
            {result.riskFactors.map((factor, idx) => (
              <div key={idx} className={`p-4 rounded-lg border ${getSeverityColor(factor.severity)}`}>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="font-semibold">{factor.category}</h4>
                  <span className="px-2 py-1 text-xs font-medium rounded-full uppercase">
                    {factor.severity}
                  </span>
                </div>
                <p className="text-sm mb-2">{factor.description}</p>
                {factor.evidence.length > 0 && (
                  <div className="text-xs">
                    <strong>Evidence:</strong>
                    <ul className="list-disc list-inside mt-1 space-y-1">
                      {factor.evidence.map((evidence, evidenceIdx) => (
                        <li key={evidenceIdx} className="font-mono break-all">
                          {evidence}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Feature Analysis */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Entropy Score */}
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3 mb-3">
            <Hash className="h-5 w-5 text-blue-500" />
            <h3 className="font-semibold text-gray-900 dark:text-gray-100">
              Entropy Score
            </h3>
          </div>
          <div className="space-y-2">
            <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
              {result.features.entropy.toFixed(2)}
            </p>
            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
              <div
                className="bg-blue-500 h-2 rounded-full"
                style={{ width: `${Math.min((result.features.entropy / 8) * 100, 100)}%` }}
              />
            </div>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Higher entropy indicates more randomness/obfuscation
            </p>
          </div>
        </div>

        {/* Base64 Strings */}
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3 mb-3">
            <Key className="h-5 w-5 text-amber-500" />
            <h3 className="font-semibold text-gray-900 dark:text-gray-100">
              Base64 Strings
            </h3>
          </div>
          <div className="space-y-2">
            <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
              {result.features.base64Count}
            </p>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Encoded strings detected
            </p>
            {result.features.base64Strings.length > 0 && (
              <div className="mt-3 max-h-20 overflow-y-auto">
                {result.features.base64Strings.slice(0, 3).map((str, idx) => (
                  <div key={idx} className="text-xs font-mono bg-gray-100 dark:bg-gray-700 p-1 rounded mb-1 truncate">
                    {str.substring(0, 30)}...
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Network Indicators */}
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3 mb-3">
            <Globe className="h-5 w-5 text-purple-500" />
            <h3 className="font-semibold text-gray-900 dark:text-gray-100">
              Network Activity
            </h3>
          </div>
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-sm text-gray-600 dark:text-gray-400">URLs:</span>
              <span className="font-bold text-gray-900 dark:text-gray-100">
                {result.features.urlCount}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-gray-600 dark:text-gray-400">IPs:</span>
              <span className="font-bold text-gray-900 dark:text-gray-100">
                {result.features.ipCount}
              </span>
            </div>
            {(result.features.urlsFound.length > 0 || result.features.ipAddresses.length > 0) && (
              <div className="mt-3 max-h-20 overflow-y-auto">
                {[...result.features.urlsFound, ...result.features.ipAddresses].slice(0, 3).map((item, idx) => (
                  <div key={idx} className="text-xs font-mono bg-gray-100 dark:bg-gray-700 p-1 rounded mb-1 truncate">
                    {item}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Obfuscation Score */}
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3 mb-3">
            <Eye className="h-5 w-5 text-red-500" />
            <h3 className="font-semibold text-gray-900 dark:text-gray-100">
              Obfuscation Score
            </h3>
          </div>
          <div className="space-y-2">
            <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
              {result.features.obfuscationScore}
            </p>
            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
              <div
                className={`h-2 rounded-full ${
                  result.features.obfuscationScore >= 70 
                    ? 'bg-red-500' 
                    : result.features.obfuscationScore >= 40 
                    ? 'bg-amber-500' 
                    : 'bg-green-500'
                }`}
                style={{ width: `${result.features.obfuscationScore}%` }}
              />
            </div>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Combined risk assessment score
            </p>
          </div>
        </div>
      </div>

      {/* Advanced Analysis */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {/* Code Structure */}
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3 mb-3">
            <Code className="h-5 w-5 text-indigo-500" />
            <h3 className="font-semibold text-gray-900 dark:text-gray-100">
              Code Structure
            </h3>
          </div>
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-sm text-gray-600 dark:text-gray-400">Functions:</span>
              <span className="font-medium text-gray-900 dark:text-gray-100">
                {result.features.functionCount}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-gray-600 dark:text-gray-400">Max Nesting:</span>
              <span className="font-medium text-gray-900 dark:text-gray-100">
                {result.features.nestedBlockDepth}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-gray-600 dark:text-gray-400">Comment Ratio:</span>
              <span className="font-medium text-gray-900 dark:text-gray-100">
                {result.features.commentRatio.toFixed(1)}%
              </span>
            </div>
          </div>
        </div>

        {/* Obfuscation Techniques */}
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3 mb-3">
            <Zap className="h-5 w-5 text-yellow-500" />
            <h3 className="font-semibold text-gray-900 dark:text-gray-100">
              Obfuscation Methods
            </h3>
          </div>
          <div className="space-y-2">
            <div className="flex justify-between">
              <span className="text-sm text-gray-600 dark:text-gray-400">Variable Obfuscation:</span>
              <span className="font-medium text-gray-900 dark:text-gray-100">
                {result.features.variableObfuscationScore.toFixed(1)}%
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-gray-600 dark:text-gray-400">Encoding Methods:</span>
              <span className="font-medium text-gray-900 dark:text-gray-100">
                {result.features.encodingMethodCount}
              </span>
            </div>
            {result.features.stringObfuscationTechniques.length > 0 && (
              <div className="mt-3">
                <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">Techniques:</p>
                <div className="flex flex-wrap gap-1">
                  {result.features.stringObfuscationTechniques.map((technique, idx) => (
                    <span
                      key={idx}
                      className="px-2 py-1 bg-yellow-100 dark:bg-yellow-950 text-yellow-800 dark:text-yellow-200 text-xs rounded"
                    >
                      {technique}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* PowerShell Commands */}
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3 mb-3">
            <Server className="h-5 w-5 text-green-500" />
            <h3 className="font-semibold text-gray-900 dark:text-gray-100">
              PowerShell Commands
            </h3>
          </div>
          <div className="space-y-2">
            <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
              {result.features.powershellCommandCount}
            </p>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Legitimate PS commands found
            </p>
            {result.features.powershellCommands.length > 0 && (
              <div className="mt-3 max-h-20 overflow-y-auto">
                {result.features.powershellCommands.slice(0, 5).map((cmd, idx) => (
                  <div key={idx} className="text-xs font-mono bg-gray-100 dark:bg-gray-700 p-1 rounded mb-1">
                    {cmd}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recommendations */}
      {result.recommendations.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <div className="flex items-center space-x-3">
              <MessageSquare className="h-5 w-5 text-blue-500" />
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                Security Recommendations
              </h3>
            </div>
          </div>
          <div className="p-6">
            <div className="space-y-3">
              {result.recommendations.map((recommendation, idx) => (
                <div key={idx} className="flex items-start space-x-3 p-3 bg-blue-50 dark:bg-blue-950 rounded-lg">
                  <div className="flex-shrink-0 w-2 h-2 bg-blue-500 rounded-full mt-2"></div>
                  <p className="text-sm text-gray-700 dark:text-gray-300">
                    {recommendation}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Detailed Features */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
            Detailed Analysis
          </h3>
        </div>
        <div className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-4">
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">Script Length:</span>
                <span className="font-medium text-gray-900 dark:text-gray-100">
                  {result.features.totalLength.toLocaleString()} chars
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">Line Count:</span>
                <span className="font-medium text-gray-900 dark:text-gray-100">
                  {result.features.lineCount}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">Avg Line Length:</span>
                <span className="font-medium text-gray-900 dark:text-gray-100">
                  {result.features.averageLineLength.toFixed(1)} chars
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">File Extensions:</span>
                <span className="font-medium text-gray-900 dark:text-gray-100">
                  {result.features.fileExtensionCount}
                </span>
              </div>
            </div>
            <div className="space-y-4">
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">Max String Length:</span>
                <span className="font-medium text-gray-900 dark:text-gray-100">
                  {result.features.maxStringLength} chars
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">Suspicious Keywords:</span>
                <span className="font-medium text-gray-900 dark:text-gray-100">
                  {result.features.suspiciousKeywordCount}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">Encoding Methods:</span>
                <span className="font-medium text-gray-900 dark:text-gray-100">
                  {result.features.encodingMethodCount}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">Variable Obfuscation:</span>
                <span className="font-medium text-gray-900 dark:text-gray-100">
                  {result.features.variableObfuscationScore.toFixed(1)}%
                </span>
              </div>
            </div>
          </div>

          {/* Suspicious Keywords */}
          {result.features.suspiciousKeywords.length > 0 && (
            <div className="mt-6">
              <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">
                Detected Suspicious Keywords:
              </h4>
              <div className="flex flex-wrap gap-2">
                {result.features.suspiciousKeywords.map((keyword, idx) => (
                  <span
                    key={idx}
                    className="px-2 py-1 bg-red-100 dark:bg-red-950 text-red-800 dark:text-red-200 text-xs rounded font-mono"
                  >
                    {keyword}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Network Indicators */}
          {(result.features.urlsFound.length > 0 || result.features.ipAddresses.length > 0) && (
            <div className="mt-6">
              <h4 className="text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">
                Network Indicators:
              </h4>
              <div className="space-y-2">
                {result.features.urlsFound.length > 0 && (
                  <div>
                    <p className="text-xs text-gray-600 dark:text-gray-400 mb-1">URLs:</p>
                    <div className="flex flex-wrap gap-2">
                      {result.features.urlsFound.map((url, idx) => (
                        <span
                          key={idx}
                          className="px-2 py-1 bg-purple-100 dark:bg-purple-950 text-purple-800 dark:text-purple-200 text-xs rounded font-mono break-all"
                        >
                          {url}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {result.features.ipAddresses.length > 0 && (
                  <div>
                    <p className="text-xs text-gray-600 dark:text-gray-400 mb-1">IP Addresses:</p>
                    <div className="flex flex-wrap gap-2">
                      {result.features.ipAddresses.map((ip, idx) => (
                        <span
                          key={idx}
                          className="px-2 py-1 bg-orange-100 dark:bg-orange-950 text-orange-800 dark:text-orange-200 text-xs rounded font-mono"
                        >
                          {ip}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}