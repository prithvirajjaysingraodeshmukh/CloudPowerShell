import React, { useState } from 'react';
import { AnalysisResult } from '../types/analysis';
import { GitCompare, TrendingUp, TrendingDown, Minus, AlertTriangle } from 'lucide-react';

interface ScriptComparisonProps {
  results: AnalysisResult[];
}

export default function ScriptComparison({ results }: ScriptComparisonProps) {
  const [selectedScripts, setSelectedScripts] = useState<string[]>([]);

  const handleScriptSelection = (filename: string) => {
    setSelectedScripts(prev => {
      if (prev.includes(filename)) {
        return prev.filter(f => f !== filename);
      } else if (prev.length < 3) {
        return [...prev, filename];
      }
      return prev;
    });
  };

  const selectedResults = results.filter(r => selectedScripts.includes(r.filename));

  const getComparisonIcon = (value1: number, value2: number) => {
    if (value1 > value2) return <TrendingUp className="h-4 w-4 text-red-500" />;
    if (value1 < value2) return <TrendingDown className="h-4 w-4 text-green-500" />;
    return <Minus className="h-4 w-4 text-gray-500" />;
  };

  const getClassificationColor = (classification: string) => {
    switch (classification) {
      case 'malicious': return 'text-red-600 bg-red-100 dark:bg-red-950 dark:text-red-400';
      case 'suspicious': return 'text-amber-600 bg-amber-100 dark:bg-amber-950 dark:text-amber-400';
      case 'benign': return 'text-green-600 bg-green-100 dark:bg-green-950 dark:text-green-400';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  if (results.length === 0) {
    return (
      <div className="text-center py-12 text-gray-500 dark:text-gray-400">
        <p>No scripts available for comparison.</p>
        <p className="text-sm mt-2">Analyze some scripts first to enable comparison features.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="text-center">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">
          Script Comparison Tool
        </h2>
        <p className="text-gray-600 dark:text-gray-400">
          Compare up to 3 scripts side-by-side to identify differences and similarities
        </p>
      </div>

      {/* Script Selection */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3">
            <GitCompare className="h-5 w-5 text-blue-500" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
              Select Scripts to Compare ({selectedScripts.length}/3)
            </h3>
          </div>
        </div>
        <div className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {results.map((result) => (
              <div
                key={result.filename}
                onClick={() => handleScriptSelection(result.filename)}
                className={`p-4 rounded-lg border cursor-pointer transition-all ${
                  selectedScripts.includes(result.filename)
                    ? 'border-blue-500 bg-blue-50 dark:bg-blue-950'
                    : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <p className="font-medium text-gray-900 dark:text-gray-100 truncate">
                    {result.filename}
                  </p>
                  <input
                    type="checkbox"
                    checked={selectedScripts.includes(result.filename)}
                    onChange={() => {}}
                    className="h-4 w-4 text-blue-600 rounded"
                  />
                </div>
                <div className="flex items-center justify-between">
                  <span className={`px-2 py-1 text-xs font-medium rounded-full ${getClassificationColor(result.classification)}`}>
                    {result.classification}
                  </span>
                  <span className="text-sm font-bold text-gray-900 dark:text-gray-100">
                    Score: {result.features.obfuscationScore}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Comparison Results */}
      {selectedResults.length >= 2 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
              Comparison Results
            </h3>
          </div>
          <div className="p-6 overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-700">
                  <th className="text-left py-3 px-4 font-medium text-gray-900 dark:text-gray-100">
                    Metric
                  </th>
                  {selectedResults.map((result, idx) => (
                    <th key={idx} className="text-center py-3 px-4 font-medium text-gray-900 dark:text-gray-100">
                      <div className="truncate max-w-32" title={result.filename}>
                        {result.filename}
                      </div>
                      <div className={`text-xs px-2 py-1 rounded-full mt-1 ${getClassificationColor(result.classification)}`}>
                        {result.classification}
                      </div>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                <tr>
                  <td className="py-3 px-4 font-medium text-gray-900 dark:text-gray-100">
                    Obfuscation Score
                  </td>
                  {selectedResults.map((result, idx) => (
                    <td key={idx} className="py-3 px-4 text-center">
                      <div className="flex items-center justify-center space-x-2">
                        <span className="font-bold text-gray-900 dark:text-gray-100">
                          {result.features.obfuscationScore}
                        </span>
                        {idx > 0 && getComparisonIcon(
                          result.features.obfuscationScore,
                          selectedResults[0].features.obfuscationScore
                        )}
                      </div>
                    </td>
                  ))}
                </tr>
                <tr>
                  <td className="py-3 px-4 font-medium text-gray-900 dark:text-gray-100">
                    Entropy
                  </td>
                  {selectedResults.map((result, idx) => (
                    <td key={idx} className="py-3 px-4 text-center">
                      <div className="flex items-center justify-center space-x-2">
                        <span className="font-bold text-gray-900 dark:text-gray-100">
                          {result.features.entropy.toFixed(2)}
                        </span>
                        {idx > 0 && getComparisonIcon(
                          result.features.entropy,
                          selectedResults[0].features.entropy
                        )}
                      </div>
                    </td>
                  ))}
                </tr>
                <tr>
                  <td className="py-3 px-4 font-medium text-gray-900 dark:text-gray-100">
                    Base64 Strings
                  </td>
                  {selectedResults.map((result, idx) => (
                    <td key={idx} className="py-3 px-4 text-center">
                      <div className="flex items-center justify-center space-x-2">
                        <span className="font-bold text-gray-900 dark:text-gray-100">
                          {result.features.base64Count}
                        </span>
                        {idx > 0 && getComparisonIcon(
                          result.features.base64Count,
                          selectedResults[0].features.base64Count
                        )}
                      </div>
                    </td>
                  ))}
                </tr>
                <tr>
                  <td className="py-3 px-4 font-medium text-gray-900 dark:text-gray-100">
                    Suspicious Keywords
                  </td>
                  {selectedResults.map((result, idx) => (
                    <td key={idx} className="py-3 px-4 text-center">
                      <div className="flex items-center justify-center space-x-2">
                        <span className="font-bold text-gray-900 dark:text-gray-100">
                          {result.features.suspiciousKeywordCount}
                        </span>
                        {idx > 0 && getComparisonIcon(
                          result.features.suspiciousKeywordCount,
                          selectedResults[0].features.suspiciousKeywordCount
                        )}
                      </div>
                    </td>
                  ))}
                </tr>
                <tr>
                  <td className="py-3 px-4 font-medium text-gray-900 dark:text-gray-100">
                    Network Indicators
                  </td>
                  {selectedResults.map((result, idx) => (
                    <td key={idx} className="py-3 px-4 text-center">
                      <div className="flex items-center justify-center space-x-2">
                        <span className="font-bold text-gray-900 dark:text-gray-100">
                          {result.features.urlCount + result.features.ipCount}
                        </span>
                        {idx > 0 && getComparisonIcon(
                          result.features.urlCount + result.features.ipCount,
                          selectedResults[0].features.urlCount + selectedResults[0].features.ipCount
                        )}
                      </div>
                    </td>
                  ))}
                </tr>
                <tr>
                  <td className="py-3 px-4 font-medium text-gray-900 dark:text-gray-100">
                    Variable Obfuscation
                  </td>
                  {selectedResults.map((result, idx) => (
                    <td key={idx} className="py-3 px-4 text-center">
                      <div className="flex items-center justify-center space-x-2">
                        <span className="font-bold text-gray-900 dark:text-gray-100">
                          {result.features.variableObfuscationScore.toFixed(1)}%
                        </span>
                        {idx > 0 && getComparisonIcon(
                          result.features.variableObfuscationScore,
                          selectedResults[0].features.variableObfuscationScore
                        )}
                      </div>
                    </td>
                  ))}
                </tr>
                <tr>
                  <td className="py-3 px-4 font-medium text-gray-900 dark:text-gray-100">
                    Script Length
                  </td>
                  {selectedResults.map((result, idx) => (
                    <td key={idx} className="py-3 px-4 text-center">
                      <div className="flex items-center justify-center space-x-2">
                        <span className="font-bold text-gray-900 dark:text-gray-100">
                          {result.features.totalLength.toLocaleString()}
                        </span>
                        {idx > 0 && getComparisonIcon(
                          result.features.totalLength,
                          selectedResults[0].features.totalLength
                        )}
                      </div>
                    </td>
                  ))}
                </tr>
                <tr>
                  <td className="py-3 px-4 font-medium text-gray-900 dark:text-gray-100">
                    Function Count
                  </td>
                  {selectedResults.map((result, idx) => (
                    <td key={idx} className="py-3 px-4 text-center">
                      <div className="flex items-center justify-center space-x-2">
                        <span className="font-bold text-gray-900 dark:text-gray-100">
                          {result.features.functionCount}
                        </span>
                        {idx > 0 && getComparisonIcon(
                          result.features.functionCount,
                          selectedResults[0].features.functionCount
                        )}
                      </div>
                    </td>
                  ))}
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Threat Categories Comparison */}
      {selectedResults.length >= 2 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <div className="flex items-center space-x-3">
              <AlertTriangle className="h-5 w-5 text-amber-500" />
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                Threat Categories Comparison
              </h3>
            </div>
          </div>
          <div className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {selectedResults.map((result, idx) => (
                <div key={idx} className="space-y-3">
                  <h4 className="font-medium text-gray-900 dark:text-gray-100 truncate" title={result.filename}>
                    {result.filename}
                  </h4>
                  {result.threatCategories && result.threatCategories.length > 0 ? (
                    <div className="space-y-2">
                      {result.threatCategories.map((category, catIdx) => (
                        <div
                          key={catIdx}
                          className="px-3 py-2 bg-red-100 dark:bg-red-950 text-red-800 dark:text-red-200 text-sm rounded-lg"
                        >
                          {category}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-gray-500 dark:text-gray-400 italic">
                      No threat categories detected
                    </p>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {selectedResults.length < 2 && (
        <div className="text-center py-12 text-gray-500 dark:text-gray-400">
          <GitCompare className="h-12 w-12 mx-auto mb-4 opacity-50" />
          <p>Select at least 2 scripts to start comparing.</p>
          <p className="text-sm mt-2">Choose scripts from the selection panel above.</p>
        </div>
      )}
    </div>
  );
}