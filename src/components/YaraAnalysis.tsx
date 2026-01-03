import React from 'react';
import { AnalysisResult } from '../types/analysis';
import { Shield, AlertTriangle, Tag, Search } from 'lucide-react';

interface YaraAnalysisProps {
  results: AnalysisResult[];
}

export default function YaraAnalysis({ results }: YaraAnalysisProps) {
  const allMatches = results.flatMap(r => r.yara || []);
  const uniqueRules = [...new Set(allMatches.map(m => m.ruleName))];
  
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-700 bg-red-100 border-red-300 dark:text-red-300 dark:bg-red-950 dark:border-red-700';
      case 'high': return 'text-orange-700 bg-orange-100 border-orange-300 dark:text-orange-300 dark:bg-orange-950 dark:border-orange-700';
      case 'medium': return 'text-yellow-700 bg-yellow-100 border-yellow-300 dark:text-yellow-300 dark:bg-yellow-950 dark:border-yellow-700';
      case 'low': return 'text-blue-700 bg-blue-100 border-blue-300 dark:text-blue-300 dark:bg-blue-950 dark:border-blue-700';
      default: return 'text-gray-700 bg-gray-100 border-gray-300';
    }
  };

  if (results.length === 0) {
    return (
      <div className="text-center py-12 text-gray-500 dark:text-gray-400">
        <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
        <p>No scripts analyzed yet.</p>
        <p className="text-sm mt-2">Upload scripts to see YARA rule matches.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="text-center">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">
          YARA Rule Analysis
        </h2>
        <p className="text-gray-600 dark:text-gray-400">
          Advanced pattern matching and threat signature detection
        </p>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3">
            <Search className="h-8 w-8 text-blue-500" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Total Matches</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">{allMatches.length}</p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3">
            <Shield className="h-8 w-8 text-green-500" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Unique Rules</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">{uniqueRules.length}</p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3">
            <AlertTriangle className="h-8 w-8 text-red-500" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Critical Matches</p>
              <p className="text-2xl font-bold text-red-600">
                {allMatches.filter(m => m.severity === 'critical').length}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3">
            <Tag className="h-8 w-8 text-purple-500" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Affected Scripts</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
                {results.filter(r => r.yara && r.yara.length > 0).length}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* YARA Matches */}
      {allMatches.length > 0 ? (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
              Detected Threat Signatures
            </h3>
          </div>
          <div className="p-6 space-y-4">
            {allMatches.map((match, idx) => (
              <div key={idx} className={`p-4 rounded-lg border ${getSeverityColor(match.severity)}`}>
                <div className="flex items-center justify-between mb-3">
                  <h4 className="font-semibold text-lg">{match.ruleName}</h4>
                  <span className="px-3 py-1 text-xs font-medium rounded-full uppercase">
                    {match.severity}
                  </span>
                </div>
                <p className="text-sm mb-3">{match.description}</p>
                
                {match.tags.length > 0 && (
                  <div className="mb-3">
                    <p className="text-xs font-medium mb-2">Tags:</p>
                    <div className="flex flex-wrap gap-2">
                      {match.tags.map((tag, tagIdx) => (
                        <span
                          key={tagIdx}
                          className="px-2 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 text-xs rounded"
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                
                {match.matches.length > 0 && (
                  <div>
                    <p className="text-xs font-medium mb-2">Pattern Matches:</p>
                    <div className="space-y-1">
                      {match.matches.map((pattern, patternIdx) => (
                        <code
                          key={patternIdx}
                          className="block text-xs bg-gray-100 dark:bg-gray-700 p-2 rounded font-mono"
                        >
                          {pattern}
                        </code>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-12 text-center">
          <Shield className="h-16 w-16 mx-auto mb-4 text-green-500" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
            No Threat Signatures Detected
          </h3>
          <p className="text-gray-600 dark:text-gray-400">
            All analyzed scripts passed YARA rule validation
          </p>
        </div>
      )}
    </div>
  );
}