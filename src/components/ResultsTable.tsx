import React from 'react';
import { AnalysisResult } from '../types/analysis';
import { Shield, AlertTriangle, AlertCircle, Download } from 'lucide-react';
import { exportToCSV } from '../utils/powershellAnalyzer';

interface ResultsTableProps {
  results: AnalysisResult[];
  onSelectResult: (result: AnalysisResult) => void;
}

export default function ResultsTable({ results, onSelectResult }: ResultsTableProps) {
  const handleExportCSV = () => {
    const csvData = exportToCSV(results);
    const blob = new Blob([csvData], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `powershell-analysis-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getClassificationIcon = (classification: string) => {
    switch (classification) {
      case 'benign':
        return <Shield className="h-4 w-4 text-green-500" />;
      case 'suspicious':
        return <AlertTriangle className="h-4 w-4 text-amber-500" />;
      case 'malicious':
        return <AlertCircle className="h-4 w-4 text-red-500" />;
      default:
        return null;
    }
  };

  const getClassificationBadge = (classification: string) => {
    const baseClasses = "px-2 py-1 text-xs font-medium rounded-full";
    switch (classification) {
      case 'benign':
        return `${baseClasses} bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-200`;
      case 'suspicious':
        return `${baseClasses} bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200`;
      case 'malicious':
        return `${baseClasses} bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200`;
      default:
        return `${baseClasses} bg-gray-100 text-gray-800`;
    }
  };

  if (results.length === 0) {
    return (
      <div className="text-center py-12 text-gray-500 dark:text-gray-400">
        <p>No analysis results yet.</p>
        <p className="text-sm mt-2">Upload PowerShell scripts to see analysis results here.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h2 className="text-xl font-bold text-gray-900 dark:text-gray-100">
          Analysis Results ({results.length})
        </h2>
        <button
          onClick={handleExportCSV}
          className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          <Download className="h-4 w-4" />
          <span>Export CSV</span>
        </button>
      </div>

      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-gray-50 dark:bg-gray-900">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  File
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Classification
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Confidence
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Entropy
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Base64
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Keywords
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Score
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Analyzed
                </th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              {results.map((result, idx) => (
                <tr
                  key={idx}
                  onClick={() => onSelectResult(result)}
                  className="hover:bg-gray-50 dark:hover:bg-gray-750 cursor-pointer transition-colors"
                >
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate max-w-xs">
                      {result.filename}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center space-x-2">
                      {getClassificationIcon(result.classification)}
                      <span className={getClassificationBadge(result.classification)}>
                        {result.classification}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">
                    {(result.confidence * 100).toFixed(1)}%
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">
                    {result.features.entropy.toFixed(2)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">
                    {result.features.base64Count}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">
                    {result.features.suspiciousKeywordCount}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center space-x-2">
                      <span className="text-sm text-gray-900 dark:text-gray-100">
                        {result.features.obfuscationScore}
                      </span>
                      <div className="w-16 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
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
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                    {result.timestamp.toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}