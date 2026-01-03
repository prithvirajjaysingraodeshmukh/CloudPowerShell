import React, { useState } from 'react';
import { AnalysisResult } from '../types/analysis';
import { Search, Filter, Target, AlertTriangle, Eye, Database } from 'lucide-react';

interface ThreatHuntingProps {
  results: AnalysisResult[];
}

export default function ThreatHunting({ results }: ThreatHuntingProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedThreatType, setSelectedThreatType] = useState('all');
  const [minRiskScore, setMinRiskScore] = useState(0);
  const [huntResults, setHuntResults] = useState<any[]>([]);

  const threatTypes = [
    'all',
    'Encoded Payload',
    'Network Communication',
    'Code Obfuscation',
    'Execution Policy Bypass',
    'High Entropy Content',
    'Multiple Encoding Methods'
  ];

  const huntingQueries = [
    {
      name: 'Base64 Encoded PowerShell',
      description: 'Scripts with multiple Base64 encoded strings',
      query: (r: AnalysisResult) => r.features.base64Count > 2
    },
    {
      name: 'Network Download Activity',
      description: 'Scripts attempting to download content',
      query: (r: AnalysisResult) => r.features.urlCount > 0 && r.features.suspiciousKeywords.some(k => k.includes('download'))
    },
    {
      name: 'Execution Policy Bypass',
      description: 'Scripts bypassing PowerShell execution policies',
      query: (r: AnalysisResult) => r.features.suspiciousKeywords.some(k => k.includes('bypass') || k.includes('executionpolicy'))
    },
    {
      name: 'High Obfuscation',
      description: 'Heavily obfuscated scripts',
      query: (r: AnalysisResult) => r.features.obfuscationScore > 70
    },
    {
      name: 'Persistence Mechanisms',
      description: 'Scripts creating persistence',
      query: (r: AnalysisResult) => r.behaviorAnalysis.persistenceMechanisms.length > 0
    },
    {
      name: 'Anti-Analysis Techniques',
      description: 'Scripts with evasion techniques',
      query: (r: AnalysisResult) => r.behaviorAnalysis.antiAnalysis.length > 0
    }
  ];

  const performHunt = (queryFunc: (r: AnalysisResult) => boolean, queryName: string) => {
    const matches = results.filter(queryFunc);
    setHuntResults(matches.map(r => ({ ...r, huntQuery: queryName })));
  };

  const filteredResults = results.filter(result => {
    const matchesSearch = searchQuery === '' || 
      result.filename.toLowerCase().includes(searchQuery.toLowerCase()) ||
      result.threatCategories.some(cat => cat.toLowerCase().includes(searchQuery.toLowerCase()));
    
    const matchesThreatType = selectedThreatType === 'all' || 
      result.threatCategories.includes(selectedThreatType);
    
    const matchesRiskScore = result.features.obfuscationScore >= minRiskScore;
    
    return matchesSearch && matchesThreatType && matchesRiskScore;
  });

  return (
    <div className="space-y-6">
      <div className="text-center">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">
          Threat Hunting Console
        </h2>
        <p className="text-gray-600 dark:text-gray-400">
          Advanced threat hunting and IOC discovery platform
        </p>
      </div>

      {/* Search and Filters */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3">
            <Search className="h-5 w-5 text-blue-500" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
              Hunt Filters
            </h3>
          </div>
        </div>
        <div className="p-6 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">
                Search Query
              </label>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search filenames, threat categories..."
                className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">
                Threat Type
              </label>
              <select
                value={selectedThreatType}
                onChange={(e) => setSelectedThreatType(e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
              >
                {threatTypes.map(type => (
                  <option key={type} value={type}>
                    {type === 'all' ? 'All Threat Types' : type}
                  </option>
                ))}
              </select>
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-900 dark:text-gray-100 mb-2">
                Min Risk Score: {minRiskScore}
              </label>
              <input
                type="range"
                min="0"
                max="100"
                value={minRiskScore}
                onChange={(e) => setMinRiskScore(parseInt(e.target.value))}
                className="w-full"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Hunting Queries */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3">
            <Target className="h-5 w-5 text-red-500" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
              Predefined Hunt Queries
            </h3>
          </div>
        </div>
        <div className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {huntingQueries.map((query, idx) => (
              <div
                key={idx}
                onClick={() => performHunt(query.query, query.name)}
                className="p-4 border border-gray-200 dark:border-gray-600 rounded-lg hover:border-blue-500 cursor-pointer transition-colors"
              >
                <h4 className="font-semibold text-gray-900 dark:text-gray-100 mb-2">
                  {query.name}
                </h4>
                <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">
                  {query.description}
                </p>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-blue-600 dark:text-blue-400">
                    Click to hunt
                  </span>
                  <span className="text-xs bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded">
                    {results.filter(query.query).length} matches
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Hunt Results */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Database className="h-5 w-5 text-green-500" />
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                Hunt Results
              </h3>
            </div>
            <span className="text-sm text-gray-600 dark:text-gray-400">
              {huntResults.length > 0 ? huntResults.length : filteredResults.length} results
            </span>
          </div>
        </div>
        <div className="p-6">
          {(huntResults.length > 0 ? huntResults : filteredResults).length > 0 ? (
            <div className="space-y-4">
              {(huntResults.length > 0 ? huntResults : filteredResults).map((result, idx) => (
                <div key={idx} className="p-4 border border-gray-200 dark:border-gray-600 rounded-lg">
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center space-x-3">
                      <div className={`w-3 h-3 rounded-full ${
                        result.classification === 'malicious' ? 'bg-red-500' :
                        result.classification === 'suspicious' ? 'bg-yellow-500' : 'bg-green-500'
                      }`} />
                      <h4 className="font-semibold text-gray-900 dark:text-gray-100">
                        {result.filename}
                      </h4>
                      {result.huntQuery && (
                        <span className="px-2 py-1 bg-blue-100 dark:bg-blue-950 text-blue-800 dark:text-blue-200 text-xs rounded">
                          {result.huntQuery}
                        </span>
                      )}
                    </div>
                    <span className="text-sm text-gray-500 dark:text-gray-400">
                      Risk: {result.features.obfuscationScore}
                    </span>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                    <div>
                      <p className="text-gray-600 dark:text-gray-400">Classification:</p>
                      <p className="font-medium text-gray-900 dark:text-gray-100 capitalize">
                        {result.classification}
                      </p>
                    </div>
                    <div>
                      <p className="text-gray-600 dark:text-gray-400">Base64 Strings:</p>
                      <p className="font-medium text-gray-900 dark:text-gray-100">
                        {result.features.base64Count}
                      </p>
                    </div>
                    <div>
                      <p className="text-gray-600 dark:text-gray-400">Network IOCs:</p>
                      <p className="font-medium text-gray-900 dark:text-gray-100">
                        {result.features.urlCount + result.features.ipCount}
                      </p>
                    </div>
                  </div>
                  
                  {result.threatCategories.length > 0 && (
                    <div className="mt-3">
                      <p className="text-xs text-gray-600 dark:text-gray-400 mb-2">Threat Categories:</p>
                      <div className="flex flex-wrap gap-2">
                        {result.threatCategories.map((category, catIdx) => (
                          <span
                            key={catIdx}
                            className="px-2 py-1 bg-red-100 dark:bg-red-950 text-red-800 dark:text-red-200 text-xs rounded"
                          >
                            {category}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12 text-gray-500 dark:text-gray-400">
              <Eye className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No threats found matching your criteria</p>
              <p className="text-sm mt-2">Try adjusting your hunt parameters</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}