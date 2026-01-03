import React, { useState } from 'react';
import { Shield, Search, AlertTriangle, Globe, Database, Clock, TrendingUp } from 'lucide-react';

interface ThreatIntelligenceProps {
  results: any[];
}

export default function ThreatIntelligence({ results }: ThreatIntelligenceProps) {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedTimeframe, setSelectedTimeframe] = useState('7d');

  // Calculate threat intelligence metrics
  const totalScripts = results.length;
  const maliciousCount = results.filter(r => r.classification === 'malicious').length;
  const suspiciousCount = results.filter(r => r.classification === 'suspicious').length;
  const benignCount = results.filter(r => r.classification === 'benign').length;

  // Get unique threat categories
  const allThreatCategories = results.flatMap(r => r.threatCategories || []);
  const threatCategoryStats = allThreatCategories.reduce((acc, category) => {
    acc[category] = (acc[category] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  // Get network indicators
  const allUrls = results.flatMap(r => r.features.urlsFound || []);
  const allIps = results.flatMap(r => r.features.ipAddresses || []);
  const uniqueUrls = [...new Set(allUrls)];
  const uniqueIps = [...new Set(allIps)];

  // Recent high-risk scripts
  const highRiskScripts = results
    .filter(r => r.features.obfuscationScore > 60)
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, 5);

  // Filter results based on search
  const filteredResults = results.filter(result =>
    result.filename.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (result.threatCategories || []).some((cat: string) => 
      cat.toLowerCase().includes(searchTerm.toLowerCase())
    )
  );

  return (
    <div className="space-y-6">
      <div className="text-center">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">
          Threat Intelligence Dashboard
        </h2>
        <p className="text-gray-600 dark:text-gray-400">
          Comprehensive analysis of {totalScripts} analyzed scripts
        </p>
      </div>

      {/* Search and Filters */}
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="flex flex-col md:flex-row gap-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search scripts, threat categories..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          <select
            value={selectedTimeframe}
            onChange={(e) => setSelectedTimeframe(e.target.value)}
            className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          >
            <option value="1d">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
            <option value="all">All time</option>
          </select>
        </div>
      </div>

      {/* Overview Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3">
            <Shield className="h-8 w-8 text-blue-500" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Total Scripts</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">{totalScripts}</p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3">
            <AlertTriangle className="h-8 w-8 text-red-500" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Malicious</p>
              <p className="text-2xl font-bold text-red-600">{maliciousCount}</p>
              <p className="text-xs text-gray-500">
                {totalScripts > 0 ? ((maliciousCount / totalScripts) * 100).toFixed(1) : 0}%
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3">
            <Globe className="h-8 w-8 text-purple-500" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Network IOCs</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
                {uniqueUrls.length + uniqueIps.length}
              </p>
              <p className="text-xs text-gray-500">
                {uniqueUrls.length} URLs, {uniqueIps.length} IPs
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3">
            <TrendingUp className="h-8 w-8 text-green-500" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Detection Rate</p>
              <p className="text-2xl font-bold text-green-600">
                {totalScripts > 0 ? (((maliciousCount + suspiciousCount) / totalScripts) * 100).toFixed(1) : 0}%
              </p>
              <p className="text-xs text-gray-500">Threats detected</p>
            </div>
          </div>
        </div>
      </div>

      {/* Threat Categories */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
            Top Threat Categories
          </h3>
        </div>
        <div className="p-6">
          {Object.keys(threatCategoryStats).length > 0 ? (
            <div className="space-y-4">
              {Object.entries(threatCategoryStats)
                .sort(([,a], [,b]) => b - a)
                .slice(0, 8)
                .map(([category, count]) => (
                  <div key={category} className="flex items-center justify-between">
                    <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
                      {category}
                    </span>
                    <div className="flex items-center space-x-3">
                      <div className="w-32 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                        <div
                          className="bg-red-500 h-2 rounded-full"
                          style={{ width: `${(count / Math.max(...Object.values(threatCategoryStats))) * 100}%` }}
                        />
                      </div>
                      <span className="text-sm font-bold text-gray-900 dark:text-gray-100 w-8">
                        {count}
                      </span>
                    </div>
                  </div>
                ))}
            </div>
          ) : (
            <p className="text-gray-500 dark:text-gray-400 text-center py-8">
              No threat categories detected yet
            </p>
          )}
        </div>
      </div>

      {/* Network Indicators */}
      {(uniqueUrls.length > 0 || uniqueIps.length > 0) && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {uniqueUrls.length > 0 && (
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
              <div className="p-6 border-b border-gray-200 dark:border-gray-700">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                  Suspicious URLs ({uniqueUrls.length})
                </h3>
              </div>
              <div className="p-6 max-h-64 overflow-y-auto">
                <div className="space-y-2">
                  {uniqueUrls.slice(0, 10).map((url, idx) => (
                    <div key={idx} className="p-2 bg-purple-50 dark:bg-purple-950 rounded border">
                      <p className="text-sm font-mono text-purple-800 dark:text-purple-200 break-all">
                        {url}
                      </p>
                    </div>
                  ))}
                  {uniqueUrls.length > 10 && (
                    <p className="text-sm text-gray-500 dark:text-gray-400 text-center">
                      ... and {uniqueUrls.length - 10} more
                    </p>
                  )}
                </div>
              </div>
            </div>
          )}

          {uniqueIps.length > 0 && (
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
              <div className="p-6 border-b border-gray-200 dark:border-gray-700">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                  IP Addresses ({uniqueIps.length})
                </h3>
              </div>
              <div className="p-6 max-h-64 overflow-y-auto">
                <div className="space-y-2">
                  {uniqueIps.slice(0, 10).map((ip, idx) => (
                    <div key={idx} className="p-2 bg-orange-50 dark:bg-orange-950 rounded border">
                      <p className="text-sm font-mono text-orange-800 dark:text-orange-200">
                        {ip}
                      </p>
                    </div>
                  ))}
                  {uniqueIps.length > 10 && (
                    <p className="text-sm text-gray-500 dark:text-gray-400 text-center">
                      ... and {uniqueIps.length - 10} more
                    </p>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Recent High-Risk Scripts */}
      {highRiskScripts.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <div className="flex items-center space-x-3">
              <Clock className="h-5 w-5 text-red-500" />
              <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                Recent High-Risk Scripts
              </h3>
            </div>
          </div>
          <div className="p-6">
            <div className="space-y-4">
              {highRiskScripts.map((script, idx) => (
                <div key={idx} className="flex items-center justify-between p-4 bg-red-50 dark:bg-red-950 rounded-lg border border-red-200 dark:border-red-800">
                  <div className="flex-1">
                    <p className="font-medium text-gray-900 dark:text-gray-100">
                      {script.filename}
                    </p>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                      {new Date(script.timestamp).toLocaleString()}
                    </p>
                    {script.threatCategories && script.threatCategories.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-2">
                        {script.threatCategories.slice(0, 3).map((category: string, catIdx: number) => (
                          <span
                            key={catIdx}
                            className="px-2 py-1 bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200 text-xs rounded"
                          >
                            {category}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                  <div className="text-right">
                    <p className="text-lg font-bold text-red-600">
                      {script.features.obfuscationScore}
                    </p>
                    <p className="text-xs text-gray-500">Risk Score</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}