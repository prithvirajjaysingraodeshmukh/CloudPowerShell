import React from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ScatterChart,
  Scatter,
  PieChart,
  Pie,
  Cell
} from 'recharts';
import { AnalysisResult } from '../types/analysis';

interface DataVisualizationProps {
  results: AnalysisResult[];
}

export default function DataVisualization({ results }: DataVisualizationProps) {
  if (results.length === 0) {
    return (
      <div className="text-center py-12 text-gray-500 dark:text-gray-400">
        <p>No analysis results to visualize yet.</p>
        <p className="text-sm mt-2">Upload and analyze scripts to see visualizations.</p>
      </div>
    );
  }

  // Prepare data for charts
  const classificationData = results.reduce((acc, result) => {
    acc[result.classification] = (acc[result.classification] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const pieChartData = Object.entries(classificationData).map(([name, value]) => ({
    name,
    value,
    color: name === 'benign' ? '#10B981' : name === 'suspicious' ? '#F59E0B' : '#EF4444'
  }));

  const scatterData = results.map((result, idx) => ({
    name: result.filename,
    entropy: result.features.entropy,
    obfuscationScore: result.features.obfuscationScore,
    classification: result.classification,
    base64Count: result.features.base64Count,
    suspiciousKeywords: result.features.suspiciousKeywordCount
  }));

  const featureComparison = [
    {
      feature: 'Avg Entropy',
      benign: results.filter(r => r.classification === 'benign').reduce((sum, r) => sum + r.features.entropy, 0) / Math.max(results.filter(r => r.classification === 'benign').length, 1),
      suspicious: results.filter(r => r.classification === 'suspicious').reduce((sum, r) => sum + r.features.entropy, 0) / Math.max(results.filter(r => r.classification === 'suspicious').length, 1),
      malicious: results.filter(r => r.classification === 'malicious').reduce((sum, r) => sum + r.features.entropy, 0) / Math.max(results.filter(r => r.classification === 'malicious').length, 1)
    },
    {
      feature: 'Avg Base64',
      benign: results.filter(r => r.classification === 'benign').reduce((sum, r) => sum + r.features.base64Count, 0) / Math.max(results.filter(r => r.classification === 'benign').length, 1),
      suspicious: results.filter(r => r.classification === 'suspicious').reduce((sum, r) => sum + r.features.base64Count, 0) / Math.max(results.filter(r => r.classification === 'suspicious').length, 1),
      malicious: results.filter(r => r.classification === 'malicious').reduce((sum, r) => sum + r.features.base64Count, 0) / Math.max(results.filter(r => r.classification === 'malicious').length, 1)
    },
    {
      feature: 'Avg Suspicious Keywords',
      benign: results.filter(r => r.classification === 'benign').reduce((sum, r) => sum + r.features.suspiciousKeywordCount, 0) / Math.max(results.filter(r => r.classification === 'benign').length, 1),
      suspicious: results.filter(r => r.classification === 'suspicious').reduce((sum, r) => sum + r.features.suspiciousKeywordCount, 0) / Math.max(results.filter(r => r.classification === 'suspicious').length, 1),
      malicious: results.filter(r => r.classification === 'malicious').reduce((sum, r) => sum + r.features.suspiciousKeywordCount, 0) / Math.max(results.filter(r => r.classification === 'malicious').length, 1)
    }
  ];

  return (
    <div className="space-y-8">
      <div className="text-center">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">
          Analysis Visualizations
        </h2>
        <p className="text-gray-600 dark:text-gray-400">
          Comparative analysis of {results.length} analyzed scripts
        </p>
      </div>

      {/* Classification Distribution */}
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
          Classification Distribution
        </h3>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={pieChartData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, value, percent }) => `${name}: ${value} (${(percent * 100).toFixed(0)}%)`}
                outerRadius={80}
                fill="#8884d8"
                dataKey="value"
              >
                {pieChartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Feature Comparison */}
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
          Feature Comparison by Classification
        </h3>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={featureComparison}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="feature" />
              <YAxis />
              <Tooltip />
              <Bar dataKey="benign" fill="#10B981" name="Benign" />
              <Bar dataKey="suspicious" fill="#F59E0B" name="Suspicious" />
              <Bar dataKey="malicious" fill="#EF4444" name="Malicious" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Entropy vs Obfuscation Score */}
      <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">
          Entropy vs Obfuscation Score
        </h3>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <ScatterChart data={scatterData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis 
                dataKey="entropy" 
                name="Entropy"
                type="number"
                domain={[0, 8]}
              />
              <YAxis 
                dataKey="obfuscationScore" 
                name="Obfuscation Score"
                type="number"
                domain={[0, 100]}
              />
              <Tooltip 
                cursor={{ strokeDasharray: '3 3' }}
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    const data = payload[0].payload;
                    return (
                      <div className="bg-white dark:bg-gray-800 p-3 border border-gray-300 dark:border-gray-600 rounded shadow">
                        <p className="font-medium">{data.name}</p>
                        <p>Entropy: {data.entropy.toFixed(2)}</p>
                        <p>Obfuscation: {data.obfuscationScore}</p>
                        <p>Classification: {data.classification}</p>
                      </div>
                    );
                  }
                  return null;
                }}
              />
              <Scatter 
                dataKey="obfuscationScore" 
                fill={(entry: any) => {
                  switch (entry.classification) {
                    case 'benign': return '#10B981';
                    case 'suspicious': return '#F59E0B';
                    case 'malicious': return '#EF4444';
                    default: return '#6B7280';
                  }
                }}
              />
            </ScatterChart>
          </ResponsiveContainer>
        </div>
        <div className="flex justify-center space-x-6 mt-4 text-sm">
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-green-500 rounded-full"></div>
            <span>Benign</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-amber-500 rounded-full"></div>
            <span>Suspicious</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-red-500 rounded-full"></div>
            <span>Malicious</span>
          </div>
        </div>
      </div>
    </div>
  );
}