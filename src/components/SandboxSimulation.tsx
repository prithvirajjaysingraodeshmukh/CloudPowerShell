import React from 'react';
import { AnalysisResult } from '../types/analysis';
import { Shield, AlertTriangle, CheckCircle, XCircle, Network, HardDrive, Settings, Activity } from 'lucide-react';

interface SandboxSimulationProps {
  results: AnalysisResult[];
}

export default function SandboxSimulation({ results }: SandboxSimulationProps) {
  if (results.length === 0) {
    return (
      <div className="text-center py-12 text-gray-500 dark:text-gray-400">
        <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
        <p>No sandbox simulation data available.</p>
        <p className="text-sm mt-2">Analyze scripts to see sandbox simulation results.</p>
      </div>
    );
  }

  const selectedResult = results[results.length - 1];
  const sandbox = selectedResult.sandbox;

  const getRiskColor = (riskLevel: string) => {
    switch (riskLevel) {
      case 'critical': return 'text-red-700 bg-red-100 border-red-300 dark:text-red-300 dark:bg-red-950 dark:border-red-700';
      case 'high': return 'text-orange-700 bg-orange-100 border-orange-300 dark:text-orange-300 dark:bg-orange-950 dark:border-orange-700';
      case 'medium': return 'text-yellow-700 bg-yellow-100 border-yellow-300 dark:text-yellow-300 dark:bg-yellow-950 dark:border-yellow-700';
      case 'low': return 'text-green-700 bg-green-100 border-green-300 dark:text-green-300 dark:bg-green-950 dark:border-green-700';
      default: return 'text-gray-700 bg-gray-100 border-gray-300';
    }
  };

  return (
    <div className="space-y-6">
      <div className="text-center">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">
          Sandbox Simulation
        </h2>
        <p className="text-gray-600 dark:text-gray-400">
          Simulated execution analysis of {selectedResult.filename}
        </p>
      </div>

      {/* Risk Assessment */}
      <div className={`p-6 rounded-lg border ${getRiskColor(sandbox.riskLevel)}`}>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-3">
            {sandbox.safeToExecute ? (
              <CheckCircle className="h-8 w-8 text-green-500" />
            ) : (
              <XCircle className="h-8 w-8 text-red-500" />
            )}
            <div>
              <h3 className="text-xl font-bold">
                {sandbox.safeToExecute ? 'Safe to Execute' : 'Unsafe to Execute'}
              </h3>
              <p className="text-sm opacity-90">
                Risk Level: {sandbox.riskLevel.toUpperCase()}
              </p>
            </div>
          </div>
        </div>
        
        {sandbox.detectedCapabilities.length > 0 && (
          <div>
            <h4 className="font-semibold mb-2">Detected Capabilities:</h4>
            <div className="flex flex-wrap gap-2">
              {sandbox.detectedCapabilities.map((capability, idx) => (
                <span
                  key={idx}
                  className="px-3 py-1 bg-white dark:bg-gray-800 rounded-full text-sm font-medium"
                >
                  {capability}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Detailed Analysis */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Network Activity */}
        {sandbox.networkActivity.length > 0 && (
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
            <div className="p-6 border-b border-gray-200 dark:border-gray-700">
              <div className="flex items-center space-x-3">
                <Network className="h-5 w-5 text-purple-500" />
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                  Network Activity
                </h3>
              </div>
            </div>
            <div className="p-6 space-y-4">
              {sandbox.networkActivity.map((activity, idx) => (
                <div key={idx} className="p-4 bg-purple-50 dark:bg-purple-950 rounded-lg border border-purple-200 dark:border-purple-800">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-medium text-purple-800 dark:text-purple-200">
                      {activity.type.toUpperCase()}
                    </span>
                    {activity.port && (
                      <span className="text-sm text-purple-600 dark:text-purple-400">
                        Port: {activity.port}
                      </span>
                    )}
                  </div>
                  <p className="text-sm font-mono text-purple-700 dark:text-purple-300 mb-2">
                    {activity.destination}
                  </p>
                  <p className="text-xs text-purple-600 dark:text-purple-400">
                    {activity.purpose}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* File System Changes */}
        {sandbox.fileSystemChanges.length > 0 && (
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
            <div className="p-6 border-b border-gray-200 dark:border-gray-700">
              <div className="flex items-center space-x-3">
                <HardDrive className="h-5 w-5 text-blue-500" />
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                  File System Changes
                </h3>
              </div>
            </div>
            <div className="p-6 space-y-4">
              {sandbox.fileSystemChanges.map((change, idx) => (
                <div key={idx} className="p-4 bg-blue-50 dark:bg-blue-950 rounded-lg border border-blue-200 dark:border-blue-800">
                  <div className="flex items-center justify-between mb-2">
                    <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                      change.action === 'create' ? 'bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-200' :
                      change.action === 'delete' ? 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200' :
                      'bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-200'
                    }`}>
                      {change.action.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-sm font-mono text-blue-700 dark:text-blue-300 mb-2">
                    {change.path}
                  </p>
                  <p className="text-xs text-blue-600 dark:text-blue-400">
                    {change.description}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Registry Changes */}
        {sandbox.registryChanges.length > 0 && (
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
            <div className="p-6 border-b border-gray-200 dark:border-gray-700">
              <div className="flex items-center space-x-3">
                <Settings className="h-5 w-5 text-orange-500" />
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                  Registry Changes
                </h3>
              </div>
            </div>
            <div className="p-6 space-y-4">
              {sandbox.registryChanges.map((change, idx) => (
                <div key={idx} className="p-4 bg-orange-50 dark:bg-orange-950 rounded-lg border border-orange-200 dark:border-orange-800">
                  <div className="flex items-center justify-between mb-2">
                    <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                      change.action === 'create' ? 'bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-200' :
                      change.action === 'delete' ? 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200' :
                      'bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-200'
                    }`}>
                      {change.action.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-sm font-mono text-orange-700 dark:text-orange-300 mb-1">
                    {change.key}
                  </p>
                  {change.value && (
                    <p className="text-sm font-mono text-orange-600 dark:text-orange-400 mb-2">
                      Value: {change.value}
                    </p>
                  )}
                  <p className="text-xs text-orange-600 dark:text-orange-400">
                    {change.description}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Process Activity */}
        {sandbox.processActivity.length > 0 && (
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
            <div className="p-6 border-b border-gray-200 dark:border-gray-700">
              <div className="flex items-center space-x-3">
                <Activity className="h-5 w-5 text-green-500" />
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                  Process Activity
                </h3>
              </div>
            </div>
            <div className="p-6 space-y-4">
              {sandbox.processActivity.map((activity, idx) => (
                <div key={idx} className="p-4 bg-green-50 dark:bg-green-950 rounded-lg border border-green-200 dark:border-green-800">
                  <div className="flex items-center justify-between mb-2">
                    <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                      activity.action === 'start' ? 'bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-200' :
                      activity.action === 'stop' ? 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200' :
                      'bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-200'
                    }`}>
                      {activity.action.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-sm font-mono text-green-700 dark:text-green-300 mb-1">
                    {activity.process}
                  </p>
                  {activity.arguments && (
                    <p className="text-sm font-mono text-green-600 dark:text-green-400 mb-2">
                      Args: {activity.arguments}
                    </p>
                  )}
                  <p className="text-xs text-green-600 dark:text-green-400">
                    {activity.description}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}