import React, { useState, useEffect } from 'react';
import { AnalysisResult } from '../types/analysis';
import { Activity, TrendingUp, AlertTriangle, Shield, Clock, Zap } from 'lucide-react';

interface LiveMonitoringProps {
  results: AnalysisResult[];
}

export default function LiveMonitoring({ results }: LiveMonitoringProps) {
  const [currentTime, setCurrentTime] = useState(new Date());
  const [alerts, setAlerts] = useState<any[]>([]);

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    // Generate alerts for high-risk scripts
    const newAlerts = results
      .filter(r => r.classification === 'malicious' || r.features.obfuscationScore > 70)
      .map(r => ({
        id: Math.random().toString(36).substr(2, 9),
        timestamp: r.timestamp,
        type: r.classification === 'malicious' ? 'critical' : 'warning',
        message: `High-risk script detected: ${r.filename}`,
        details: `Obfuscation Score: ${r.features.obfuscationScore}, Confidence: ${(r.confidence * 100).toFixed(1)}%`
      }));
    
    setAlerts(prev => [...newAlerts, ...prev].slice(0, 10));
  }, [results]);

  const recentActivity = results.slice(-5).reverse();
  const totalScripts = results.length;
  const maliciousCount = results.filter(r => r.classification === 'malicious').length;
  const suspiciousCount = results.filter(r => r.classification === 'suspicious').length;
  const avgObfuscationScore = results.length > 0 
    ? results.reduce((sum, r) => sum + r.features.obfuscationScore, 0) / results.length 
    : 0;

  const getAlertColor = (type: string) => {
    switch (type) {
      case 'critical': return 'border-l-red-500 bg-red-50 dark:bg-red-950';
      case 'warning': return 'border-l-yellow-500 bg-yellow-50 dark:bg-yellow-950';
      default: return 'border-l-blue-500 bg-blue-50 dark:bg-blue-950';
    }
  };

  return (
    <div className="space-y-6">
      <div className="text-center">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">
          Live Security Monitoring
        </h2>
        <p className="text-gray-600 dark:text-gray-400">
          Real-time threat detection and analysis dashboard
        </p>
        <p className="text-sm text-gray-500 dark:text-gray-500 mt-2">
          Last updated: {currentTime.toLocaleTimeString()}
        </p>
      </div>

      {/* Real-time Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3">
            <Activity className="h-8 w-8 text-blue-500" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Scripts Analyzed</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">{totalScripts}</p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3">
            <AlertTriangle className="h-8 w-8 text-red-500" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Threats Detected</p>
              <p className="text-2xl font-bold text-red-600">{maliciousCount + suspiciousCount}</p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3">
            <TrendingUp className="h-8 w-8 text-orange-500" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Avg Risk Score</p>
              <p className="text-2xl font-bold text-orange-600">{avgObfuscationScore.toFixed(1)}</p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 p-6 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3">
            <Shield className="h-8 w-8 text-green-500" />
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Detection Rate</p>
              <p className="text-2xl font-bold text-green-600">
                {totalScripts > 0 ? (((maliciousCount + suspiciousCount) / totalScripts * 100).toFixed(1)) : 0}%
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Live Alerts */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3">
            <Zap className="h-5 w-5 text-yellow-500" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
              Security Alerts
            </h3>
          </div>
        </div>
        <div className="p-6">
          {alerts.length > 0 ? (
            <div className="space-y-3">
              {alerts.map((alert) => (
                <div
                  key={alert.id}
                  className={`p-4 border-l-4 rounded-r-lg ${getAlertColor(alert.type)}`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      {alert.type === 'critical' ? (
                        <AlertTriangle className="h-4 w-4 text-red-500" />
                      ) : (
                        <AlertTriangle className="h-4 w-4 text-yellow-500" />
                      )}
                      <span className="font-medium text-gray-900 dark:text-gray-100">
                        {alert.message}
                      </span>
                    </div>
                    <span className="text-xs text-gray-500 dark:text-gray-400">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mt-1 ml-6">
                    {alert.details}
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-gray-500 dark:text-gray-400">
              <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No security alerts</p>
              <p className="text-sm mt-2">All systems operating normally</p>
            </div>
          )}
        </div>
      </div>

      {/* Recent Activity */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center space-x-3">
            <Clock className="h-5 w-5 text-blue-500" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
              Recent Activity
            </h3>
          </div>
        </div>
        <div className="p-6">
          {recentActivity.length > 0 ? (
            <div className="space-y-4">
              {recentActivity.map((result, idx) => (
                <div key={idx} className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                  <div className="flex items-center space-x-4">
                    <div className={`w-3 h-3 rounded-full ${
                      result.classification === 'malicious' ? 'bg-red-500' :
                      result.classification === 'suspicious' ? 'bg-yellow-500' : 'bg-green-500'
                    }`} />
                    <div>
                      <p className="font-medium text-gray-900 dark:text-gray-100">
                        {result.filename}
                      </p>
                      <p className="text-sm text-gray-600 dark:text-gray-400">
                        {result.classification} • Score: {result.features.obfuscationScore}
                      </p>
                    </div>
                  </div>
                  <span className="text-sm text-gray-500 dark:text-gray-400">
                    {new Date(result.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-gray-500 dark:text-gray-400">
              <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No recent activity</p>
              <p className="text-sm mt-2">Start analyzing scripts to see activity</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}