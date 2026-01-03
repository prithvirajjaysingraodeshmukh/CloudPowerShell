import React from 'react';
import { AnalysisResult } from '../types/analysis';
import { Activity, FileText, Settings, Network, Shield, Clock, AlertTriangle } from 'lucide-react';

interface BehaviorAnalysisProps {
  results: AnalysisResult[];
}

export default function BehaviorAnalysis({ results }: BehaviorAnalysisProps) {
  if (results.length === 0) {
    return (
      <div className="text-center py-12 text-gray-500 dark:text-gray-400">
        <Activity className="h-12 w-12 mx-auto mb-4 opacity-50" />
        <p>No behavioral analysis data available.</p>
        <p className="text-sm mt-2">Analyze scripts to see behavioral patterns.</p>
      </div>
    );
  }

  const selectedResult = results[results.length - 1]; // Show latest result
  const behavior = selectedResult.behaviorAnalysis;

  const behaviorCategories = [
    {
      title: 'File Operations',
      icon: FileText,
      items: behavior.fileOperations,
      color: 'blue'
    },
    {
      title: 'Registry Operations',
      icon: Settings,
      items: behavior.registryOperations,
      color: 'purple'
    },
    {
      title: 'Network Connections',
      icon: Network,
      items: behavior.networkConnections,
      color: 'green'
    },
    {
      title: 'Process Creation',
      icon: Activity,
      items: behavior.processCreation,
      color: 'orange'
    },
    {
      title: 'Service Manipulation',
      icon: Shield,
      items: behavior.serviceManipulation,
      color: 'red'
    },
    {
      title: 'Scheduled Tasks',
      icon: Clock,
      items: behavior.scheduledTasks,
      color: 'yellow'
    },
    {
      title: 'Persistence Mechanisms',
      icon: AlertTriangle,
      items: behavior.persistenceMechanisms,
      color: 'red'
    },
    {
      title: 'Anti-Analysis',
      icon: Shield,
      items: behavior.antiAnalysis,
      color: 'gray'
    },
    {
      title: 'Data Exfiltration',
      icon: Network,
      items: behavior.dataExfiltration,
      color: 'red'
    },
    {
      title: 'Privilege Escalation',
      icon: AlertTriangle,
      items: behavior.privilegeEscalation,
      color: 'red'
    }
  ];

  const getColorClasses = (color: string) => {
    const colors = {
      blue: 'text-blue-600 bg-blue-100 border-blue-200 dark:text-blue-400 dark:bg-blue-950 dark:border-blue-800',
      purple: 'text-purple-600 bg-purple-100 border-purple-200 dark:text-purple-400 dark:bg-purple-950 dark:border-purple-800',
      green: 'text-green-600 bg-green-100 border-green-200 dark:text-green-400 dark:bg-green-950 dark:border-green-800',
      orange: 'text-orange-600 bg-orange-100 border-orange-200 dark:text-orange-400 dark:bg-orange-950 dark:border-orange-800',
      red: 'text-red-600 bg-red-100 border-red-200 dark:text-red-400 dark:bg-red-950 dark:border-red-800',
      yellow: 'text-yellow-600 bg-yellow-100 border-yellow-200 dark:text-yellow-400 dark:bg-yellow-950 dark:border-yellow-800',
      gray: 'text-gray-600 bg-gray-100 border-gray-200 dark:text-gray-400 dark:bg-gray-950 dark:border-gray-800'
    };
    return colors[color as keyof typeof colors] || colors.gray;
  };

  return (
    <div className="space-y-6">
      <div className="text-center">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-2">
          Behavioral Analysis
        </h2>
        <p className="text-gray-600 dark:text-gray-400">
          Analysis of {selectedResult.filename} - Behavioral patterns and capabilities
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {behaviorCategories.map((category, idx) => {
          const Icon = category.icon;
          return (
            <div
              key={idx}
              className={`p-6 rounded-lg border ${getColorClasses(category.color)}`}
            >
              <div className="flex items-center space-x-3 mb-4">
                <Icon className="h-6 w-6" />
                <h3 className="font-semibold text-lg">{category.title}</h3>
              </div>
              
              {category.items.length > 0 ? (
                <div className="space-y-2">
                  {category.items.map((item, itemIdx) => (
                    <div
                      key={itemIdx}
                      className="p-2 bg-white dark:bg-gray-800 rounded text-sm border"
                    >
                      {item}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm opacity-75 italic">
                  No {category.title.toLowerCase()} detected
                </p>
              )}
            </div>
          );
        })}
      </div>

      {/* Timeline */}
      {selectedResult.timeline && selectedResult.timeline.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
              Execution Timeline
            </h3>
          </div>
          <div className="p-6">
            <div className="space-y-4">
              {selectedResult.timeline.map((event, idx) => (
                <div key={idx} className="flex items-start space-x-4">
                  <div className={`w-3 h-3 rounded-full mt-2 ${
                    event.severity === 'critical' ? 'bg-red-500' :
                    event.severity === 'warning' ? 'bg-yellow-500' : 'bg-blue-500'
                  }`} />
                  <div className="flex-1">
                    <div className="flex items-center justify-between">
                      <h4 className="font-medium text-gray-900 dark:text-gray-100">
                        {event.action}
                      </h4>
                      <span className="text-sm text-gray-500 dark:text-gray-400">
                        {event.timestamp}
                      </span>
                    </div>
                    <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                      {event.description}
                    </p>
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