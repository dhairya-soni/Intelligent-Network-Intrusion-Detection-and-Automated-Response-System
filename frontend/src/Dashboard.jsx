import { useState } from 'react'

function Dashboard({ stats, alerts }) {
  if (!stats) {
    return <div className="text-slate-400">No statistics available</div>
  }

  const recentAlerts = alerts.slice(0, 10)

  return (
    <div className="space-y-6">
      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard
          title="Total Alerts"
          value={stats.total_alerts}
          icon="📊"
          color="bg-slate-700"
        />
        <StatCard
          title="Critical"
          value={stats.severity_counts.CRITICAL}
          icon="🔴"
          color="bg-red-900/50 border-red-700"
        />
        <StatCard
          title="High"
          value={stats.severity_counts.HIGH}
          icon="🟠"
          color="bg-orange-900/50 border-orange-700"
        />
        <StatCard
          title="Medium"
          value={stats.severity_counts.MEDIUM}
          icon="🟡"
          color="bg-yellow-900/50 border-yellow-700"
        />
        <StatCard
          title="Low"
          value={stats.severity_counts.LOW}
          icon="🟢"
          color="bg-green-900/50 border-green-700"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Types Distribution */}
        <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
          <h2 className="text-xl font-semibold mb-4 flex items-center">
            <span className="mr-2">🎯</span>
            Threat Types
          </h2>
          
          {Object.keys(stats.attack_types).length === 0 ? (
            <p className="text-slate-400 text-center py-8">No threats detected yet</p>
          ) : (
            <div className="space-y-3">
              {Object.entries(stats.attack_types)
                .sort((a, b) => b[1] - a[1])
                .map(([type, count]) => (
                  <div key={type} className="flex items-center justify-between">
                    <div className="flex items-center space-x-3 flex-1">
                      <span className="text-2xl">{getThreatIcon(type)}</span>
                      <div className="flex-1">
                        <p className="text-sm font-medium">{type}</p>
                        <div className="w-full bg-slate-700 rounded-full h-2 mt-1">
                          <div
                            className="bg-blue-500 h-2 rounded-full transition-all duration-300"
                            style={{ width: `${(count / stats.total_alerts) * 100}%` }}
                          />
                        </div>
                      </div>
                    </div>
                    <span className="ml-3 px-3 py-1 bg-slate-700 rounded-full text-sm font-semibold">
                      {count}
                    </span>
                  </div>
                ))}
            </div>
          )}
        </div>

        {/* Recent Alerts */}
        <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
          <h2 className="text-xl font-semibold mb-4 flex items-center">
            <span className="mr-2">⚡</span>
            Recent Activity
          </h2>
          
          {recentAlerts.length === 0 ? (
            <p className="text-slate-400 text-center py-8">No alerts yet. Run the demo to generate attacks!</p>
          ) : (
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {recentAlerts.map((alert) => (
                <div
                  key={alert.id}
                  className="bg-slate-700/50 rounded-lg p-3 border border-slate-600 hover:border-slate-500 transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center space-x-2">
                        <SeverityBadge severity={alert.severity} />
                        <span className="text-sm font-medium">{alert.threat_type}</span>
                      </div>
                      <p className="text-xs text-slate-400 mt-1">
                        {alert.source_ip} → {alert.dest_ip}:{alert.dest_port}
                      </p>
                      <div className="flex items-center space-x-4 mt-2 text-xs text-slate-400">
                        <span>ML: {(alert.ml_score * 100).toFixed(0)}%</span>
                        <span>Confidence: {alert.confidence}%</span>
                        {alert.rule_matched && <span className="text-yellow-400">✓ Rule Match</span>}
                      </div>
                    </div>
                    <span className="text-xs text-slate-500">
                      {new Date(alert.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Detection Pipeline Status */}
      <div className="bg-slate-800 rounded-lg p-6 border border-slate-700">
        <h2 className="text-xl font-semibold mb-4 flex items-center">
          <span className="mr-2">⚙️</span>
          Detection Pipeline Status
        </h2>
        
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <PipelineStep
            title="Event Ingestion"
            status="active"
            description="Receiving security events"
          />
          <PipelineStep
            title="Feature Extraction"
            status="active"
            description="10 features extracted"
          />
          <PipelineStep
            title="ML Detection"
            status="active"
            description="Isolation Forest model"
          />
          <PipelineStep
            title="Rule Engine"
            status="active"
            description="5 active rules"
          />
        </div>
      </div>
    </div>
  )
}

function StatCard({ title, value, icon, color }) {
  return (
    <div className={`rounded-lg p-6 border ${color || 'bg-slate-700 border-slate-600'}`}>
      <div className="flex items-center justify-between">
        <div>
          <p className="text-slate-400 text-sm">{title}</p>
          <p className="text-3xl font-bold mt-2">{value}</p>
        </div>
        <div className="text-4xl">{icon}</div>
      </div>
    </div>
  )
}

function SeverityBadge({ severity }) {
  const colors = {
    CRITICAL: 'bg-red-600 text-white',
    HIGH: 'bg-orange-600 text-white',
    MEDIUM: 'bg-yellow-600 text-white',
    LOW: 'bg-green-600 text-white'
  }
  
  return (
    <span className={`px-2 py-1 rounded text-xs font-semibold ${colors[severity] || 'bg-gray-600'}`}>
      {severity}
    </span>
  )
}

function PipelineStep({ title, status, description }) {
  const statusColors = {
    active: 'bg-green-500',
    warning: 'bg-yellow-500',
    error: 'bg-red-500',
    inactive: 'bg-slate-600'
  }
  
  return (
    <div className="bg-slate-700/50 rounded-lg p-4 border border-slate-600">
      <div className="flex items-center justify-between mb-2">
        <h3 className="font-semibold text-sm">{title}</h3>
        <div className={`w-3 h-3 rounded-full ${statusColors[status]} animate-pulse`} />
      </div>
      <p className="text-xs text-slate-400">{description}</p>
    </div>
  )
}

function getThreatIcon(threatType) {
  const icons = {
    'Brute Force Attack': '🔓',
    'Port Scan': '🔍',
    'SQL Injection Attempt': '💉',
    'DDoS Attack': '🌊',
    'Malware Activity': '🦠',
    'Anomalous Behavior': '⚠️'
  }
  return icons[threatType] || '🚨'
}

export default Dashboard
